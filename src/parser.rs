// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Stateful, streaming MySQL binlog reader.
use crate::event::{EventPayload, EventType, ParsedEvent, RowChange};
use mysql_common::binlog::{
    EventStreamReader,
    consts::{
        BinlogChecksumAlg, BinlogVersion, IncidentType, IntvarEventType,
        TransactionPayloadCompressionType,
    },
    events::{Event, EventData, PreviousGtidsEvent, RowsEventData, TransactionPayloadReader},
};
use std::{
    collections::HashMap,
    convert::Infallible,
    fs::File,
    io::{self, BufRead, BufReader, Cursor, Read},
    ops::ControlFlow,
    path::Path,
};

/// Upper bound on the accepted size of a single event, including its header.
pub const MAX_EVENT_SIZE: u32 = 64 * 1024 * 1024;

/// Upper bound on the inner events the collecting [`BinlogParser::events`]
/// iterator buffers per transaction payload (R46b).
///
/// The bound targets the pathological tiny-event case: a payload of 250,000
/// minimal events decodes to roughly 250 MB of retained event values, which
/// is the heaviest shape one payload can produce, while sitting about two
/// orders of magnitude above real transactions so legitimate payloads never
/// reach it. Breaching the bound returns [`ParserError::TooManyInnerEvents`]
/// instead of growing memory without limit. The bound can be raised through
/// [`BinlogParser::with_inner_event_limit`], and
/// [`BinlogParser::visit_events`] is not affected: its callback consumes
/// each inner event immediately, so the user applies backpressure.
pub const DEFAULT_INNER_EVENT_LIMIT: usize = 250_000;

/// Capacity of the buffered reader wrapping the input.
const READ_BUFFER_CAPACITY: usize = 1 << 20;

/// Upper bound on the uncompressed size a transaction payload may declare.
///
/// The declared value is metadata from the event header and is checked before
/// any decompression starts; exceeding it is corruption or an attack.
const MAX_UNCOMPRESSED_PAYLOAD_SIZE: u64 = 1 << 30;

/// Tolerance applied to the declared uncompressed size while counting the
/// decompressed bytes of a transaction payload.
const PAYLOAD_SIZE_SLACK: u64 = 1 << 20;

/// Failure opening or reading a binlog.
///
/// This enum is `#[non_exhaustive]` (R45): downstream matches require a
/// wildcard arm, so structured variants can be added without a semver-major
/// release. [`ParserError::Io`] stays the documented catch-all for failures
/// without a dedicated variant.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParserError {
    /// Encrypted MySQL binlogs must be read through the server.
    #[error(
        "encrypted binlog detected; use mysqlbinlog --read-from-remote-server against the MySQL server"
    )]
    EncryptedBinlog,
    /// The input does not have the plaintext MySQL binlog magic.
    #[error("invalid or truncated binlog file header")]
    InvalidHeader,
    /// Any other input or event decoding failure.
    #[error("binlog error at offset {offset}: {source}")]
    Io {
        /// File offset at which the failure was detected.
        offset: u64,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// The event's CRC32 checksum does not match its bytes.
    ///
    /// The Display string is identical to the message this path emitted
    /// before the variant existed (R45); the offset is structured so callers
    /// can locate the corruption programmatically.
    #[error("binlog error at offset {offset}: event checksum mismatch")]
    Checksum {
        /// File offset at which the failed event begins.
        offset: u64,
    },
    /// The event body ended before its declared size was read.
    ///
    /// The Display string is identical to the underlying `read_exact` EOF
    /// failure the truncated/EOF path surfaced before the variant existed
    /// (R45).
    #[error("binlog error at offset {offset}: failed to fill whole buffer")]
    Truncated {
        /// File offset at which the truncated event begins.
        offset: u64,
    },
    /// The declared event size is outside the valid range: below the
    /// 19-byte event header or above the configured per-event cap.
    ///
    /// The Display string is identical to the message this path emitted
    /// before the variant existed (R45); `size` and `limit` are structured
    /// fields, not part of the message.
    #[error("binlog error at offset {offset}: invalid or oversized event")]
    OversizedEvent {
        /// File offset at which the rejected event begins.
        offset: u64,
        /// Declared size carried in the event header.
        size: u32,
        /// The configured per-event size cap.
        limit: u32,
    },
    /// A transaction payload carried more inner events than the configured
    /// inner-event collection bound allows (R46b).
    ///
    /// The collecting [`BinlogParser::events`] iterator buffers every inner
    /// event of a payload; this error stops the input before the buffer can
    /// grow without limit. The message names the CLI flag and the uncapped
    /// visiting alternative so the remedy is discoverable.
    #[error(
        "transaction payload at offset {offset} contains more than {limit} inner events; raise --max-inner-events or use visit_events"
    )]
    TooManyInnerEvents {
        /// File offset of the enclosing transaction payload event.
        offset: u64,
        /// The configured inner-event collection bound.
        limit: usize,
    },
}

/// One notification from [`BinlogParser::visit_events`].
///
/// Compressed transactions produce a start notification, their inner events
/// in stream order, and an end notification after successful decoding. An
/// error or an early stop can leave a start without a matching end.
#[derive(Debug)]
#[non_exhaustive]
pub enum VisitEvent<'a> {
    /// A decoded ordinary event or one inner event of a compressed transaction.
    Event {
        /// The current event, borrowed only for this callback invocation.
        event: &'a ParsedEvent,
        /// File offset of the enclosing transaction payload, or `None` for
        /// an ordinary outer event. Inner event offsets are relative to the
        /// decompressed stream.
        parent_offset: Option<u64>,
    },
    /// A validated transaction payload about to be decoded.
    TransactionPayloadStart {
        /// Byte offset of the outer event in the binlog file.
        offset: u64,
        /// Outer timestamp, inherited by every inner event.
        timestamp: u32,
        /// Outer server identifier, inherited by every inner event.
        server_id: u32,
        /// Original outer event size, including its header and checksum.
        event_size: u32,
        /// Position recorded in the outer event header.
        log_pos: u32,
        /// Canonical compression name, `"NONE"` or `"ZSTD"`.
        compression: &'a str,
        /// Uncompressed size declared by the payload header.
        uncompressed_size: u64,
    },
    /// All inner events and the end of the decompression stream were read
    /// successfully.
    TransactionPayloadEnd {
        /// File offset of the corresponding outer transaction payload.
        offset: u64,
    },
}

/// A checked outer event together with its original on-disk coordinates.
struct FramedEvent {
    event: Event,
    offset: u64,
    size: u32,
}

impl FramedEvent {
    fn into_parsed(self, payload: EventPayload) -> ParsedEvent {
        let header = self.event.header();
        ParsedEvent {
            offset: self.offset,
            timestamp: header.timestamp(),
            event_type: EventType::from_raw(header.event_type_raw()),
            event_type_code: header.event_type_raw(),
            server_id: header.server_id(),
            event_size: self.size,
            log_pos: header.log_pos(),
            payload,
        }
    }
}

#[derive(Clone, Copy)]
struct PayloadInfo {
    compression: &'static str,
    uncompressed_size: u64,
}

enum PayloadItem {
    Start(PayloadInfo),
    Event(ParsedEvent),
}

/// Framing-layer failure raised by [`BinlogParser::read_framed_event`].
///
/// The helper runs where the failed event's file offset is known to its
/// callers but not to itself, so it reports the framing problem without one;
/// the callers map it onto the public [`ParserError`] structured variants
/// with the starting offset (R45).
#[derive(Debug, thiserror::Error)]
enum FrameError {
    /// The event's CRC32 checksum does not match its bytes.
    #[error("event checksum mismatch")]
    Checksum,
    /// The event body ended before its declared size was read.
    #[error("failed to fill whole buffer")]
    Truncated,
    /// The declared event size is outside the valid range.
    #[error("invalid or oversized event")]
    OversizedEvent {
        /// Declared size carried in the event header.
        size: u32,
        /// The configured per-event size cap.
        limit: u32,
    },
    /// Any other I/O failure while framing the event.
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl FrameError {
    /// Attaches the file offset where the failed event begins, keeping every
    /// public Display string identical to the one the path emitted before
    /// the structured variants existed (R45).
    fn into_parser_error(self, offset: u64) -> ParserError {
        match self {
            Self::Checksum => ParserError::Checksum { offset },
            Self::Truncated => ParserError::Truncated { offset },
            Self::OversizedEvent { size, limit } => ParserError::OversizedEvent {
                offset,
                size,
                limit,
            },
            Self::Io(source) => ParserError::Io { offset, source },
        }
    }
}

/// Classifies an I/O failure while filling the raw event buffer: a short
/// read is the truncated/EOF path (R45), everything else stays a plain I/O
/// error with its original source.
fn truncated_or_io(error: io::Error) -> FrameError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        FrameError::Truncated
    } else {
        FrameError::Io(error)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("transaction payload at inner offset {offset}: {source}")]
struct InnerEventError {
    offset: u64,
    #[source]
    source: io::Error,
}

/// Maintains the format description and table maps while reading one event at a time.
///
/// The reader works on any [`Read`] input (a file, standard input, or an
/// in-memory buffer). Raw event sizes are capped at [`MAX_EVENT_SIZE`] by
/// default, configurable through [`BinlogParser::with_max_event_size`], and
/// the inner-event collection of the collecting [`BinlogParser::events`]
/// iterator is bounded by [`DEFAULT_INNER_EVENT_LIMIT`], configurable
/// through [`BinlogParser::with_inner_event_limit`] (R46b). Decoded row
/// images can consume more memory than their wire data.
/// [`BinlogParser::visit_events`] delivers and releases each inner event in
/// turn while retaining the outer raw payload and shared table-map state.
pub struct BinlogParser<R: Read = File> {
    reader: EventStreamReader,
    input: BufReader<R>,
    offset: u64,
    stopped: bool,
    buffer: Vec<u8>,
    max_event_size: u32,
    /// Inner-event collection bound of the collecting iterator (R46b).
    inner_event_limit: usize,
    warnings: Vec<String>,
    /// Per-table signedness metadata (R42): `signedness()` walks the table
    /// map's serialized body, so it is computed once per registration instead
    /// of once per row event. Entries are replaced when a table map
    /// re-registers the same table id.
    signedness_cache: HashMap<u64, std::sync::Arc<Vec<Option<bool>>>>,
}

impl BinlogParser<File> {
    /// Open a plaintext binlog. Encrypted input is explicitly rejected.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ParserError> {
        let file = File::open(path).map_err(|source| ParserError::Io { offset: 0, source })?;
        Self::from_reader(file)
    }
}

impl<R: Read> BinlogParser<R> {
    /// Read from an arbitrary streaming source after validating the four-byte
    /// binlog magic.
    ///
    /// Only the magic is consumed here; events are read lazily through
    /// [`BinlogParser::events`], so the input does not need to be seekable.
    pub fn from_reader(reader: R) -> Result<Self, ParserError> {
        let mut input = BufReader::with_capacity(READ_BUFFER_CAPACITY, reader);
        let mut magic = [0; 4];
        input.read_exact(&mut magic).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                ParserError::InvalidHeader
            } else {
                ParserError::Io {
                    offset: 0,
                    source: e,
                }
            }
        })?;
        match &magic {
            b"\xfd\x62\x69\x6e" => return Err(ParserError::EncryptedBinlog),
            b"\xfe\x62\x69\x6e" => (),
            _ => return Err(ParserError::InvalidHeader),
        }
        Ok(Self {
            reader: EventStreamReader::new(BinlogVersion::Version4),
            input,
            offset: 4,
            stopped: false,
            buffer: Vec::new(),
            max_event_size: MAX_EVENT_SIZE,
            inner_event_limit: DEFAULT_INNER_EVENT_LIMIT,
            warnings: Vec::new(),
            signedness_cache: HashMap::new(),
        })
    }

    /// Overrides the per-event size cap (defaulting to [`MAX_EVENT_SIZE`]).
    pub fn with_max_event_size(mut self, cap: u32) -> Self {
        self.max_event_size = cap;
        self
    }

    /// Overrides the inner-event collection bound of the collecting
    /// [`BinlogParser::events`] iterator (defaulting to
    /// [`DEFAULT_INNER_EVENT_LIMIT`], R46b).
    ///
    /// Like [`Self::with_max_event_size`], this is infallible builder-style
    /// configuration: a limit of zero cannot be expressed because the
    /// argument is a [`core::num::NonZeroUsize`]. Only the collecting path
    /// is bounded; [`Self::visit_events`] stays uncapped because its
    /// callback applies backpressure.
    pub fn with_inner_event_limit(mut self, limit: core::num::NonZeroUsize) -> Self {
        self.inner_event_limit = limit.get();
        self
    }

    /// Drains the advisory warnings collected so far.
    ///
    /// Warnings are non-fatal observations that do not stop parsing — most
    /// notably a header `log_pos` that does not land right after its event.
    /// The buffer is bounded, so a corrupt file cannot grow it without limit;
    /// call this periodically (the CLI drains after each input).
    pub fn take_warnings(&mut self) -> Vec<String> {
        std::mem::take(&mut self.warnings)
    }

    /// Iterate over events, retrying transient [`io::ErrorKind::Interrupted`]
    /// reads. Other I/O errors and framing or decoding errors terminate the stream.
    ///
    /// This iterator collects the inner events of each transaction payload
    /// into `EventPayload::TransactionPayload.events`, so that collection is
    /// bounded by [`DEFAULT_INNER_EVENT_LIMIT`] (configurable through
    /// [`Self::with_inner_event_limit`], R46b); breaching the bound stops the
    /// stream with [`ParserError::TooManyInnerEvents`].
    pub fn events(&mut self) -> impl Iterator<Item = Result<ParsedEvent, ParserError>> + '_ {
        std::iter::from_fn(move || self.next_event())
    }

    /// Visit the remaining events, consuming compressed transactions one
    /// inner event at a time.
    ///
    /// Unlike [`Self::events`], this method does not collect the decoded inner
    /// events of a transaction into a vector. The parser retains the outer
    /// compressed event, the current inner event, and its shared table maps.
    /// A single decoded event can still contain multiple row images. The
    /// collecting path's [`DEFAULT_INNER_EVENT_LIMIT`] does not apply here:
    /// the callback consumes each inner event immediately, so memory stays
    /// bounded by backpressure instead of a numeric cap (R46b).
    ///
    /// The callback receives [`VisitEvent::TransactionPayloadStart`] only
    /// after outer framing, checksum, and payload-header validation and
    /// decompressor creation succeed. [`VisitEvent::TransactionPayloadEnd`]
    /// confirms that all inner events and the decompression stream completed.
    /// Previously delivered callbacks cannot be rolled back on a later error.
    ///
    /// Return [`ControlFlow::Break`] from the callback to stop immediately.
    /// EOF returns [`ControlFlow::Continue`]. Both outcomes leave this parser
    /// terminated. Callback errors carry the current outer
    /// file offset through [`ParserError::Io`]. A callback error or panic
    /// also terminates the parser, so subsequent calls cannot resume with
    /// partially updated table-map state.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use binlog_inspect::parser::{BinlogParser, VisitEvent};
    /// use std::ops::ControlFlow;
    ///
    /// let mut parser = BinlogParser::open("mysql-bin.000001")?;
    /// let mut inner_events = 0u64;
    /// let outcome = parser.visit_events(|notification| {
    ///     if let VisitEvent::Event { parent_offset: Some(_), .. } = notification {
    ///         inner_events += 1;
    ///     }
    ///     Ok(ControlFlow::Continue(()))
    /// })?;
    /// assert_eq!(outcome, ControlFlow::Continue(()));
    /// println!("Decoded {inner_events} inner events");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn visit_events(
        &mut self,
        mut visitor: impl FnMut(VisitEvent<'_>) -> io::Result<ControlFlow<()>>,
    ) -> Result<ControlFlow<()>, ParserError> {
        if self.stopped {
            return Ok(ControlFlow::Continue(()));
        }
        // The raw framing helper does not consult this flag. Setting it
        // before invoking user code also makes a caught callback panic fuse
        // the public parser without a guard or unsafe code.
        self.stopped = true;
        loop {
            let offset = self.offset;
            let Some(framed) = self
                .read_framed_event()
                .map_err(|error| error.into_parser_error(offset))?
            else {
                return Ok(ControlFlow::Continue(()));
            };
            let result = (|| -> io::Result<ControlFlow<()>> {
                if framed.event.header().event_type_raw() == 40 {
                    let header = framed.event.header();
                    let flow =
                        self.walk_transaction_payload(&framed.event, &mut |item| match item {
                            PayloadItem::Start(info) => {
                                visitor(VisitEvent::TransactionPayloadStart {
                                    offset,
                                    timestamp: header.timestamp(),
                                    server_id: header.server_id(),
                                    event_size: framed.size,
                                    log_pos: header.log_pos(),
                                    compression: info.compression,
                                    uncompressed_size: info.uncompressed_size,
                                })
                            }
                            PayloadItem::Event(event) => visitor(VisitEvent::Event {
                                event: &event,
                                parent_offset: Some(offset),
                            }),
                        })?;
                    if flow.is_break() {
                        return Ok(ControlFlow::Break(()));
                    }
                    visitor(VisitEvent::TransactionPayloadEnd { offset })
                } else {
                    let payload = self.payload_for(&framed.event)?;
                    let event = framed.into_parsed(payload);
                    visitor(VisitEvent::Event {
                        event: &event,
                        parent_offset: None,
                    })
                }
            })();
            if result
                .map_err(|source| ParserError::Io { offset, source })?
                .is_break()
            {
                return Ok(ControlFlow::Break(()));
            }
        }
    }

    /// Length of the trailing checksum the underlying library will strip from
    /// an event of the given raw type, according to the active format
    /// description.
    fn checksum_len(&self, raw_type: u8) -> usize {
        if raw_type != 15
            && self
                .reader
                .get_fde()
                .footer()
                .get_checksum_alg()
                .ok()
                .flatten()
                == Some(BinlogChecksumAlg::BINLOG_CHECKSUM_ALG_CRC32)
        {
            4
        } else {
            0
        }
    }

    fn next_event(&mut self) -> Option<Result<ParsedEvent, ParserError>> {
        if self.stopped {
            return None;
        }
        let offset = self.offset;
        let result = (|| -> Result<Option<ParsedEvent>, ParserError> {
            let Some(framed) = self
                .read_framed_event()
                .map_err(|error| error.into_parser_error(offset))?
            else {
                return Ok(None);
            };
            let payload = if framed.event.header().event_type_raw() == 40 {
                self.transaction_payload(&framed.event, offset)?
            } else {
                self.payload_for(&framed.event)
                    .map_err(|source| ParserError::Io { offset, source })?
            };
            Ok(Some(framed.into_parsed(payload)))
        })();
        match result {
            Ok(Some(e)) => Some(Ok(e)),
            Ok(None) => {
                self.stopped = true;
                None
            }
            Err(error) => {
                self.stopped = true;
                Some(Err(error))
            }
        }
    }

    /// Read and validate one outer event, retaining its original coordinates
    /// when table-map metadata is stripped before library decoding.
    ///
    /// Failures are reported as [`FrameError`] without the file offset; the
    /// callers attach the offset where the event begins and map them onto
    /// the public [`ParserError`] variants (R45).
    fn read_framed_event(&mut self) -> Result<Option<FramedEvent>, FrameError> {
        let offset = self.offset;
        // Validate framing before allowing the library to allocate the event buffer.
        let mut head = [0u8; 19];
        // Retry transient interruptions without treating a reader's
        // UnexpectedEof error as a clean event boundary.
        let first = loop {
            match self.input.read(&mut head[..1]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };
        if first == 0 {
            return Ok(None);
        }
        self.input
            .read_exact(&mut head[1..])
            .map_err(truncated_or_io)?;
        let size = u32::from_le_bytes(head[9..13].try_into().unwrap());
        if !(19..=self.max_event_size).contains(&size) {
            return Err(FrameError::OversizedEvent {
                size,
                limit: self.max_event_size,
            });
        }
        // mysql_common assumes the complete event body is available.
        if head[4] == 15 && size < 19 + 57 {
            return Err(FrameError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "short format description",
            )));
        }
        if head[4] != 15 && self.checksum_len(head[4]) > 0 && size < 23 {
            return Err(FrameError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "short checksummed event",
            )));
        }
        // Resizing without clearing only zero-fills the newly observed
        // tail; every byte is overwritten by the head and body anyway.
        self.buffer.resize(size as usize, 0);
        self.buffer[..19].copy_from_slice(&head);
        self.input
            .read_exact(&mut self.buffer[19..])
            .map_err(truncated_or_io)?;
        // Hostile-input prevalidation before the library decodes anything:
        // its previous-GTIDs and table-map metadata parsers allocate from
        // untrusted declared counts, and its transaction-payload header
        // parser unwraps the compression type, so crafted input would
        // abort the process.
        let data_len = self.buffer.len() - 19 - self.checksum_len(head[4]);
        let body = &self.buffer[19..19 + data_len];
        if head[4] == 35 {
            validate_previous_gtids(body)?;
        }
        if head[4] == 19 {
            let header_len = self.reader.get_fde().get_event_type_header_length(
                mysql_common::binlog::consts::EventType::TABLE_MAP_EVENT,
            );
            crate::row_decode::validate_table_map_metadata(body, header_len)?;
        }
        if head[4] == 40 {
            validate_transaction_payload_header(body)?;
        }
        // Table maps of partial-JSON binlogs (WL#2955) carry optional
        // metadata types the library's lazily iterated metadata rejects;
        // those entries are stripped from the bytes the library parses,
        // so the stored table map stays acceptable for every later row
        // event. The strip runs after the prevalidation of the original
        // bytes, and only for table maps.
        let mut stripped_tlv_bytes = 0usize;
        if head[4] == 19 {
            let header_len = self.reader.get_fde().get_event_type_header_length(
                mysql_common::binlog::consts::EventType::TABLE_MAP_EVENT,
            );
            let ranges =
                crate::row_decode::unsupported_tlv_ranges(body, header_len)?.unwrap_or_default();
            if !ranges.is_empty() {
                // The checksum must be verified on the original bytes:
                // stripping changes everything the library would hash.
                if self.checksum_len(head[4]) > 0 {
                    verify_event_checksum(&self.buffer)?;
                }
                stripped_tlv_bytes = remove_ranges(&mut self.buffer, 19, &ranges);
                let new_size = u32::try_from(self.buffer.len()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid event size")
                })?;
                self.buffer[9..13].copy_from_slice(&new_size.to_le_bytes());
            }
        }
        let Some(event) = self.reader.read(&mut Cursor::new(self.buffer.as_slice()))? else {
            return Ok(None);
        };
        let checksum_algorithm = event
            .footer()
            .get_checksum_alg()
            .map_err(|err| io::Error::new(io::ErrorKind::Unsupported, err))?;
        if stripped_tlv_bytes == 0
            && let (Some(checksum), Some(alg)) = (event.checksum(), checksum_algorithm)
            && u32::from_le_bytes(checksum) != event.calc_checksum(alg)
        {
            return Err(FrameError::Checksum);
        }
        let h = event.header();
        // The header `event_size` reflects the stripped bytes; the
        // original size is what positions the stream and the output.
        self.offset += u64::from(size);
        // Advisory only (R35): on a master-written file each header's
        // log_pos lands right after its event. A mismatch suggests
        // tampering or a spliced file but does not stop parsing; a zero
        // log_pos is how artificial events mark "no position".
        const WARNING_CAP: usize = 100;
        let log_pos = u64::from(h.log_pos());
        let expected = offset + u64::from(size);
        if log_pos != 0 && log_pos != expected && self.warnings.len() < WARNING_CAP {
            self.warnings.push(format!(
                "log_pos {log_pos} does not match offset {offset} + event size {size}"
            ));
        }
        Ok(Some(FramedEvent {
            event,
            offset,
            size,
        }))
    }

    /// Maps a decoded event onto the stable payload model.
    ///
    /// Shared between the outer event stream and the events decompressed out
    /// of a transaction payload: table maps registered by inner events live in
    /// the same reader state, so inner and later outer row events resolve
    /// identically.
    fn payload_for(&mut self, event: &Event) -> io::Result<EventPayload> {
        let payload = match event.read_data()? {
            Some(EventData::FormatDescriptionEvent(e)) => EventPayload::FormatDescription {
                server_version: server_version(e.server_version_raw()),
            },
            Some(EventData::TableMapEvent(e)) => {
                // Refresh the signedness cache on every registration: a
                // re-registered table id carries a new schema, so the cached
                // entry must be replaced (R42).
                let table_id = e.table_id();
                if let Some(map) = self.reader.get_tme(table_id) {
                    let computed = std::sync::Arc::new(crate::row_decode::signedness(map)?);
                    self.signedness_cache.insert(table_id, computed);
                }
                EventPayload::TableMap {
                    table_id: e.table_id(),
                    database: e.database_name().into_owned(),
                    table: e.table_name().into_owned(),
                    column_count: e.columns_count(),
                }
            }
            Some(EventData::QueryEvent(e)) => EventPayload::Query {
                database: e.schema().into_owned(),
                sql: e.query().into_owned(),
            },
            Some(EventData::XidEvent(e)) => EventPayload::Xid { xid: e.xid },
            Some(EventData::RotateEvent(e)) => EventPayload::Rotate {
                next_file: e.name().into_owned(),
                position: e.position(),
            },
            Some(EventData::GtidEvent(e)) => {
                let mut gtid = format_sid(&e.sid());
                let tag = e.tag().map(|tag| tag.as_str().to_owned());
                if let Some(tag) = &tag {
                    gtid.push(':');
                    gtid.push_str(tag);
                }
                gtid.push(':');
                gtid.push_str(&e.gno().to_string());
                EventPayload::Gtid { gtid, tag }
            }
            // Anonymous GTID events carry no GTID; mysqlbinlog renders the
            // placeholder "ANONYMOUS".
            Some(EventData::AnonymousGtidEvent(_)) => EventPayload::Gtid {
                gtid: "ANONYMOUS".to_owned(),
                tag: None,
            },
            Some(EventData::PreviousGtidsEvent(e)) => EventPayload::PreviousGtids {
                gtid_set: format_gtid_set(&e),
            },
            Some(EventData::StopEvent) => EventPayload::Stop,
            Some(EventData::RowsQueryEvent(e)) => EventPayload::RowsQuery {
                sql: e.query().into_owned(),
            },
            Some(EventData::IncidentEvent(e)) => EventPayload::Incident {
                incident_type: match e.incident_type() {
                    // The canonical name is pinned below (R51), not the
                    // library's Debug rendering, so a library rename cannot
                    // change the output.
                    Ok(incident_type) => incident_type_name(incident_type).to_owned(),
                    Err(unknown) => format!("UNKNOWN({})", u16::from(unknown)),
                },
                message: e.message().into_owned(),
            },
            Some(EventData::IntvarEvent(e)) => EventPayload::Intvar {
                var_type: intvar_type_name(e.subtype()).to_owned(),
                value: e.value(),
            },
            Some(EventData::RowsEvent(RowsEventData::PartialUpdateRowsEvent(e))) => {
                // Partial update rows (WL#2955): the before image is a full
                // row image, the after image carries JSON diffs per JSON
                // column. The pair decode applies each diff sequence against
                // the before value; unappliable diffs surface as loss-marked
                // PartialJson cells instead of failing the event.
                let id = e.table_id();
                match self.reader.get_tme(id) {
                    Some(map) => {
                        // Mirror the MySQL applier: a row event may declare
                        // fewer columns than the table map records (the table
                        // grew after the event was written), but never more.
                        if e.num_columns() > map.columns_count() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "row event column count exceeds the table map",
                            ));
                        }
                        let n = usize::try_from(map.columns_count()).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "column count overflow")
                        })?;
                        let declared = usize::try_from(e.num_columns()).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "column count overflow")
                        })?;
                        let pad = |bits: Vec<bool>| {
                            let mut bits = bits;
                            bits.resize(n, false);
                            bits
                        };
                        let before_bitmap = Some(e.columns_before_image())
                            .map(|bits| {
                                crate::row_decode::present_bits(bits.iter().by_vals(), declared)
                                    .map(pad)
                            })
                            .transpose()?;
                        let after_bitmap = Some(e.columns_after_image())
                            .map(|bits| {
                                crate::row_decode::present_bits(bits.iter().by_vals(), declared)
                                    .map(pad)
                            })
                            .transpose()?;
                        // The signedness walk re-serializes the table map, so
                        // it is cached per table id at registration (R42);
                        // the fallback covers ids the cache has not seen.
                        let signedness = {
                            if let Some(cached) = self.signedness_cache.get(&id) {
                                std::sync::Arc::clone(cached)
                            } else {
                                let computed =
                                    std::sync::Arc::new(crate::row_decode::signedness(map)?);
                                self.signedness_cache
                                    .insert(id, std::sync::Arc::clone(&computed));
                                computed
                            }
                        };
                        // R50: prevalidate the row layout before the library
                        // iterates the rows — hostile packed decimals and
                        // trailing bytes are rejected with precise messages
                        // instead of the dependency's panics or silent
                        // misdecoding. The after image carries the WL#2955
                        // value-options header here.
                        // The partial-update accessors return the bitmaps
                        // directly (both images are always present here).
                        let before_layout = Some(e.columns_before_image())
                            .zip(before_bitmap.as_deref())
                            .map(|(bits, present)| crate::row_decode::RowImageLayout {
                                bitmap_ones: bits.count_ones(),
                                present,
                                partial_header: false,
                            });
                        let after_layout = Some(e.columns_after_image())
                            .zip(after_bitmap.as_deref())
                            .map(|(bits, present)| crate::row_decode::RowImageLayout {
                                bitmap_ones: bits.count_ones(),
                                present,
                                partial_header: true,
                            });
                        crate::row_decode::prevalidate_row_layout(
                            e.rows_data(),
                            &[before_layout, after_layout],
                            map.json_column_count(),
                            map,
                        )?;
                        let mut before = Vec::new();
                        let mut after = Vec::new();
                        for row in e.rows(map) {
                            let (before_row, after_row) = row?;
                            let (before_image, after_image) = crate::row_decode::decode_rows_pair(
                                before_row.as_ref(),
                                after_row.as_ref(),
                                before_bitmap.as_deref(),
                                after_bitmap.as_deref(),
                                &signedness,
                            )?;
                            before.push(before_image);
                            after.push(after_image);
                        }
                        EventPayload::PartialUpdateRows {
                            table_id: id,
                            database: map.database_name().into_owned(),
                            table: map.table_name().into_owned(),
                            before,
                            after,
                        }
                    }
                    None => EventPayload::Unresolved { table_id: id },
                }
            }
            Some(EventData::RowsEvent(e)) => {
                let id = e.table_id();
                if let Some(map) = self.reader.get_tme(id) {
                    // With no selected columns, an ordinary row consumes
                    // neither a NULL bitmap nor values. The dependency's
                    // iterator would repeatedly yield an empty row while
                    // retaining the same nonempty data buffer.
                    if !e.rows_data().is_empty()
                        && !e.columns_before_image().is_some_and(|bits| bits.any())
                        && !e.columns_after_image().is_some_and(|bits| bits.any())
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "row data with no selected columns cannot make progress",
                        ));
                    }
                    // See the PartialUpdateRows arm: a row event may
                    // declare fewer columns than the table map, never
                    // more; missing tail columns render as absent.
                    if e.num_columns() > map.columns_count() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "row event column count exceeds the table map",
                        ));
                    }
                    let n = usize::try_from(map.columns_count()).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "column count overflow")
                    })?;
                    let declared = usize::try_from(e.num_columns()).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "column count overflow")
                    })?;
                    let pad = |bits: Vec<bool>| {
                        let mut bits = bits;
                        bits.resize(n, false);
                        bits
                    };
                    let before_bitmap = e
                        .columns_before_image()
                        .map(|bits| {
                            crate::row_decode::present_bits(bits.iter().by_vals(), declared)
                                .map(pad)
                        })
                        .transpose()?;
                    let after_bitmap = e
                        .columns_after_image()
                        .map(|bits| {
                            crate::row_decode::present_bits(bits.iter().by_vals(), declared)
                                .map(pad)
                        })
                        .transpose()?;
                    // Cached per table id at registration (R42); see the
                    // PartialUpdateRows arm for the fallback.
                    let signedness = {
                        if let Some(cached) = self.signedness_cache.get(&id) {
                            std::sync::Arc::clone(cached)
                        } else {
                            let computed = std::sync::Arc::new(crate::row_decode::signedness(map)?);
                            self.signedness_cache
                                .insert(id, std::sync::Arc::clone(&computed));
                            computed
                        }
                    };
                    // R50: prevalidate the row layout before the library
                    // iterates the rows — hostile packed decimals and
                    // trailing bytes are rejected with precise messages
                    // instead of the dependency's panics or silent
                    // misdecoding.
                    let before_layout = e.columns_before_image().zip(before_bitmap.as_deref()).map(
                        |(bits, present)| crate::row_decode::RowImageLayout {
                            bitmap_ones: bits.count_ones(),
                            present,
                            partial_header: false,
                        },
                    );
                    let after_layout = e.columns_after_image().zip(after_bitmap.as_deref()).map(
                        |(bits, present)| crate::row_decode::RowImageLayout {
                            bitmap_ones: bits.count_ones(),
                            present,
                            partial_header: false,
                        },
                    );
                    crate::row_decode::prevalidate_row_layout(
                        e.rows_data(),
                        &[before_layout, after_layout],
                        map.json_column_count(),
                        map,
                    )?;
                    let mut changes = Vec::new();
                    for row in e.rows(map) {
                        let (before_row, after_row) = row?;
                        // The pair decode applies partial-JSON after images
                        // (WL#2955) to their before values; images without
                        // diffs decode exactly like single images.
                        let (before, after) = crate::row_decode::decode_rows_pair(
                            before_row.as_ref(),
                            after_row.as_ref(),
                            before_bitmap.as_deref(),
                            after_bitmap.as_deref(),
                            &signedness,
                        )?;
                        changes.push(RowChange { before, after });
                    }
                    EventPayload::Rows {
                        table_id: id,
                        database: map.database_name().into_owned(),
                        table: map.table_name().into_owned(),
                        changes,
                    }
                } else {
                    EventPayload::Unresolved { table_id: id }
                }
            }
            // Named but undecoded event types (rand, user_var, heartbeat,
            // ignorable, ...) and event types the library cannot decode at
            // all (e.g. code 41) keep only their raw length. Nested
            // transaction payloads never reach here: they are rejected while
            // streaming the inner event.
            _ => EventPayload::Unknown {
                raw_len: event.data().len(),
            },
        };
        Ok(payload)
    }

    /// Decodes a compressed transaction payload (code 40, WL#3549).
    ///
    /// The framing layer has already validated the payload header (see
    /// [`validate_transaction_payload_header`]). The declared uncompressed
    /// size is bounded before any decompression, and the library's streaming
    /// `decompressed()` reader is wrapped in a [`PayloadStream`] that counts
    /// every decompressed byte against the declaration and prevalidates each
    /// inner event before the library parses it. Inner events carry no
    /// checksums (WL#3549), and the library registers their table maps in the
    /// shared reader state so later outer row events resolve. `offset` is the
    /// outer event's file position, attached to failures (R45).
    fn transaction_payload(
        &mut self,
        event: &Event,
        offset: u64,
    ) -> Result<EventPayload, ParserError> {
        // R46b: only the collecting path buffers inner events into memory,
        // so only this path enforces the inner-event limit. The visiting
        // path hands each event to the callback, which applies backpressure.
        let limit = self.inner_event_limit;
        let mut events = Vec::new();
        let mut over_limit = false;
        let flow = self
            .walk_transaction_payload(event, &mut |item| {
                if let PayloadItem::Event(event) = item {
                    if events.len() >= limit {
                        over_limit = true;
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "transaction payload inner event limit exceeded",
                        ));
                    }
                    events.push(event);
                }
                Ok(ControlFlow::<Infallible>::Continue(()))
            })
            .map_err(|source| {
                // The closure records the breach before returning: the only
                // error that can carry the flag out of the walk is this one,
                // because an emit error propagates immediately.
                if over_limit {
                    ParserError::TooManyInnerEvents { offset, limit }
                } else {
                    ParserError::Io { offset, source }
                }
            })?;
        let info = match flow {
            ControlFlow::Continue(info) => info,
            ControlFlow::Break(never) => match never {},
        };
        Ok(EventPayload::TransactionPayload {
            compression: info.compression.to_owned(),
            uncompressed_size: info.uncompressed_size,
            events,
        })
    }

    /// Shared payload decoder. The collecting API owns each emitted event;
    /// the visiting API borrows it for one callback and then drops it.
    fn walk_transaction_payload<B>(
        &mut self,
        event: &Event,
        emit: &mut impl FnMut(PayloadItem) -> io::Result<ControlFlow<B>>,
    ) -> io::Result<ControlFlow<B, PayloadInfo>> {
        let Some(EventData::TransactionPayloadEvent(payload)) = event.read_data()? else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed transaction payload",
            ));
        };
        let compression = match payload.algorithm() {
            TransactionPayloadCompressionType::NONE => "NONE",
            TransactionPayloadCompressionType::ZSTD => "ZSTD",
        };
        let uncompressed_size = payload.uncompressed_size();
        if uncompressed_size > MAX_UNCOMPRESSED_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compressed payload declares excessive uncompressed size",
            ));
        }
        // The library only writes uncompressed_size for compressed payloads
        // (NONE payloads carry 0 on the wire); for NONE the decompressed
        // stream is the payload bytes themselves, so the exact payload size
        // is the honest limit — the limit below is looser than exact by the
        // header TLV bytes the framing already consumed, a difference the
        // 1 MiB slack covers intentionally. Compressed payloads get the
        // declared size plus a small slack so a bomb must lie by more than
        // the slack to pass.
        let limit = match payload.algorithm() {
            TransactionPayloadCompressionType::NONE => u64::from(event.header().event_size())
                .saturating_sub(19)
                .saturating_add(PAYLOAD_SIZE_SLACK),
            TransactionPayloadCompressionType::ZSTD => {
                uncompressed_size.saturating_add(PAYLOAD_SIZE_SLACK)
            }
        };
        let tme_header_len = self
            .reader
            .get_fde()
            .get_event_type_header_length(mysql_common::binlog::consts::EventType::TABLE_MAP_EVENT);
        let mut stream = PayloadStream::new(
            payload.decompressed()?,
            limit,
            u64::from(self.max_event_size),
            tme_header_len,
        );
        let info = PayloadInfo {
            compression,
            uncompressed_size,
        };
        if let ControlFlow::Break(value) = emit(PayloadItem::Start(info))? {
            return Ok(ControlFlow::Break(value));
        }
        let timestamp = event.header().timestamp();
        let server_id = event.header().server_id();
        loop {
            let offset = stream.position;
            let decoded = (|| -> io::Result<Option<ParsedEvent>> {
                let Some(inner) = self.reader.read_decompressed(&mut stream)? else {
                    return Ok(None);
                };
                let h = inner.header();
                Ok(Some(ParsedEvent {
                    offset: stream.last_event_offset(),
                    timestamp,
                    event_type: EventType::from_raw(h.event_type_raw()),
                    event_type_code: h.event_type_raw(),
                    server_id,
                    // The declared size, not the stripped one the library saw.
                    event_size: stream.last_event_size(),
                    log_pos: h.log_pos(),
                    payload: self.payload_for(&inner)?,
                }))
            })()
            .map_err(|source| io::Error::new(source.kind(), InnerEventError { offset, source }))?;
            let Some(decoded) = decoded else {
                break;
            };
            if let ControlFlow::Break(value) = emit(PayloadItem::Event(decoded))? {
                return Ok(ControlFlow::Break(value));
            }
        }
        Ok(ControlFlow::Continue(info))
    }
}

/// Streaming adapter over the decompressed payload of a transaction payload
/// event.
///
/// The library reader yields raw decompressed bytes. This adapter re-frames
/// them into whole inner events (the inner stream carries no event checksums,
/// WL#3549), hands them to the library one event at a time, and enforces the
/// compressed-payload safety rules: every byte is counted against the declared
/// uncompressed size, a single inner event may not exceed the parser's event
/// size cap, and each inner event is prevalidated exactly like an outer one so
/// the library's hostile-input allocation paths are never reached.
struct PayloadStream<'a> {
    inner: TransactionPayloadReader<'a>,
    /// The fully buffered inner event currently being consumed.
    pending: Vec<u8>,
    /// Bytes of `pending` already handed downstream.
    consumed: usize,
    /// Total bytes handed downstream, i.e. the byte position in the
    /// decompressed stream.
    position: u64,
    /// Start position of the most recently buffered inner event.
    event_start: u64,
    /// Maximum total decompressed bytes: declared uncompressed size plus slack.
    limit: u64,
    /// Per-event cap mirroring the parser's own event size limit.
    max_event_size: u64,
    /// Post-header length of table map events per the active format
    /// description, needed to prevalidate inner table maps.
    tme_header_len: u8,
    /// Declared size of the most recently buffered inner event, before any
    /// partial-JSON metadata stripping changed the buffered bytes.
    last_event_size: u32,
}

impl<'a> PayloadStream<'a> {
    fn new(
        inner: TransactionPayloadReader<'a>,
        limit: u64,
        max_event_size: u64,
        tme_header_len: u8,
    ) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            consumed: 0,
            position: 0,
            event_start: 0,
            limit,
            max_event_size,
            tme_header_len,
            last_event_size: 0,
        }
    }

    /// Byte offset within the decompressed stream of the most recently
    /// buffered inner event.
    fn last_event_offset(&self) -> u64 {
        self.event_start
    }

    /// Declared size (header included) of the most recently buffered inner
    /// event, before any partial-JSON metadata stripping.
    fn last_event_size(&self) -> u32 {
        self.last_event_size
    }

    /// Buffers the next inner event. Returns `false` at a clean end of the
    /// decompressed stream.
    fn load_next_event(&mut self) -> io::Result<bool> {
        let mut header = [0u8; 19];
        match fill_from(&mut self.inner, &mut header)? {
            0 => return Ok(false),
            // The stream ended between events; anything else is truncation.
            n if n < header.len() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated transaction payload",
                ));
            }
            _ => (),
        }
        let size = u32::from_le_bytes(header[9..13].try_into().unwrap());
        let raw = header[4];
        if size < 19 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid inner event size",
            ));
        }
        if raw == 40 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "nested transaction payload",
            ));
        }
        // A format description or rotate inside a payload would rewrite the
        // shared parser state (checksum handling, table maps); legitimate
        // payloads only carry the transaction's data events.
        if raw == 15 || raw == 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected event inside transaction payload",
            ));
        }
        let size = usize::try_from(size)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid inner event size"))?;
        let max = usize::try_from(self.max_event_size)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid event size limit"))?;
        if size > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inner event exceeds the event size limit",
            ));
        }
        if self.position + u64::try_from(size).unwrap_or(u64::MAX) > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decompressed payload exceeds declared size",
            ));
        }
        self.pending.clear();
        self.pending.resize(size, 0);
        self.pending[..header.len()].copy_from_slice(&header);
        if fill_from(&mut self.inner, &mut self.pending[header.len()..])? != size - header.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated transaction payload",
            ));
        }
        // Hostile-input prevalidation, identical to the outer framing: the
        // library allocates from declared counts when parsing these bodies.
        let body = &self.pending[header.len()..];
        if raw == 19 {
            crate::row_decode::validate_table_map_metadata(body, self.tme_header_len)?;
        }
        if raw == 35 {
            validate_previous_gtids(body)?;
        }
        // The offsets and sizes reported for inner events always refer to the
        // original decompressed stream, including stripped bytes.
        self.event_start = self.position;
        self.last_event_size = u32::try_from(size)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid inner event size"))?;
        if raw == 19 {
            // Inner table maps are stripped exactly like outer ones: the
            // library's metadata iterator would reject the partial-JSON
            // entries when decoding later row events. The inner stream
            // carries no checksums (WL#3549), so nothing needs re-verification.
            let ranges = crate::row_decode::unsupported_tlv_ranges(body, self.tme_header_len)?
                .unwrap_or_default();
            if !ranges.is_empty() {
                let removed = remove_ranges(&mut self.pending, header.len(), &ranges);
                let new_size = u32::try_from(self.pending.len()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid inner event size")
                })?;
                self.pending[9..13].copy_from_slice(&new_size.to_le_bytes());
                // The stripped bytes never reach the reader, so the position
                // is advanced here to keep the declared-size accounting exact.
                self.position += u64::try_from(removed).unwrap_or(u64::MAX);
            }
        }
        Ok(true)
    }
}

impl Read for PayloadStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        if available.is_empty() {
            return Ok(0);
        }
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for PayloadStream<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.consumed >= self.pending.len() {
            self.pending.clear();
            self.consumed = 0;
            if !self.load_next_event()? {
                return Ok(&[]);
            }
        }
        Ok(&self.pending[self.consumed..])
    }

    fn consume(&mut self, amt: usize) {
        let amt = amt.min(self.pending.len() - self.consumed);
        self.consumed += amt;
        self.position += amt as u64;
    }
}

/// Reads `buf.len()` bytes from `reader` unless the stream ends first and
/// returns the number of bytes read; the library's payload reader is a plain
/// `Read` whose `read` may return short reads.
fn fill_from(reader: &mut TransactionPayloadReader<'_>, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// Renders the server version with any NUL padding removed.
fn server_version(raw: &[u8]) -> String {
    let end = raw.iter().position(|&byte| byte == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// Canonical stable name for a replication incident type.
///
/// The library's `Debug` output must not leak into the output model, so
/// every [`IncidentType`] variant maps to its constant name; a library
/// rename cannot change the output (R51, mirroring the `column_type_name`
/// pattern).
fn incident_type_name(incident_type: IncidentType) -> &'static str {
    match incident_type {
        IncidentType::INCIDENT_NONE => "INCIDENT_NONE",
        IncidentType::INCIDENT_LOST_EVENTS => "INCIDENT_LOST_EVENTS",
    }
}

/// Canonical stable name for an intvar event subtype.
///
/// See [`incident_type_name`] for why the names are pinned instead of taken
/// from the library's `Debug` rendering (R51).
fn intvar_type_name(subtype: IntvarEventType) -> &'static str {
    match subtype {
        IntvarEventType::INVALID_INT_EVENT => "INVALID_INT_EVENT",
        IntvarEventType::LAST_INSERT_ID_EVENT => "LAST_INSERT_ID_EVENT",
        IntvarEventType::INSERT_ID_EVENT => "INSERT_ID_EVENT",
    }
}

/// Lowercase hex digits shared with the row decoder.
const HEX: [u8; 16] = *b"0123456789abcdef";

/// Renders a 16-byte SID as the canonical hyphenated lowercase UUID.
fn format_sid(sid: &[u8; 16]) -> String {
    let mut out = String::with_capacity(36);
    for (index, byte) in sid.iter().enumerate() {
        if index == 4 || index == 6 || index == 8 || index == 10 {
            out.push('-');
        }
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Renders a previous-GTIDs event in the mysqlbinlog textual form:
/// `uuid[:tag]:gno` per interval (single GTIDs without a dash, ranges as
/// `start-end` inclusive), with entries separated by commas.
fn format_gtid_set(event: &PreviousGtidsEvent<'_>) -> String {
    use std::fmt::Write as _;
    let mut parts: Vec<String> = Vec::new();
    for sid in event.sids() {
        let mut part = format_sid(&sid.uuid());
        if let Some(tag) = sid.tag() {
            let _ = write!(part, ":{}", tag.as_str());
        }
        for interval in sid.intervals() {
            let (start, end) = (interval.start(), interval.end());
            // Validation rejects degenerate intervals; the saturating
            // arithmetic keeps rendering total even if the library ever
            // yields one.
            let last = end.saturating_sub(1);
            if last == start {
                let _ = write!(part, ":{start}");
            } else {
                let _ = write!(part, ":{start}-{last}");
            }
        }
        parts.push(part);
    }
    parts.join(",")
}

/// Validates a previous-GTIDs event body before the library parses it.
///
/// The library sizes its SID and interval vectors from untrusted declared
/// counts, which aborts the process on crafted input. This walk mirrors the
/// library's wire format (8-byte header, then per SID: 16-byte UUID, optional
/// varlen tag, 8-byte interval count, 16 bytes per interval) and rejects any
/// declared count that the remaining bytes cannot satisfy, plus intervals the
/// renderer could not format safely.
fn validate_previous_gtids(body: &[u8]) -> io::Result<()> {
    const OVERSIZED: &str = "previous gtids payload exceeds event bounds";
    const INVALID_INTERVAL: &str = "invalid previous gtids interval";
    if body.len() < 8 {
        // Too short for the header; the library rejects this deterministically.
        return Ok(());
    }
    let header = u64::from_le_bytes(body[..8].try_into().unwrap());
    let tagged = (header >> 56) != 0;
    let n_sids = if tagged {
        (header >> 8) & ((1 << 48) - 1)
    } else {
        header & ((1 << 56) - 1)
    };
    // Conservative minimum per SID: 16 bytes of UUID plus 8 bytes of interval count.
    if u64::try_from(body.len() - 8).unwrap_or(u64::MAX) < n_sids.saturating_mul(24) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, OVERSIZED));
    }
    let mut pos = 8usize;
    for _ in 0..n_sids {
        if body.len() - pos < 24 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, OVERSIZED));
        }
        pos += 16; // UUID
        if tagged {
            let tag_len = read_varlen_uint(body, &mut pos)?;
            if u64::try_from(body.len() - pos).unwrap_or(u64::MAX) < tag_len {
                return Err(io::Error::new(io::ErrorKind::InvalidData, OVERSIZED));
            }
            pos += tag_len as usize;
            if body.len() - pos < 8 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, OVERSIZED));
            }
        }
        let n_intervals = u64::from_le_bytes(body[pos..pos + 8].try_into().unwrap());
        pos += 8;
        if u64::try_from(body.len() - pos).unwrap_or(u64::MAX) < n_intervals.saturating_mul(16) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, OVERSIZED));
        }
        for _ in 0..n_intervals {
            let start = u64::from_le_bytes(body[pos..pos + 8].try_into().unwrap());
            let end = u64::from_le_bytes(body[pos + 8..pos + 16].try_into().unwrap());
            // MySQL GNOs start at one and intervals are [start, end); the
            // renderer subtracts one from `end`, so degenerate values must
            // never reach it.
            if start == 0 || end <= start {
                return Err(io::Error::new(io::ErrorKind::InvalidData, INVALID_INTERVAL));
            }
            pos += 16;
        }
    }
    Ok(())
}

/// Reads a MySQL serialization library variable-length unsigned integer,
/// mirroring the library's encoding.
fn read_varlen_uint(buf: &[u8], pos: &mut usize) -> io::Result<u64> {
    let Some(&first) = buf.get(*pos) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected end of varlen integer",
        ));
    };
    let trailing_ones = first.trailing_ones() as usize;
    if trailing_ones == 8 {
        let end = pos
            .checked_add(9)
            .filter(|end| *end <= buf.len())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected end of varlen integer",
                )
            })?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&buf[*pos + 1..end]);
        *pos = end;
        return Ok(u64::from_le_bytes(raw));
    }
    let num_bytes = trailing_ones + 1;
    let end = pos
        .checked_add(num_bytes)
        .filter(|end| *end <= buf.len())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected end of varlen integer",
            )
        })?;
    let mut raw = [0u8; 8];
    raw[..num_bytes].copy_from_slice(&buf[*pos..end]);
    *pos = end;
    Ok(u64::from_le_bytes(raw) >> num_bytes)
}

/// Validates the TLV header of a transaction payload event body before the
/// library parses it.
///
/// The header starts right after the 19-byte event header and is a sequence of
/// fields, each a length-encoded type followed by field-specific content:
/// `0` marks the header end, `1` is the payload size, `2` the compression
/// algorithm, `3` the uncompressed size, anything else is skipped by declared
/// length. The library's parser panics on an unknown algorithm byte, on a
/// field type above `u8::MAX` (its error constructor cannot hold one), and on
/// a skip length or length prefix that runs past the buffer, so this walk
/// mirrors its loop and turns each of those into a clean `InvalidData` error.
/// Truncations on the strictly parsed fields are left to the library, which
/// rejects them deterministically.
fn validate_transaction_payload_header(body: &[u8]) -> io::Result<()> {
    const UNSUPPORTED: &str = "unsupported transaction payload compression algorithm";
    const SHORT: &str = "truncated transaction payload header";
    let mut pos = 0usize;
    while pos < body.len() {
        let Some(field_type) = read_strict_lenenc(body, &mut pos) else {
            // The library reports invalid prefixes and short fields itself.
            return Ok(());
        };
        if field_type > u64::from(u8::MAX) {
            // The library's unknown-field error cannot represent this value
            // and panics while constructing it.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown transaction payload header field",
            ));
        }
        match field_type {
            // End of header; the remaining payload is only consumed in place.
            0 => return Ok(()),
            1..=3 => {
                // The declared field length is read but ignored by the
                // library, which parses the value immediately after it.
                let (Some(_), Some(value)) = (
                    read_strict_lenenc(body, &mut pos),
                    read_strict_lenenc(body, &mut pos),
                ) else {
                    return Ok(());
                };
                if field_type == 2 && (value > u64::from(u8::MAX) || (value != 0 && value != 255)) {
                    // The library unwraps this conversion; only ZSTD (0) and
                    // NONE (255) exist.
                    return Err(io::Error::new(io::ErrorKind::InvalidData, UNSUPPORTED));
                }
            }
            _ => {
                // Unknown field: the library reads a length-encoded length
                // through its lenient in-place reader, which panics past the
                // end of the buffer, then skips that many bytes, which also
                // panics if the length exceeds the remaining bytes.
                let Some(&first) = body.get(pos) else {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, SHORT));
                };
                pos += 1;
                let length = match first {
                    x @ 0..=0xfa => u64::from(x),
                    0xfc => {
                        let Some(raw) = body.get(pos..pos + 2) else {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, SHORT));
                        };
                        pos += 2;
                        u64::from(u16::from_le_bytes(raw.try_into().unwrap()))
                    }
                    0xfd => {
                        let Some(raw) = body.get(pos..pos + 3) else {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, SHORT));
                        };
                        pos += 3;
                        u64::from(u32::from_le_bytes([raw[0], raw[1], raw[2], 0]))
                    }
                    0xfe => {
                        let Some(raw) = body.get(pos..pos + 8) else {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, SHORT));
                        };
                        pos += 8;
                        u64::from_le_bytes(raw.try_into().unwrap())
                    }
                    // The library decodes the non-canonical prefixes to zero.
                    _ => 0,
                };
                if length > (body.len() - pos) as u64 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, SHORT));
                }
                pos += length as usize;
            }
        }
    }
    Ok(())
}

/// Reads a MySQL length-encoded integer the way the library's strict
/// `read_lenenc_int` does: the non-canonical `0xfb`/`0xff` prefixes and a
/// truncated field are errors, signaled here as `None` so the caller can leave
/// the rejection to the library, whose error is identical.
fn read_strict_lenenc(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *buf.get(*pos)?;
    *pos += 1;
    let extra = match first {
        x if x <= 0xfa => return Some(u64::from(x)),
        0xfc => 2,
        0xfd => 3,
        0xfe => 8,
        // Invalid length-encoded integer prefix.
        _ => return None,
    };
    let raw = buf.get(*pos..*pos + extra)?;
    *pos += extra;
    let mut bytes = [0u8; 8];
    bytes[..extra].copy_from_slice(raw);
    Some(u64::from_le_bytes(bytes))
}

/// CRC-32 (IEEE 802.3, reflected) used for binlog event checksums.
struct Crc32 {
    state: u32,
}

impl Crc32 {
    fn new() -> Self {
        Self { state: !0 }
    }

    fn update(&mut self, data: &[u8]) {
        for &byte in data {
            let index = ((self.state ^ u32::from(byte)) & 0xff) as usize;
            self.state = CRC32_TABLE[index] ^ (self.state >> 8);
        }
    }

    fn finalize(self) -> u32 {
        !self.state
    }
}

/// Lookup table for [`Crc32`], built at compile time.
const CRC32_TABLE: [u32; 256] = {
    const fn build() -> [u32; 256] {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut value = i as u32;
            let mut bit = 0;
            while bit < 8 {
                value = if value & 1 != 0 {
                    0xedb88320 ^ (value >> 1)
                } else {
                    value >> 1
                };
                bit += 1;
            }
            table[i] = value;
            i += 1;
        }
        table
    }
    build()
};

/// Verifies the CRC32 checksum of an event directly on its raw bytes.
///
/// This mirrors the library's `Event::calc_checksum` (header with the
/// "binlog in use" flag cleared, then the body). It is needed when a table
/// map event body is modified by stripping before the library parses it: the
/// library's own verification would then hash the modified bytes against the
/// original checksum. A mismatch is framed as [`FrameError::Checksum`] so it
/// surfaces as the structured [`ParserError::Checksum`] variant (R45).
fn verify_event_checksum(buffer: &[u8]) -> Result<(), FrameError> {
    // `EventFlags::LOG_EVENT_BINLOG_IN_USE_F` (0x0001) is cleared before the
    // checksum is computed, both by the server when writing and by the
    // library when verifying.
    const BINLOG_IN_USE_FLAG: u16 = 0x0001;
    let Some(body_len) = buffer.len().checked_sub(4) else {
        return Err(FrameError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "short checksummed event",
        )));
    };
    let mut header = [0u8; 19];
    header.copy_from_slice(&buffer[..19]);
    let mut flags = u16::from_le_bytes([header[17], header[18]]);
    if flags & BINLOG_IN_USE_FLAG != 0 {
        flags &= !BINLOG_IN_USE_FLAG;
        header[17..19].copy_from_slice(&flags.to_le_bytes());
    }
    let mut crc = Crc32::new();
    crc.update(&header);
    crc.update(&buffer[19..body_len]);
    let recorded = u32::from_le_bytes(buffer[body_len..].try_into().unwrap());
    if crc.finalize() != recorded {
        return Err(FrameError::Checksum);
    }
    Ok(())
}

/// Removes the given byte ranges (relative to `base`) from `buffer` in place,
/// returning the number of bytes removed. Ranges must be ascending and
/// non-overlapping, which the TLV scan guarantees.
fn remove_ranges(buffer: &mut Vec<u8>, base: usize, ranges: &[std::ops::Range<usize>]) -> usize {
    let mut removed = 0;
    let mut read = base;
    let mut write = base;
    for range in ranges {
        let start = base + range.start;
        let end = base + range.end;
        buffer.copy_within(read..start, write);
        write += start - read;
        read = end;
        removed += end - start;
    }
    buffer.copy_within(read.., write);
    buffer.truncate(buffer.len() - removed);
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_parser_errors_keep_their_display_strings() {
        // R45: the structured variants carry the offset (and size/limit) as
        // fields while their Display strings stay identical to the messages
        // the paths emitted before the variants existed.
        assert_eq!(
            ParserError::Checksum { offset: 125 }.to_string(),
            "binlog error at offset 125: event checksum mismatch"
        );
        assert_eq!(
            ParserError::Truncated { offset: 4 }.to_string(),
            "binlog error at offset 4: failed to fill whole buffer"
        );
        assert_eq!(
            ParserError::OversizedEvent {
                offset: 31,
                size: 0,
                limit: MAX_EVENT_SIZE
            }
            .to_string(),
            "binlog error at offset 31: invalid or oversized event"
        );
        assert_eq!(
            FrameError::Checksum.into_parser_error(125).to_string(),
            ParserError::Checksum { offset: 125 }.to_string()
        );
        assert_eq!(
            truncated_or_io(io::Error::new(io::ErrorKind::UnexpectedEof, "ignored"))
                .into_parser_error(4)
                .to_string(),
            ParserError::Truncated { offset: 4 }.to_string()
        );
        // A non-EOF failure while filling the buffer stays a plain I/O error.
        let interrupted = io::Error::new(io::ErrorKind::Interrupted, "retry");
        assert!(matches!(truncated_or_io(interrupted), FrameError::Io(_)));
    }

    #[test]
    fn intvar_and_incident_type_names_are_pinned() {
        // R51: the intvar and incident type names are pinned constants, not
        // the library's Debug rendering, so a library rename cannot change
        // the output.
        assert_eq!(
            intvar_type_name(IntvarEventType::INVALID_INT_EVENT),
            "INVALID_INT_EVENT"
        );
        assert_eq!(
            intvar_type_name(IntvarEventType::LAST_INSERT_ID_EVENT),
            "LAST_INSERT_ID_EVENT"
        );
        assert_eq!(
            intvar_type_name(IntvarEventType::INSERT_ID_EVENT),
            "INSERT_ID_EVENT"
        );
        assert_eq!(
            incident_type_name(IncidentType::INCIDENT_NONE),
            "INCIDENT_NONE"
        );
        assert_eq!(
            incident_type_name(IncidentType::INCIDENT_LOST_EVENTS),
            "INCIDENT_LOST_EVENTS"
        );
    }

    #[test]
    fn server_version_stops_at_first_nul() {
        let mut raw = vec![b'8', b'.', b'0', b'.', b'3', b'0'];
        raw.resize(50, 0);
        assert_eq!(server_version(&raw), "8.0.30");
        assert_eq!(server_version(&[0; 50]), "");
    }

    #[test]
    fn sid_is_rendered_hyphenated() {
        let sid = [
            0x55, 0x77, 0x89, 0x04, 0x02, 0x99, 0x11, 0xf1, 0xb1, 0xb8, 0x4e, 0xf0, 0xc4, 0x95,
            0x6f, 0xeb,
        ];
        assert_eq!(format_sid(&sid), "55778904-0299-11f1-b1b8-4ef0c4956feb");
    }

    #[test]
    fn oversized_previous_gtids_are_rejected() {
        // Untagged header declaring more SIDs than the body can hold.
        let mut body = 8u64.to_le_bytes().to_vec();
        body[0] = 0x01;
        assert!(validate_previous_gtids(&body).is_err());
        // Tagged header (format byte in the top bits) with the same abuse.
        let header = (1u64 << 56) | (1 << 8) | 1;
        let mut body = header.to_le_bytes().to_vec();
        body.extend_from_slice(&[0u8; 23]);
        assert!(validate_previous_gtids(&body).is_err());
        // A single SID with an inflated interval count is also rejected.
        let mut body = 1u64.to_le_bytes().to_vec();
        body.extend_from_slice(&[0u8; 16]); // UUID
        body.extend_from_slice(&1_000_000u64.to_le_bytes()); // n_intervals
        assert!(validate_previous_gtids(&body).is_err());
    }

    #[test]
    fn well_formed_previous_gtids_is_accepted() {
        // One untagged SID with interval [1, 3).
        let mut body = 1u64.to_le_bytes().to_vec();
        body.extend_from_slice(&[0x55; 16]);
        body.extend_from_slice(&1u64.to_le_bytes());
        body.extend_from_slice(&1u64.to_le_bytes());
        body.extend_from_slice(&3u64.to_le_bytes());
        validate_previous_gtids(&body).unwrap();
    }

    #[test]
    fn degenerate_previous_gtids_intervals_are_rejected() {
        let interval = |start: u64, end: u64| {
            let mut body = 1u64.to_le_bytes().to_vec();
            body.extend_from_slice(&[0x55; 16]);
            body.extend_from_slice(&1u64.to_le_bytes()); // n_intervals
            body.extend_from_slice(&start.to_le_bytes());
            body.extend_from_slice(&end.to_le_bytes());
            body
        };
        // GNOs start at one; an interval starting at zero is malformed.
        let err = validate_previous_gtids(&interval(0, 0)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // Empty and reversed intervals would break the inclusive renderer.
        for (start, end) in [(5, 5), (10, 4), (u64::MAX, u64::MAX)] {
            let err = validate_previous_gtids(&interval(start, end)).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
        // The largest well-formed single-GNO interval is accepted.
        validate_previous_gtids(&interval(1, u64::MAX)).unwrap();
        validate_previous_gtids(&interval(u64::MAX - 1, u64::MAX)).unwrap();
    }

    /// Writes a MySQL length-encoded integer like the library does.
    fn put_lenenc(out: &mut Vec<u8>, value: u64) {
        if value < 251 {
            out.push(value as u8);
        } else if value < 65536 {
            out.push(0xfc);
            out.extend_from_slice(&(value as u16).to_le_bytes());
        } else if value < 1 << 24 {
            out.push(0xfd);
            out.extend_from_slice(&(value as u32).to_le_bytes()[..3]);
        } else {
            out.push(0xfe);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }

    /// Appends a header field: type, declared length, value.
    fn tlv(field: u64, value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        put_lenenc(&mut out, field);
        put_lenenc(&mut out, 1);
        put_lenenc(&mut out, value);
        out
    }

    fn payload_header(algorithm: u64) -> Vec<u8> {
        let mut body = tlv(2, algorithm);
        body.extend(tlv(1, 0));
        body.push(0); // end mark
        body
    }

    #[test]
    fn well_formed_payload_header_is_accepted() {
        for algorithm in [0u64, 255] {
            validate_transaction_payload_header(&payload_header(algorithm)).unwrap();
        }
    }

    #[test]
    fn unknown_payload_algorithm_is_rejected() {
        for algorithm in [1u64, 7, 254, 256, u64::MAX] {
            let err = validate_transaction_payload_header(&payload_header(algorithm)).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(err.to_string().contains("compression algorithm"));
        }
    }

    #[test]
    fn payload_field_type_above_u8_is_rejected() {
        // A field type encoded with the 8-byte prefix panics the library's
        // error construction and must be rejected here.
        let mut body = vec![0xfe];
        body.extend_from_slice(&5_000_000u64.to_le_bytes());
        let err = validate_transaction_payload_header(&body).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn payload_unknown_field_skip_overflow_is_rejected() {
        // An unknown field declaring a 65535-byte skip in a tiny body would
        // panic the library's in-place skip.
        let mut body = vec![5, 0xfc];
        body.extend_from_slice(&65535u16.to_le_bytes());
        let err = validate_transaction_payload_header(&body).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // A skip that fits is accepted.
        let body = vec![5, 3, 1, 2, 3, 0];
        validate_transaction_payload_header(&body).unwrap();
    }

    #[test]
    fn truncated_payload_header_walks_without_panic() {
        // Truncations on strictly parsed fields are left to the library,
        // which rejects them deterministically.
        for body in [
            vec![2],          // compression field without length and value
            vec![2, 1],       // length without value
            vec![2, 1, 0xfc], // truncated 2-byte value
            vec![1, 1, 0],    // payload size without end mark
            vec![0xfc],       // invalid prefix in the type position
        ] {
            validate_transaction_payload_header(&body).unwrap();
        }
    }

    /// An inner XID event: 19-byte header plus the 8-byte transaction id.
    fn inner_xid(xid: u64) -> Vec<u8> {
        let mut event = Vec::new();
        event.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        event.push(16); // XID_EVENT
        event.extend_from_slice(&7u32.to_le_bytes()); // server id
        event.extend_from_slice(&27u32.to_le_bytes()); // event size
        event.extend_from_slice(&27u32.to_le_bytes()); // log pos
        event.extend_from_slice(&0u16.to_le_bytes()); // flags
        event.extend_from_slice(&xid.to_le_bytes());
        event
    }

    #[test]
    fn payload_stream_frames_inner_events_with_offsets() {
        use mysql_common::binlog::events::EventData;
        let mut bytes = inner_xid(11);
        bytes.extend(inner_xid(22));
        let reader = TransactionPayloadReader::new_uncompressed(&bytes);
        let mut stream = PayloadStream::new(reader, 1 << 20, u64::from(MAX_EVENT_SIZE), 0);
        let mut parser_events = EventStreamReader::new(BinlogVersion::Version4);
        let first = parser_events
            .read_decompressed(&mut stream)
            .unwrap()
            .unwrap();
        assert_eq!(stream.last_event_offset(), 0);
        assert_eq!(first.header().event_type_raw(), 16);
        assert!(matches!(
            first.read_data().unwrap(),
            Some(EventData::XidEvent(e)) if e.xid == 11
        ));
        let second = parser_events
            .read_decompressed(&mut stream)
            .unwrap()
            .unwrap();
        assert_eq!(stream.last_event_offset(), 27);
        assert!(matches!(
            second.read_data().unwrap(),
            Some(EventData::XidEvent(e)) if e.xid == 22
        ));
        assert!(
            parser_events
                .read_decompressed(&mut stream)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn payload_stream_enforces_declared_size() {
        // Two inner events total 54 bytes; a limit just below rejects the
        // second one before it is handed to the library.
        let mut bytes = inner_xid(11);
        bytes.extend(inner_xid(22));
        let reader = TransactionPayloadReader::new_uncompressed(&bytes);
        let mut stream = PayloadStream::new(reader, 40, u64::from(MAX_EVENT_SIZE), 0);
        let mut parser_events = EventStreamReader::new(BinlogVersion::Version4);
        assert!(
            parser_events
                .read_decompressed(&mut stream)
                .unwrap()
                .is_some()
        );
        let err = parser_events.read_decompressed(&mut stream).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("declared size"));
    }

    #[test]
    fn payload_stream_rejects_truncation_and_nested_payload() {
        // A truncated inner event body is a clean error, not EOF.
        let mut bytes = inner_xid(11);
        bytes.truncate(bytes.len() - 2);
        let reader = TransactionPayloadReader::new_uncompressed(&bytes);
        let mut stream = PayloadStream::new(reader, 1 << 20, u64::from(MAX_EVENT_SIZE), 0);
        let mut parser_events = EventStreamReader::new(BinlogVersion::Version4);
        let err = parser_events.read_decompressed(&mut stream).unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");

        // A nested transaction payload event is rejected before the library
        // would see it.
        let mut nested = Vec::new();
        nested.extend_from_slice(&0u32.to_le_bytes());
        nested.push(40);
        nested.extend_from_slice(&7u32.to_le_bytes());
        nested.extend_from_slice(&39u32.to_le_bytes());
        nested.extend_from_slice(&39u32.to_le_bytes());
        nested.extend_from_slice(&0u16.to_le_bytes());
        nested.extend_from_slice(&[2, 1, 0, 0]);
        let mut bytes = inner_xid(11);
        bytes.extend(nested);
        let reader = TransactionPayloadReader::new_uncompressed(&bytes);
        let mut stream = PayloadStream::new(reader, 1 << 20, u64::from(MAX_EVENT_SIZE), 0);
        let mut parser_events = EventStreamReader::new(BinlogVersion::Version4);
        assert!(
            parser_events
                .read_decompressed(&mut stream)
                .unwrap()
                .is_some()
        );
        let err = parser_events.read_decompressed(&mut stream).unwrap_err();
        assert!(err.to_string().contains("nested"), "{err}");
    }
}
