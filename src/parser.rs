// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Stateful, streaming MySQL binlog reader.
use crate::event::{EventPayload, EventType, ParsedEvent, RowChange};
use mysql_common::binlog::{
    EventStreamReader,
    consts::{BinlogChecksumAlg, BinlogVersion, TransactionPayloadCompressionType},
    events::{Event, EventData, PreviousGtidsEvent, RowsEventData, TransactionPayloadReader},
};
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Cursor, Read},
    path::Path,
};

/// Upper bound on the accepted size of a single event, including its header.
pub const MAX_EVENT_SIZE: u32 = 64 * 1024 * 1024;

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
#[derive(Debug, thiserror::Error)]
pub enum ParserError {
    /// Encrypted MySQL binlogs must be read through the server.
    #[error(
        "encrypted binlog detected; use mysqlbinlog --read-from-remote-server against the MySQL server"
    )]
    EncryptedBinlog,
    /// The input does not have the plaintext MySQL binlog magic.
    #[error("invalid or truncated binlog file header")]
    InvalidHeader,
    /// An input or event decoding failure.
    #[error("binlog error at offset {offset}: {source}")]
    Io {
        /// File offset at which the failure was detected.
        offset: u64,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
}

/// Maintains the format description and table maps while reading one event at a time.
///
/// The reader works on any [`Read`] input (a file, standard input, or an
/// in-memory buffer) and bounds its own memory use per event: no allocation
/// may exceed [`MAX_EVENT_SIZE`] unless a larger cap is requested explicitly
/// through [`BinlogParser::with_max_event_size`].
pub struct BinlogParser<R: Read = File> {
    reader: EventStreamReader,
    input: BufReader<R>,
    offset: u64,
    stopped: bool,
    buffer: Vec<u8>,
    max_event_size: u32,
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
        })
    }

    /// Overrides the per-event size cap (defaulting to [`MAX_EVENT_SIZE`]).
    pub fn with_max_event_size(mut self, cap: u32) -> Self {
        self.max_event_size = cap;
        self
    }

    /// Iterate over events; a framing or decoding error terminates the stream.
    pub fn events(&mut self) -> impl Iterator<Item = Result<ParsedEvent, ParserError>> + '_ {
        std::iter::from_fn(move || self.next_event())
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
        let result = (|| -> io::Result<Option<ParsedEvent>> {
            // Validate framing before allowing the library to allocate the event buffer.
            let mut head = [0u8; 19];
            let first = self.input.read(&mut head[..1])?;
            if first == 0 {
                return Ok(None);
            }
            self.input.read_exact(&mut head[1..])?;
            let size = u32::from_le_bytes(head[9..13].try_into().unwrap());
            if !(19..=self.max_event_size).contains(&size) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid or oversized event",
                ));
            }
            // mysql_common assumes the complete event body is available.
            if head[4] == 15 && size < 19 + 57 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short format description",
                ));
            }
            if head[4] != 15 && self.checksum_len(head[4]) > 0 && size < 23 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short checksummed event",
                ));
            }
            // Resizing without clearing only zero-fills the newly observed
            // tail; every byte is overwritten by the head and body anyway.
            self.buffer.resize(size as usize, 0);
            self.buffer[..19].copy_from_slice(&head);
            self.input.read_exact(&mut self.buffer[19..])?;
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
            let Some(event) = self.reader.read(&mut Cursor::new(self.buffer.as_slice()))? else {
                return Ok(None);
            };
            let checksum_algorithm = event
                .footer()
                .get_checksum_alg()
                .map_err(|err| io::Error::new(io::ErrorKind::Unsupported, err))?;
            if let (Some(checksum), Some(alg)) = (event.checksum(), checksum_algorithm)
                && u32::from_le_bytes(checksum) != event.calc_checksum(alg)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "event checksum mismatch",
                ));
            }
            let h = event.header();
            self.offset += u64::from(h.event_size());
            let raw = h.event_type_raw();
            let event_type = EventType::from_raw(raw);
            // The mapping is shared with the events decompressed out of a
            // transaction payload; code 40 itself takes its own path below.
            let payload = if raw == 40 {
                self.transaction_payload(&event)?
            } else {
                self.payload_for(&event)?
            };
            Ok(Some(ParsedEvent {
                offset,
                timestamp: h.timestamp(),
                event_type,
                event_type_code: raw,
                server_id: h.server_id(),
                event_size: h.event_size(),
                log_pos: h.log_pos(),
                payload,
            }))
        })();
        match result {
            Ok(Some(e)) => Some(Ok(e)),
            Ok(None) => {
                self.stopped = true;
                None
            }
            Err(source) => {
                self.stopped = true;
                Some(Err(ParserError::Io { offset, source }))
            }
        }
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
            Some(EventData::TableMapEvent(e)) => EventPayload::TableMap {
                table_id: e.table_id(),
                database: e.database_name().into_owned(),
                table: e.table_name().into_owned(),
                column_count: e.columns_count(),
            },
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
                    Ok(incident_type) => format!("{incident_type:?}"),
                    Err(unknown) => format!("UNKNOWN({})", u16::from(unknown)),
                },
                message: e.message().into_owned(),
            },
            Some(EventData::IntvarEvent(e)) => EventPayload::Intvar {
                var_type: format!("{:?}", e.subtype()),
                value: e.value(),
            },
            Some(EventData::RowsEvent(RowsEventData::PartialUpdateRowsEvent(e))) => {
                // Partial update rows (WL#2955): the before image is a full
                // row image, the after image is a JSON diff. The JSON-diff
                // after-image decode is intentionally never invoked; only
                // the before image is surfaced.
                let id = e.table_id();
                match self.reader.get_tme(id) {
                    Some(map) => {
                        if e.num_columns() != map.columns_count() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "row event column count does not match table map",
                            ));
                        }
                        let n = usize::try_from(map.columns_count()).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "column count overflow")
                        })?;
                        let before_bitmap = Some(e.columns_before_image())
                            .map(|bits| crate::row_decode::present_bits(bits.iter().by_vals(), n))
                            .transpose()?;
                        let signedness = crate::row_decode::signedness(map)?;
                        let mut before = Vec::new();
                        for row in e.rows(map) {
                            let (before_row, _json_diff_after) = row?;
                            before.push(
                                before_row
                                    .map(|r| {
                                        crate::row_decode::decode_row(
                                            &r,
                                            before_bitmap.as_deref().ok_or_else(|| {
                                                io::Error::new(
                                                    io::ErrorKind::InvalidData,
                                                    "missing before bitmap",
                                                )
                                            })?,
                                            &signedness,
                                        )
                                    })
                                    .transpose()?,
                            );
                        }
                        EventPayload::PartialUpdateRows {
                            table_id: id,
                            database: map.database_name().into_owned(),
                            table: map.table_name().into_owned(),
                            before,
                        }
                    }
                    None => EventPayload::Unresolved { table_id: id },
                }
            }
            Some(EventData::RowsEvent(e)) => {
                let id = e.table_id();
                if let Some(map) = self.reader.get_tme(id) {
                    if e.num_columns() != map.columns_count() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "row event column count does not match table map",
                        ));
                    }
                    let n = usize::try_from(map.columns_count()).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "column count overflow")
                    })?;
                    let before_bitmap = e
                        .columns_before_image()
                        .map(|bits| crate::row_decode::present_bits(bits.iter().by_vals(), n))
                        .transpose()?;
                    let after_bitmap = e
                        .columns_after_image()
                        .map(|bits| crate::row_decode::present_bits(bits.iter().by_vals(), n))
                        .transpose()?;
                    let signedness = crate::row_decode::signedness(map)?;
                    let mut changes = Vec::new();
                    for row in e.rows(map) {
                        let (before, after) = row?;
                        changes.push(RowChange {
                            before: before
                                .map(|r| {
                                    crate::row_decode::decode_row(
                                        &r,
                                        before_bitmap.as_deref().ok_or_else(|| {
                                            io::Error::new(
                                                io::ErrorKind::InvalidData,
                                                "missing before bitmap",
                                            )
                                        })?,
                                        &signedness,
                                    )
                                })
                                .transpose()?,
                            after: after
                                .map(|r| {
                                    crate::row_decode::decode_row(
                                        &r,
                                        after_bitmap.as_deref().ok_or_else(|| {
                                            io::Error::new(
                                                io::ErrorKind::InvalidData,
                                                "missing after bitmap",
                                            )
                                        })?,
                                        &signedness,
                                    )
                                })
                                .transpose()?,
                        });
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
    /// shared reader state so later outer row events resolve.
    fn transaction_payload(&mut self, event: &Event) -> io::Result<EventPayload> {
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
        // is the honest limit. Compressed payloads get the declared size plus
        // a small slack so a bomb must lie by more than the slack to pass.
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
        let timestamp = event.header().timestamp();
        let server_id = event.header().server_id();
        let mut events = Vec::new();
        while let Some(inner) = self.reader.read_decompressed(&mut stream)? {
            let offset = stream.last_event_offset();
            let h = inner.header();
            events.push(ParsedEvent {
                offset,
                timestamp,
                event_type: EventType::from_raw(h.event_type_raw()),
                event_type_code: h.event_type_raw(),
                server_id,
                event_size: h.event_size(),
                log_pos: h.log_pos(),
                payload: self.payload_for(&inner)?,
            });
        }
        Ok(EventPayload::TransactionPayload {
            compression: compression.to_owned(),
            uncompressed_size,
            events,
        })
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
        }
    }

    /// Byte offset within the decompressed stream of the most recently
    /// buffered inner event.
    fn last_event_offset(&self) -> u64 {
        self.event_start
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
        self.event_start = self.position;
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
        match reader.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// Renders the server version with any NUL padding removed.
fn server_version(raw: &[u8]) -> String {
    let end = raw.iter().position(|&byte| byte == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
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

#[cfg(test)]
mod tests {
    use super::*;

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
