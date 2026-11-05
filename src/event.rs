//! Stable output model, independent of the underlying binlog library.
use serde::{Deserialize, Serialize};

/// Canonical event type; the single source of truth for event naming.
///
/// The JSON output renders the snake_case variant name, which matches the
/// historical string values byte for byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub enum EventType {
    /// Layout description for the rest of the binlog file.
    FormatDescription,
    /// Table identifier and its schema.
    TableMap,
    /// Inserted row images.
    WriteRows,
    /// Updated row image pairs.
    UpdateRows,
    /// Deleted row images.
    DeleteRows,
    /// Partial update row events: only before images are full row images,
    /// after images are JSON diffs that are not decoded.
    PartialUpdateRows,
    /// Statement event.
    Query,
    /// Transaction commit identifier.
    Xid,
    /// Global transaction identifier (tagged or untagged).
    Gtid,
    /// Global transaction identifier of an anonymous transaction.
    AnonymousGtid,
    /// GTID set committed before the current binlog file.
    PreviousGtids,
    /// Log rotation.
    Rotate,
    /// Server shutdown marker.
    Stop,
    /// Original statement for row events.
    RowsQuery,
    /// Replication incident report.
    Incident,
    /// Statement-time integer variable assignment.
    Intvar,
    /// Random seed used by statement-based replication.
    Rand,
    /// User-defined variable assignment.
    UserVar,
    /// Bulk load data carried outside the statement stream.
    BeginLoadQuery,
    /// Bulk load execution marker.
    ExecuteLoadQuery,
    /// Replication heartbeat.
    Heartbeat,
    /// Event that may be safely ignored by readers that do not handle it.
    Ignorable,
    /// Two-phase commit transaction context.
    TransactionContext,
    /// Group replication view change.
    ViewChange,
    /// XA transaction prepare.
    XaPrepare,
    /// Compressed transaction payload (WL#3549) enclosing a whole transaction.
    TransactionPayload,
    /// Event type that this version does not name.
    Unknown,
}

impl EventType {
    /// The snake_case name used in JSON output; identical to the serde
    /// rendering of this variant.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FormatDescription => "format_description",
            Self::TableMap => "table_map",
            Self::WriteRows => "write_rows",
            Self::UpdateRows => "update_rows",
            Self::DeleteRows => "delete_rows",
            Self::PartialUpdateRows => "partial_update_rows",
            Self::Query => "query",
            Self::Xid => "xid",
            Self::Gtid => "gtid",
            Self::AnonymousGtid => "anonymous_gtid",
            Self::PreviousGtids => "previous_gtids",
            Self::Rotate => "rotate",
            Self::Stop => "stop",
            Self::RowsQuery => "rows_query",
            Self::Incident => "incident",
            Self::Intvar => "intvar",
            Self::Rand => "rand",
            Self::UserVar => "user_var",
            Self::BeginLoadQuery => "begin_load_query",
            Self::ExecuteLoadQuery => "execute_load_query",
            Self::Heartbeat => "heartbeat",
            Self::Ignorable => "ignorable",
            Self::TransactionContext => "transaction_context",
            Self::ViewChange => "view_change",
            Self::XaPrepare => "xa_prepare",
            Self::TransactionPayload => "transaction_payload",
            Self::Unknown => "unknown",
        }
    }

    /// Maps a raw binlog event type number to the canonical event type.
    ///
    /// Pre-GA row events (codes 23-25) and MariaDB-only codes (160+) have no
    /// stable cross-server meaning and are reported as [`EventType::Unknown`].
    pub fn from_raw(code: u8) -> Self {
        match code {
            2 => Self::Query,
            3 => Self::Stop,
            4 => Self::Rotate,
            5 => Self::Intvar,
            13 => Self::Rand,
            14 => Self::UserVar,
            15 => Self::FormatDescription,
            16 => Self::Xid,
            17 => Self::BeginLoadQuery,
            18 => Self::ExecuteLoadQuery,
            19 => Self::TableMap,
            26 => Self::Incident,
            27 | 41 => Self::Heartbeat,
            28 => Self::Ignorable,
            29 => Self::RowsQuery,
            30 => Self::WriteRows,
            31 => Self::UpdateRows,
            32 => Self::DeleteRows,
            33 | 42 => Self::Gtid,
            34 => Self::AnonymousGtid,
            35 => Self::PreviousGtids,
            36 => Self::TransactionContext,
            37 => Self::ViewChange,
            38 => Self::XaPrepare,
            39 => Self::PartialUpdateRows,
            40 => Self::TransactionPayload,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An event and its byte offset in the input file.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ParsedEvent {
    /// File offset of the event header.
    pub offset: u64,
    /// Unix timestamp in seconds.
    pub timestamp: u32,
    /// Canonical event type.
    pub event_type: EventType,
    /// Raw MySQL event type number.
    pub event_type_code: u8,
    /// Originating server ID.
    pub server_id: u32,
    /// Event size including header.
    pub event_size: u32,
    /// Position of the next event recorded in the header.
    pub log_pos: u32,
    /// Decoded event content.
    pub payload: EventPayload,
}

/// Event-specific content.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventPayload {
    /// Format description.
    FormatDescription {
        /// Server version with NUL padding removed.
        server_version: String,
    },
    /// Table identifier and its schema.
    TableMap {
        /// Table identifier used by following row events.
        table_id: u64,
        /// Database containing the table.
        database: String,
        /// Table name.
        table: String,
        /// Number of columns in the table.
        column_count: u64,
    },
    /// Row images with typed column values.
    Rows {
        /// Table identifier from the preceding table map event.
        table_id: u64,
        /// Database containing the table.
        database: String,
        /// Table name.
        table: String,
        /// One entry per affected row.
        changes: Vec<RowChange>,
    },
    /// Partial update row event (WL#2955).
    ///
    /// Only the before image is decoded: it is a full row image. The after
    /// image is a JSON diff that is intentionally left undecoded.
    PartialUpdateRows {
        /// Table identifier from the preceding table map event.
        table_id: u64,
        /// Database containing the table.
        database: String,
        /// Table name.
        table: String,
        /// Full before image per affected row; `None` when the image is absent.
        before: Vec<Option<RowImage>>,
    },
    /// A row event whose table map was not available.
    Unresolved {
        /// Table identifier that had no table map event.
        table_id: u64,
    },
    /// Statement event.
    Query {
        /// Default database of the statement.
        database: String,
        /// Statement text.
        sql: String,
    },
    /// Transaction commit identifier.
    Xid {
        /// Transaction ID.
        xid: u64,
    },
    /// Global transaction identifier.
    Gtid {
        /// Canonical GTID: `uuid:gno` when untagged, `uuid:tag:gno` when
        /// tagged; `ANONYMOUS` for anonymous transactions.
        gtid: String,
        /// GTID tag (MySQL 8.4+), if present.
        tag: Option<String>,
    },
    /// GTID set committed before the current binlog file, rendered in the
    /// mysqlbinlog textual form (`uuid[:tag]:interval[,...]`, sids separated
    /// by commas).
    PreviousGtids {
        /// Rendered GTID set.
        gtid_set: String,
    },
    /// Log rotation.
    Rotate {
        /// Name of the next binlog file.
        next_file: String,
        /// Start position in the next file.
        position: u64,
    },
    /// Server shutdown marker.
    Stop,
    /// Original statement for row events.
    RowsQuery {
        /// Statement text.
        sql: String,
    },
    /// Replication incident report.
    Incident {
        /// Canonical incident type name, or `UNKNOWN(n)` for unrecognized codes.
        incident_type: String,
        /// Human-readable incident description.
        message: String,
    },
    /// Statement-time integer variable assignment.
    Intvar {
        /// Variable kind, using the library's stable constant names
        /// (`INVALID_INT_EVENT`, `LAST_INSERT_ID_EVENT`, `INSERT_ID_EVENT`).
        var_type: String,
        /// Assigned value.
        value: u64,
    },
    /// Unhandled event, retained with its type and size.
    Unknown {
        /// Length of the retained event data.
        raw_len: usize,
    },
    /// A compressed transaction payload (code 40, WL#3549) and its decoded
    /// inner events.
    ///
    /// The compression algorithm byte is validated before the underlying
    /// library parses the header, the payload is only ever streamed through a
    /// counting decompression reader bounded by the declared size, and inner
    /// events share the parser's table map state with the outer stream.
    TransactionPayload {
        /// Canonical compression name: `"NONE"` or `"ZSTD"`.
        compression: String,
        /// Declared uncompressed size from the payload header.
        uncompressed_size: u64,
        /// Inner events in stream order; the `offset` of each inner event is
        /// its byte position inside the decompressed payload, while
        /// `timestamp` and `server_id` are inherited from the enclosing event.
        events: Vec<ParsedEvent>,
    },
}

/// Before and after images for a single row.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RowChange {
    /// Previous image, if present.
    pub before: Option<RowImage>,
    /// New image, if present.
    pub after: Option<RowImage>,
}

/// A row image in table-column order, including columns omitted by minimal row images.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RowImage {
    /// Cells are in zero-based table-column order.
    pub columns: Vec<ColumnValue>,
}

/// One table column in a row image.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ColumnValue {
    /// Zero-based position in the table.
    pub index: usize,
    /// Column name when present in binlog metadata; otherwise a generated name.
    pub name: Option<String>,
    /// MySQL column type, if this column is present in the row image.
    pub mysql_type: Option<String>,
    /// Signedness metadata for numeric columns; unknown if the binlog omitted it.
    pub signedness: Option<Signedness>,
    /// Value, including explicit absent and SQL NULL states.
    pub value: CellValue,
}

/// Loss-aware MySQL value representation.
///
/// When deserializing, [`CellValue::Bytes`] expects the lowercase hexadecimal
/// encoding produced by serialization; no character decoding is performed.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum CellValue {
    /// Column omitted from this image.
    Absent,
    /// SQL NULL.
    Null,
    /// Bytes encoded as lowercase hexadecimal; no character encoding is assumed.
    Bytes(String),
    /// Signed integer.
    Int(i64),
    /// Unsigned integer.
    UInt(u64),
    /// Single-precision value, rendered as a string to preserve non-finite values.
    Float(String),
    /// Double-precision value, rendered as a string to preserve non-finite values.
    Double(String),
    /// Date or datetime components, including zero dates.
    Date {
        /// Gregorian year.
        year: u16,
        /// Month of the year (1-12).
        month: u8,
        /// Day of the month (1-31).
        day: u8,
        /// Hour of the day (0-23).
        hour: u8,
        /// Minute of the hour (0-59).
        minute: u8,
        /// Second of the minute (0-59).
        second: u8,
        /// Microsecond component.
        micros: u32,
    },
    /// Signed MySQL TIME components, including values greater than 24 hours.
    Time {
        /// Whether the value is negative.
        negative: bool,
        /// Whole days beyond the hour component.
        days: u32,
        /// Remaining hours (0-23).
        hours: u8,
        /// Remaining minutes (0-59).
        minutes: u8,
        /// Remaining seconds (0-59).
        seconds: u8,
        /// Microsecond component.
        micros: u32,
    },
    /// Decoded full JSON value.
    Json(serde_json::Value),
}

/// Signedness carried by the table map, or unknown when metadata was omitted.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signedness {
    /// A signed numeric column.
    Signed,
    /// An unsigned numeric column.
    Unsigned,
    /// Decoded using the library's signed default; schema is required to interpret it.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_matches_serde_snake_case() {
        let codes = [
            0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 100,
            160, 255,
        ];
        for code in codes {
            let event_type = EventType::from_raw(code);
            let json = serde_json::to_string(&event_type).unwrap();
            assert_eq!(
                json.trim_matches('"'),
                event_type.as_str(),
                "serde and as_str disagree for code {code}"
            );
        }
    }

    #[test]
    fn raw_code_table_matches_contract() {
        let expected = [
            (2u8, "query"),
            (3, "stop"),
            (4, "rotate"),
            (5, "intvar"),
            (13, "rand"),
            (14, "user_var"),
            (15, "format_description"),
            (16, "xid"),
            (17, "begin_load_query"),
            (18, "execute_load_query"),
            (19, "table_map"),
            (26, "incident"),
            (27, "heartbeat"),
            (28, "ignorable"),
            (29, "rows_query"),
            (30, "write_rows"),
            (31, "update_rows"),
            (32, "delete_rows"),
            (33, "gtid"),
            (34, "anonymous_gtid"),
            (35, "previous_gtids"),
            (36, "transaction_context"),
            (37, "view_change"),
            (38, "xa_prepare"),
            (39, "partial_update_rows"),
            (40, "transaction_payload"),
            (41, "heartbeat"),
            (42, "gtid"),
        ];
        for (code, name) in expected {
            assert_eq!(EventType::from_raw(code).as_str(), name, "code {code}");
        }
        for code in [
            0u8, 1, 6, 7, 8, 9, 10, 11, 12, 20, 21, 22, 23, 24, 25, 43, 160, 255,
        ] {
            assert_eq!(EventType::from_raw(code), EventType::Unknown, "code {code}");
        }
    }
}
