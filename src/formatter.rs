// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Output formatters that operate on the independent event model.
use crate::event::{EventPayload, ParsedEvent};
use std::io::Write;
/// Failures while writing formatted events.
///
/// This enum is `#[non_exhaustive]` (R45): downstream matches require a
/// wildcard arm, so new variants can be added without a semver-major
/// release.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FormatterError {
    /// JSON encoding of an event or payload failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// The underlying writer failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
/// Formatter for one decoded event.
///
/// Formatters own their trailing newlines so that the bytes written are
/// exactly the formatted output; the caller only selects the destination.
pub trait Formatter {
    /// Optional CSV header.
    fn header(&self) -> Option<&'static str> {
        None
    }
    /// Write the event; returns whether any output was produced.
    fn format(&mut self, event: &ParsedEvent, out: &mut dyn Write) -> Result<bool, FormatterError>;
}
/// One JSON value per event.
pub struct JsonLinesFormatter;
impl Formatter for JsonLinesFormatter {
    fn format(&mut self, e: &ParsedEvent, out: &mut dyn Write) -> Result<bool, FormatterError> {
        // Serialize straight into the writer; no intermediate String per event.
        serde_json::to_writer(&mut *out, e)?;
        out.write_all(b"\n")?;
        Ok(true)
    }
}
/// Human-readable event summaries.
pub struct TextFormatter;
impl Formatter for TextFormatter {
    fn format(&mut self, e: &ParsedEvent, out: &mut dyn Write) -> Result<bool, FormatterError> {
        write!(
            out,
            "{} {} server={} pos={} ",
            e.timestamp,
            e.event_type.as_str(),
            e.server_id,
            e.log_pos
        )?;
        serde_json::to_writer(&mut *out, &e.payload)?;
        out.write_all(b"\n")?;
        Ok(true)
    }
}
/// One CSV record per decoded row image.
pub struct CsvFormatter;

/// Reuse the escaped string for its enclosing quotes, avoiding a second
/// formatted String allocation for each field.
fn quote(text: &str) -> String {
    let mut quoted = text.replace('"', "\"\"");
    quoted.reserve(2);
    quoted.insert(0, '"');
    quoted.push('"');
    quoted
}
impl Formatter for CsvFormatter {
    fn header(&self) -> Option<&'static str> {
        Some("timestamp,event_type,database,table,before,after")
    }
    fn format(&mut self, e: &ParsedEvent, out: &mut dyn Write) -> Result<bool, FormatterError> {
        match &e.payload {
            EventPayload::Rows {
                database,
                table,
                changes,
                ..
            } => {
                let database = quote(database);
                let table = quote(table);
                for change in changes {
                    // EventType's fixed names never contain CSV delimiters.
                    writeln!(
                        out,
                        "{},\"{}\",{},{},{},{}",
                        e.timestamp,
                        e.event_type.as_str(),
                        database,
                        table,
                        quote(&serde_json::to_string(&change.before)?),
                        quote(&serde_json::to_string(&change.after)?)
                    )?;
                }
                Ok(!changes.is_empty())
            }
            // Partial update rows carry a full before image and a diff-applied
            // after image per row; both render like any other row-image pair,
            // an absent image as JSON `null`.
            EventPayload::PartialUpdateRows {
                database,
                table,
                before,
                after,
                ..
            } => {
                let database = quote(database);
                let table = quote(table);
                for (before_row, after_row) in before.iter().zip(after) {
                    writeln!(
                        out,
                        "{},\"{}\",{},{},{},{}",
                        e.timestamp,
                        e.event_type.as_str(),
                        database,
                        table,
                        quote(&serde_json::to_string(&before_row)?),
                        quote(&serde_json::to_string(&after_row)?)
                    )?;
                }
                Ok(!before.is_empty())
            }
            _ => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{CellValue, ColumnValue, EventPayload, EventType, RowChange, RowImage};

    fn write_rows_event(changes: Vec<RowChange>) -> ParsedEvent {
        ParsedEvent {
            offset: 100,
            timestamp: 7,
            event_type: EventType::WriteRows,
            event_type_code: 30,
            server_id: 1,
            event_size: 50,
            log_pos: 150,
            payload: EventPayload::Rows {
                table_id: 5,
                database: "db".to_owned(),
                table: "t".to_owned(),
                changes,
            },
        }
    }

    fn image(value: CellValue) -> RowImage {
        RowImage {
            columns: vec![ColumnValue {
                index: 0,
                name: None,
                mysql_type: Some("JSON".to_owned()),
                signedness: None,
                value,
            }],
        }
    }

    #[test]
    fn csv_writes_one_record_per_row_change_with_a_header() {
        let event = write_rows_event(vec![RowChange {
            before: None,
            after: Some(image(CellValue::Null)),
        }]);
        let mut formatter = CsvFormatter;
        let header = formatter.header().expect("csv has a header");
        let mut out = Vec::new();
        assert!(formatter.format(&event, &mut &mut out).unwrap());
        let csv = String::from_utf8(out).unwrap();
        assert_eq!(
            csv,
            "7,\"write_rows\",\"db\",\"t\",\"null\",\"{\"\"columns\"\":[{\"\"index\"\":0,\
             \"\"name\"\":null,\"\"mysql_type\"\":\"\"JSON\"\",\"\"signedness\"\":null,\
             \"\"value\"\":{\"\"type\"\":\"\"null\"\"}}]}\"\n"
        );
        assert_eq!(header, "timestamp,event_type,database,table,before,after");
    }

    #[test]
    fn csv_renders_partial_update_rows_as_row_pairs() {
        let event = ParsedEvent {
            offset: 200,
            timestamp: 9,
            event_type: EventType::PartialUpdateRows,
            event_type_code: 39,
            server_id: 1,
            event_size: 80,
            log_pos: 280,
            payload: EventPayload::PartialUpdateRows {
                table_id: 5,
                database: "db".to_owned(),
                table: "t".to_owned(),
                before: vec![
                    Some(image(CellValue::Json(serde_json::json!({"a": 1})))),
                    None,
                ],
                after: vec![
                    Some(image(CellValue::Json(serde_json::json!({"a": 2})))),
                    None,
                ],
            },
        };
        let mut out = Vec::new();
        assert!(CsvFormatter.format(&event, &mut out).unwrap());
        let csv = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2, "{csv}");
        assert!(
            lines[0].starts_with("9,\"partial_update_rows\",\"db\",\"t\","),
            "{csv}"
        );
        // The applied after image renders as the full new document.
        assert!(lines[0].contains("\"\"a\"\":2"), "{csv}");
        // An absent image in either position renders as quoted JSON `null`.
        assert_eq!(
            lines[1], "9,\"partial_update_rows\",\"db\",\"t\",\"null\",\"null\"",
            "{csv}"
        );
    }

    #[test]
    fn csv_ignores_non_row_events() {
        let event = ParsedEvent {
            offset: 4,
            timestamp: 1,
            event_type: EventType::Xid,
            event_type_code: 16,
            server_id: 1,
            event_size: 27,
            log_pos: 31,
            payload: EventPayload::Xid { xid: 1 },
        };
        let mut out = Vec::new();
        assert!(!CsvFormatter.format(&event, &mut out).unwrap());
        assert!(out.is_empty());
    }
}
