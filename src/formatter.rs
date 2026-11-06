// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Output formatters that operate on the independent event model.
use crate::event::{EventPayload, ParsedEvent};
use std::io::Write;
/// Failures while writing formatted events.
#[derive(Debug, thiserror::Error)]
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
        if let EventPayload::Rows {
            database,
            table,
            changes,
            ..
        } = &e.payload
        {
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
        } else {
            Ok(false)
        }
    }
}
