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
fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
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
            for change in changes {
                writeln!(
                    out,
                    "{},{},{},{},{},{}",
                    e.timestamp,
                    quote(e.event_type.as_str()),
                    quote(database),
                    quote(table),
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
