// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Streaming inspection of plaintext MySQL binary logs.
//!
//! The crate parses a binlog one event at a time into a stable event model
//! ([`event::ParsedEvent`]) that is independent of the underlying binlog
//! library, so CLI output and library consumers never see raw library types.
//!
//! # Guarantees
//!
//! * Raw event buffers are limited by [`parser::MAX_EVENT_SIZE`] by default.
//!   [`parser::BinlogParser::visit_events`] delivers compressed-transaction
//!   children individually. The collecting iterator retains all children of
//!   a payload up to [`parser::DEFAULT_INNER_EVENT_LIMIT`] (raise it with
//!   [`parser::BinlogParser::with_inner_event_limit`]), and decoded row
//!   images and shared table maps also use memory. Decoded JSON values are
//!   bounded by a nesting-depth cap and a node budget.
//! * Encrypted binlogs are detected and rejected, not misread.
//! * Framing, checksum, and decoding failures are reported as errors carrying
//!   the file offset; nothing is silently skipped.
//!
//! # Example
//!
//! Build a synthetic in-memory binlog (the four-byte magic followed by one
//! XID event) and parse it from a [`std::io::Cursor`]:
//!
//! ```
//! use binlog_inspect::{event::{EventPayload, EventType}, parser::BinlogParser};
//! use std::io::Cursor;
//!
//! // One event: 19-byte header (timestamp, type, server id, size, log_pos,
//! // flags) plus the 8-byte XID body.
//! fn xid_event(xid: u64) -> Vec<u8> {
//!     let size = 19u32 + 8;
//!     let mut event = Vec::new();
//!     event.extend(1u32.to_le_bytes()); // timestamp
//!     event.push(16); // XID_EVENT
//!     event.extend(7u32.to_le_bytes()); // server id
//!     event.extend(size.to_le_bytes());
//!     event.extend((4 + size).to_le_bytes()); // log_pos
//!     event.extend(0u16.to_le_bytes()); // flags
//!     event.extend(xid.to_le_bytes());
//!     event
//! }
//!
//! let mut bytes = b"\xfebin".to_vec();
//! bytes.extend(xid_event(42));
//! let mut parser = BinlogParser::from_reader(Cursor::new(bytes)).unwrap();
//! let event = parser.events().next().unwrap().unwrap();
//! assert_eq!(event.event_type, EventType::Xid);
//! assert!(matches!(event.payload, EventPayload::Xid { xid: 42 }));
//! ```
#![warn(missing_docs)]
#![forbid(unsafe_code)]
pub mod event;
pub mod filter;
pub mod formatter;
pub mod parser;

mod row_decode;
