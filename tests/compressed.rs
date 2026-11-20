// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Compressed transaction payloads (code 40, WL#3549) decode safely: the
//! compression algorithm byte is validated before the underlying library can
//! panic on it, decompression is streamed and bounded by the declared size,
//! inner events share the parser's table map state, and hostile payloads fail
//! with clean `InvalidData` errors instead of aborting the process.
//!
//! All fixtures are crafted bytes; the zstd frames store their content in
//! uncompressed blocks, which the reference decoder reconstructs exactly.
use binlog_inspect::{
    event::{CellValue, ColumnValue, EventPayload, EventType, RowChange, RowImage, Signedness},
    parser::BinlogParser,
};
use mysql_common::{
    binlog::{consts::TransactionPayloadCompressionType, events::TransactionPayloadEvent},
    proto::MySerialize,
};
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
};

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

fn raw_event(code: u8, body: &[u8], checksum: bool) -> Vec<u8> {
    let size = 19 + body.len() + if checksum { 4 } else { 0 };
    let mut data = Vec::new();
    data.extend_from_slice(&555u32.to_le_bytes()); // timestamp
    data.push(code);
    data.extend_from_slice(&99u32.to_le_bytes()); // server id
    data.extend_from_slice(&(size as u32).to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes()); // log pos
    data.extend_from_slice(&0u16.to_le_bytes()); // flags
    data.extend_from_slice(body);
    if checksum {
        data.extend_from_slice(&crc32(&data).to_le_bytes());
    }
    data
}

/// A checksummed format description enabling CRC32 event checksums, with the
/// post-header length array left zeroed (6-byte table ids, extra-data length
/// present in row events).
fn format_description() -> Vec<u8> {
    let mut body = vec![0; 57];
    body[0..2].copy_from_slice(&4u16.to_le_bytes());
    body[2..8].copy_from_slice(b"8.0.30");
    body[56] = 19;
    body.extend([0; 40]);
    body.push(1);
    raw_event(15, &body, true)
}

fn file(data: &[u8]) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f
}

/// An inner event of a decompressed payload: 19-byte header plus body, no
/// checksum (WL#3549). The header's timestamp and server id are deliberately
/// different from the outer event's to prove they are inherited.
fn inner_event(code: u8, body: &[u8]) -> Vec<u8> {
    let size = 19 + body.len();
    let mut event = Vec::with_capacity(size);
    event.extend_from_slice(&1234u32.to_le_bytes());
    event.push(code);
    event.extend_from_slice(&1u32.to_le_bytes());
    event.extend_from_slice(&(size as u32).to_le_bytes());
    event.extend_from_slice(&(size as u32).to_le_bytes()); // log pos
    event.extend_from_slice(&0u16.to_le_bytes());
    event.extend_from_slice(body);
    event
}

/// An inner table map for table `db`.`t` with one LONG column.
fn inner_table_map(table_id: u64) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&table_id.to_le_bytes()[..6]);
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.push(2);
    body.extend_from_slice(b"db");
    body.push(0);
    body.push(1);
    body.extend_from_slice(b"t");
    body.push(0);
    body.push(1); // column count
    body.push(0x03); // LONG
    body.push(0); // empty optional metadata
    body.push(0); // null bitmap
    inner_event(19, &body)
}

/// An inner write rows event inserting one row with a single integer value.
fn inner_write_rows(table_id: u64, value: i32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&table_id.to_le_bytes()[..6]);
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.extend_from_slice(&2u16.to_le_bytes()); // extra data length
    body.push(1); // column count
    body.push(0x01); // after-image bitmap
    body.push(0); // row null bitmap
    body.extend_from_slice(&value.to_le_bytes());
    inner_event(30, &body)
}

fn inner_xid(xid: u64) -> Vec<u8> {
    inner_event(16, &xid.to_le_bytes())
}

/// An inner regular GTID event (code 33): flags, sid, gno. Renders as the
/// canonical hyphenated lowercase `uuid:gno`.
fn inner_gtid(sid: [u8; 16], gno: u64) -> Vec<u8> {
    let mut body = vec![0u8]; // flags
    body.extend(sid);
    body.extend(gno.to_le_bytes());
    inner_event(33, &body)
}

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

/// Serializes a transaction payload event body with the library's own writer,
/// wrapped in a checksummed code 40 event.
fn library_payload_event(
    algorithm: TransactionPayloadCompressionType,
    uncompressed_size: u64,
    payload: &[u8],
) -> Vec<u8> {
    let event = TransactionPayloadEvent::new(
        payload.len() as u64,
        algorithm,
        uncompressed_size,
        payload.to_vec(),
    );
    let mut body = Vec::new();
    event.serialize(&mut body);
    raw_event(40, &body, true)
}

/// Hand-crafts a transaction payload event body, allowing field combinations
/// the library's own writer cannot express (declared sizes that lie, unknown
/// algorithm bytes).
fn crafted_payload_event(
    algorithm: Option<u64>,
    uncompressed_size: Option<u64>,
    payload: &[u8],
    checksum: bool,
) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some(algorithm) = algorithm {
        put_lenenc(&mut body, 2); // compression type
        put_lenenc(&mut body, 1); // declared value length
        put_lenenc(&mut body, algorithm);
    }
    if let Some(size) = uncompressed_size {
        put_lenenc(&mut body, 3); // uncompressed size
        put_lenenc(&mut body, 1);
        put_lenenc(&mut body, size);
    }
    put_lenenc(&mut body, 1); // payload size
    put_lenenc(&mut body, 1);
    put_lenenc(&mut body, payload.len() as u64);
    put_lenenc(&mut body, 0); // end mark
    body.extend_from_slice(payload);
    raw_event(40, &body, checksum)
}

/// Builds a valid zstd frame (RFC 8878) whose content is stored in
/// uncompressed ("raw") blocks; the reference decoder reconstructs it exactly.
fn zstd_raw_frame(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 32);
    out.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd]); // magic
    let (fcs_flag, fcs_bytes): (u8, Vec<u8>) = if content.len() < 256 {
        (0, vec![content.len() as u8])
    } else if content.len() < 256 + 65791 {
        (1, ((content.len() - 256) as u16).to_le_bytes().to_vec())
    } else {
        (2, (content.len() as u32).to_le_bytes().to_vec())
    };
    out.push((fcs_flag << 6) | 0x20); // single segment, no checksum, no dict
    out.extend_from_slice(&fcs_bytes);
    let block_cap = 64 * 1024;
    let n_blocks = content.len().div_ceil(block_cap).max(1);
    for (i, chunk) in content.chunks(block_cap).enumerate() {
        // Block header: size, raw block type, last-block flag.
        let header = ((chunk.len() as u32) << 3) | u32::from(i + 1 == n_blocks);
        out.extend_from_slice(&header.to_le_bytes()[..3]);
        out.extend_from_slice(chunk);
    }
    out
}

fn binlog(events: &[Vec<u8>]) -> tempfile::NamedTempFile {
    let mut bytes = b"\xfebin".to_vec();
    for event in events {
        bytes.extend_from_slice(event);
    }
    file(&bytes)
}

/// A payload header without an end mark and without a payload decodes as an
/// empty uncompressed payload: the library treats the missing end mark as an
/// empty payload, and the parser reports it honestly.
#[test]
fn minimal_none_payload_decodes() {
    // The library's serialization of a NONE payload omits the uncompressed
    // size field entirely.
    let f = binlog(&[format_description(), {
        let event =
            TransactionPayloadEvent::new(0, TransactionPayloadCompressionType::NONE, 0, Vec::new());
        let mut body = Vec::new();
        event.serialize(&mut body);
        raw_event(40, &body, true)
    }]);
    let mut parser = BinlogParser::open(f.path()).unwrap();
    let mut events = parser.events();
    assert!(events.next().unwrap().is_ok()); // format description
    let event = events.next().unwrap().unwrap();
    assert_eq!(event.event_type, EventType::TransactionPayload);
    assert_eq!(event.event_type_code, 40);
    assert_eq!(
        event.payload,
        EventPayload::TransactionPayload {
            compression: "NONE".into(),
            uncompressed_size: 0,
            events: Vec::new(),
        }
    );
    assert!(events.next().is_none());
}

/// A ZSTD payload carrying an inner table map, write rows and XID decodes to
/// inner events with stream-relative offsets, inherited timestamp and server
/// id, and fully typed row values.
#[test]
fn zstd_payload_with_inner_events_decodes() {
    let content = [inner_table_map(5), inner_write_rows(5, 42), inner_xid(77)].concat();
    let f = binlog(&[format_description(), {
        library_payload_event(
            TransactionPayloadCompressionType::ZSTD,
            content.len() as u64,
            &zstd_raw_frame(&content),
        )
    }]);
    let mut parser = BinlogParser::open(f.path()).unwrap();
    let mut events = parser.events();
    assert!(events.next().unwrap().is_ok()); // format description
    let event = events.next().unwrap().unwrap();
    assert_eq!(event.event_type, EventType::TransactionPayload);
    assert_eq!(event.timestamp, 555);
    assert_eq!(event.server_id, 99);
    let EventPayload::TransactionPayload {
        compression,
        uncompressed_size,
        events: inner,
    } = event.payload
    else {
        panic!("expected a transaction payload, got {:?}", event.payload);
    };
    assert_eq!(compression, "ZSTD");
    // The declared size matches the frame's decompressed length.
    assert_eq!(uncompressed_size, content.len() as u64);
    assert_eq!(inner.len(), 3);

    // Inner table map: stream-relative offset, inherited header fields.
    assert_eq!(inner[0].offset, 0);
    assert_eq!(inner[0].timestamp, 555);
    assert_eq!(inner[0].server_id, 99);
    assert_eq!(inner[0].event_type, EventType::TableMap);
    assert_eq!(inner[0].event_type_code, 19);
    assert_eq!(inner[0].event_size, 38);
    assert_eq!(
        inner[0].payload,
        EventPayload::TableMap {
            table_id: 5,
            database: "db".into(),
            table: "t".into(),
            column_count: 1,
        }
    );

    // Inner write rows: typed values decoded through the inner table map.
    assert_eq!(inner[1].offset, 38);
    assert_eq!(inner[1].event_type, EventType::WriteRows);
    assert_eq!(inner[1].event_type_code, 30);
    let EventPayload::Rows {
        table_id,
        database,
        table,
        changes,
    } = &inner[1].payload
    else {
        panic!("expected rows, got {:?}", inner[1].payload);
    };
    assert_eq!(*table_id, 5);
    assert_eq!(database.as_str(), "db");
    assert_eq!(table.as_str(), "t");
    assert_eq!(changes.len(), 1);
    assert!(changes[0].before.is_none());
    let after = changes[0].after.as_ref().unwrap();
    assert_eq!(after.columns.len(), 1);
    assert_eq!(after.columns[0].index, 0);
    assert_eq!(after.columns[0].value, CellValue::Int(42));

    // Inner XID.
    assert_eq!(inner[2].offset, 74);
    assert_eq!(inner[2].event_type, EventType::Xid);
    assert_eq!(inner[2].payload, EventPayload::Xid { xid: 77 });
}

/// An uncompressed (NONE) payload decodes through the same streaming path.
#[test]
fn none_payload_with_inner_event_decodes() {
    let content = inner_xid(11);
    let f = binlog(&[format_description(), {
        library_payload_event(TransactionPayloadCompressionType::NONE, 0, &content)
    }]);
    let mut parser = BinlogParser::open(f.path()).unwrap();
    let mut events = parser.events();
    assert!(events.next().unwrap().is_ok());
    let event = events.next().unwrap().unwrap();
    let EventPayload::TransactionPayload {
        compression,
        events: inner,
        ..
    } = event.payload
    else {
        panic!("expected a transaction payload, got {:?}", event.payload);
    };
    assert_eq!(compression, "NONE");
    assert_eq!(inner.len(), 1);
    assert_eq!(inner[0].payload, EventPayload::Xid { xid: 11 });
    assert_eq!(inner[0].offset, 0);
}

/// NONE payloads carry uncompressed_size = 0 on the wire; their decompressed
/// stream is the payload bytes themselves, so the size limit must be the
/// actual payload size, not the declared zero. A valid uncompressed payload
/// larger than the 1 MiB slack once slipped through as "exceeds declared
/// size" (reachable when the server's zstd threshold is raised above 1 MiB).
#[test]
fn large_none_payload_within_payload_size_decodes() {
    let content = inner_xid(1).repeat(40_000); // ~1.08 MiB of inner events
    assert!(content.len() > 1024 * 1024);
    let f = binlog(&[format_description(), {
        library_payload_event(TransactionPayloadCompressionType::NONE, 0, &content)
    }]);
    let mut parser = BinlogParser::open(f.path()).unwrap();
    let mut events = parser.events();
    assert!(events.next().unwrap().is_ok());
    let event = events.next().unwrap().unwrap();
    let EventPayload::TransactionPayload {
        compression,
        events: inner,
        ..
    } = event.payload
    else {
        panic!("expected a transaction payload, got {:?}", event.payload);
    };
    assert_eq!(compression, "NONE");
    assert_eq!(inner.len(), 40_000);
}

/// An unknown compression algorithm byte would unwrap() into a panic inside
/// mysql_common 0.38.2; the framing prevalidation must reject it cleanly.
#[test]
fn unknown_compression_algorithm_is_clean_invalid_data() {
    let f = binlog(&[crafted_payload_event(Some(7), Some(0), b"payload", false)]);
    let outcome = std::panic::catch_unwind(move || {
        let mut parser = BinlogParser::open(f.path()).unwrap();
        let err = parser.events().next().unwrap().unwrap_err();
        assert_eq!(
            err.to_string(),
            "binlog error at offset 4: unsupported transaction payload compression algorithm"
        );
    });
    assert!(outcome.is_ok(), "unknown algorithm caused a panic");
}

#[test]
fn unknown_compression_algorithm_does_not_panic() {
    // The same corpus through the CLI: a non-zero exit without an abort.
    let f = binlog(&[crafted_payload_event(Some(7), Some(0), b"payload", false)]);
    let output = Command::new(env!("CARGO_BIN_EXE_binlog-inspect"))
        .arg(f.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
}

/// A declared uncompressed size above the cap is rejected before any
/// decompression happens; the payload bytes are deliberately not a valid
/// zstd stream to prove they are never touched.
#[test]
fn excessive_declared_uncompressed_size_is_rejected() {
    let f = binlog(&[crafted_payload_event(
        Some(0),
        Some((1 << 30) + 1),
        b"not a zstd frame",
        false,
    )]);
    let mut parser = BinlogParser::open(f.path()).unwrap();
    let err = parser.events().next().unwrap().unwrap_err();
    assert!(
        err.to_string()
            .contains("declares excessive uncompressed size"),
        "{err}"
    );
}

/// A payload whose decompressed stream exceeds the declared uncompressed size
/// (plus slack) is rejected mid-stream: the declaration cannot be trusted to
/// bound a decompression bomb.
#[test]
fn lying_uncompressed_size_is_rejected() {
    // ~39000 inner XIDs, 27 bytes each: slightly more than 1 MiB of
    // decompressed content against a declared size of zero.
    let mut content = Vec::new();
    for xid in 0..39001u64 {
        content.extend_from_slice(&inner_xid(xid));
    }
    assert!(content.len() > (1 << 20) + 1);
    let f = binlog(&[crafted_payload_event(
        Some(0),
        Some(0),
        &zstd_raw_frame(&content),
        false,
    )]);
    let mut parser = BinlogParser::open(f.path()).unwrap();
    let err = parser.events().next().unwrap().unwrap_err();
    assert!(
        err.to_string()
            .contains("decompressed payload exceeds declared size"),
        "{err}"
    );
}

/// A payload containing an inner transaction payload event is rejected: the
/// library refuses nested payloads, and the parser rejects them before the
/// library ever parses the inner bytes.
#[test]
fn nested_payload_is_rejected_cleanly() {
    let content = [inner_xid(11), inner_event(40, &[2, 1, 0, 0])].concat();
    let f = binlog(&[crafted_payload_event(
        Some(0),
        Some(0),
        &zstd_raw_frame(&content),
        false,
    )]);
    let outcome = std::panic::catch_unwind(move || {
        let mut parser = BinlogParser::open(f.path()).unwrap();
        let err = parser.events().next().unwrap().unwrap_err();
        assert!(err.to_string().contains("nested"), "{err}");
    });
    assert!(outcome.is_ok(), "nested payload caused a panic");
}

/// A truncated inner event inside a decompressed payload is an error, not a
/// silent end of stream.
#[test]
fn truncated_inner_event_is_rejected() {
    let content = inner_xid(11);
    let f = binlog(&[crafted_payload_event(
        Some(0),
        Some(0),
        &zstd_raw_frame(&content[..content.len() - 2]),
        false,
    )]);
    let mut parser = BinlogParser::open(f.path()).unwrap();
    let err = parser.events().next().unwrap().unwrap_err();
    assert!(err.to_string().contains("truncated"), "{err}");
}

/// An inner table map carrying a hostile ENUM variant count would abort the
/// process inside the library's metadata parser; the streaming prevalidation
/// rejects it first.
#[test]
fn inner_hostile_table_map_is_rejected() {
    let mut body = vec![5, 0, 0, 0, 0, 0]; // table id
    body.extend([0, 0]); // flags
    body.extend([1, b'd', 0]); // database name
    body.extend([1, b't', 0]); // table name
    body.push(1); // one column
    body.push(0x03); // LONG
    body.push(0); // empty optional metadata length
    body.push(0); // null bitmap
    // ENUM_STR_VALUE TLV declaring u64::MAX variants.
    let mut tlv = vec![6u8, 9, 0xfe];
    tlv.extend_from_slice(&u64::MAX.to_le_bytes());
    body.extend_from_slice(&tlv);
    let content = inner_event(19, &body);
    let f = binlog(&[format_description(), {
        library_payload_event(
            TransactionPayloadCompressionType::ZSTD,
            0,
            &zstd_raw_frame(&content),
        )
    }]);
    let outcome = std::panic::catch_unwind(move || {
        let mut parser = BinlogParser::open(f.path()).unwrap();
        let mut events = parser.events();
        assert!(events.next().unwrap().is_ok()); // format description
        let err = events.next().unwrap().unwrap_err();
        assert!(err.to_string().contains("variant count"), "{err}");
    });
    assert!(outcome.is_ok(), "hostile inner table map caused a panic");
}

/// A table map registered from inside a payload stays available: a later
/// outer row event for the same table id resolves against it.
#[test]
fn inner_table_map_registers_for_later_outer_rows() {
    let content = inner_table_map(5);
    let mut outer_rows = Vec::new();
    outer_rows.extend_from_slice(&5u64.to_le_bytes()[..6]); // table id
    outer_rows.extend_from_slice(&0u16.to_le_bytes()); // flags
    outer_rows.extend_from_slice(&2u16.to_le_bytes()); // extra data length
    outer_rows.push(1); // column count
    outer_rows.push(0x01); // after-image bitmap
    outer_rows.push(0); // row null bitmap
    outer_rows.extend_from_slice(&42i32.to_le_bytes());
    let f = binlog(&[
        format_description(),
        library_payload_event(
            TransactionPayloadCompressionType::ZSTD,
            0,
            &zstd_raw_frame(&content),
        ),
        raw_event(30, &outer_rows, true),
    ]);
    let mut parser = BinlogParser::open(f.path()).unwrap();
    let mut events = parser.events();
    assert!(events.next().unwrap().is_ok()); // format description
    assert!(events.next().unwrap().is_ok()); // transaction payload
    let rows = events.next().unwrap().unwrap();
    assert_eq!(rows.event_type, EventType::WriteRows);
    assert_eq!(
        rows.payload,
        EventPayload::Rows {
            table_id: 5,
            database: "db".into(),
            table: "t".into(),
            changes: vec![RowChange {
                before: None,
                after: Some(RowImage {
                    columns: vec![ColumnValue {
                        index: 0,
                        name: Some("@0".into()),
                        mysql_type: Some("LONG".into()),
                        signedness: Some(Signedness::Unknown),
                        value: CellValue::Int(42),
                    }],
                }),
            }],
        }
    );
    assert!(events.next().is_none());
}

// ---------------------------------------------------------------------------
// R46b: `--stream-payload-events` — streamed compressed-transaction output.
//
// Every expected string below is the real CLI output for the synthetic
// fixtures above, pinned byte for byte: the streamed outer record omits the
// `events` field and carries `streamed: true`, and each inner event becomes a
// top-level line with `parent_offset` and `inner_index` markers.
// ---------------------------------------------------------------------------

/// Runs the CLI and returns the completed process output.
fn run_cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_binlog-inspect"))
        .args(args)
        .output()
        .unwrap()
}

/// The streaming sample: a checksummed format description followed by one
/// NONE payload carrying an inner table map, write rows and XID.
fn none_payload_sample() -> tempfile::NamedTempFile {
    let content = [inner_table_map(5), inner_write_rows(5, 42), inner_xid(77)].concat();
    binlog(&[format_description(), {
        library_payload_event(TransactionPayloadCompressionType::NONE, 0, &content)
    }])
}

/// The exact streaming output for [`none_payload_sample`].
const STREAM_SAMPLE_OUTPUT: &str = concat!(
    r#"{"offset":4,"timestamp":555,"event_type":"format_description","event_type_code":15,"server_id":99,"event_size":121,"log_pos":0,"payload":{"kind":"format_description","server_version":"8.0.30"}}"#,
    "\n",
    r#"{"offset":125,"timestamp":555,"event_type":"transaction_payload","event_type_code":40,"server_id":99,"event_size":133,"log_pos":0,"payload":{"kind":"transaction_payload","compression":"NONE","uncompressed_size":0,"streamed":true}}"#,
    "\n",
    r#"{"offset":0,"timestamp":555,"event_type":"table_map","event_type_code":19,"server_id":99,"event_size":38,"log_pos":38,"payload":{"kind":"table_map","table_id":5,"database":"db","table":"t","column_count":1},"parent_offset":125,"inner_index":0}"#,
    "\n",
    r#"{"offset":38,"timestamp":555,"event_type":"write_rows","event_type_code":30,"server_id":99,"event_size":36,"log_pos":36,"payload":{"kind":"rows","table_id":5,"database":"db","table":"t","changes":[{"before":null,"after":{"columns":[{"index":0,"name":"@0","mysql_type":"LONG","signedness":"unknown","value":{"type":"int","value":42}}]}}]},"parent_offset":125,"inner_index":1}"#,
    "\n",
    r#"{"offset":74,"timestamp":555,"event_type":"xid","event_type_code":16,"server_id":99,"event_size":27,"log_pos":27,"payload":{"kind":"xid","xid":77},"parent_offset":125,"inner_index":2}"#,
    "\n",
);

/// The exact default-mode output for [`none_payload_sample`]: the payload is
/// one nested record, with no `streamed` field and a real (possibly empty)
/// `events` array.
const DEFAULT_SAMPLE_OUTPUT: &str = concat!(
    r#"{"offset":4,"timestamp":555,"event_type":"format_description","event_type_code":15,"server_id":99,"event_size":121,"log_pos":0,"payload":{"kind":"format_description","server_version":"8.0.30"}}"#,
    "\n",
    r#"{"offset":125,"timestamp":555,"event_type":"transaction_payload","event_type_code":40,"server_id":99,"event_size":133,"log_pos":0,"payload":{"kind":"transaction_payload","compression":"NONE","uncompressed_size":0,"events":[{"offset":0,"timestamp":555,"event_type":"table_map","event_type_code":19,"server_id":99,"event_size":38,"log_pos":38,"payload":{"kind":"table_map","table_id":5,"database":"db","table":"t","column_count":1}},{"offset":38,"timestamp":555,"event_type":"write_rows","event_type_code":30,"server_id":99,"event_size":36,"log_pos":36,"payload":{"kind":"rows","table_id":5,"database":"db","table":"t","changes":[{"before":null,"after":{"columns":[{"index":0,"name":"@0","mysql_type":"LONG","signedness":"unknown","value":{"type":"int","value":42}}]}}]}},{"offset":74,"timestamp":555,"event_type":"xid","event_type_code":16,"server_id":99,"event_size":27,"log_pos":27,"payload":{"kind":"xid","xid":77}}]}}"#,
    "\n",
);

/// Streaming mode emits the outer payload record without the `events` field
/// (with `streamed: true`) and one top-level line per inner event, carrying
/// `parent_offset` (the outer file offset) and `inner_index` (0-based per
/// payload).
#[test]
fn stream_payload_events_lines_are_byte_exact() {
    let f = none_payload_sample();
    let path = f.path().to_str().unwrap();
    let output = run_cli(&["--stream-payload-events", "--format", "jsonl", path]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        STREAM_SAMPLE_OUTPUT
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

/// The default run of the same fixture is unchanged: the payload stays one
/// nested record rendering `events: [...]` exactly as before the streaming
/// flag existed (and an empty payload still renders `"events":[]`).
#[test]
fn default_mode_output_stays_nested() {
    let f = none_payload_sample();
    let path = f.path().to_str().unwrap();
    let output = run_cli(&[path]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        DEFAULT_SAMPLE_OUTPUT
    );

    // A genuinely empty payload still renders `events:[]` in default mode.
    let empty = binlog(&[format_description(), {
        let event =
            TransactionPayloadEvent::new(0, TransactionPayloadCompressionType::NONE, 0, Vec::new());
        let mut body = Vec::new();
        event.serialize(&mut body);
        raw_event(40, &body, true)
    }]);
    let output = run_cli(&[empty.path().to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""payload":{"kind":"transaction_payload","compression":"NONE","uncompressed_size":0,"events":[]}"#),
        "{stdout}"
    );
}

/// `--table` evaluates the inner lines as their own events: the inner table
/// map and write rows match `db.t` while the outer payload record (no table)
/// and the inner XID (not a table event) are dropped.
#[test]
fn stream_table_filter_matches_inner_events() {
    let f = none_payload_sample();
    let path = f.path().to_str().unwrap();
    let output = run_cli(&["--stream-payload-events", "--table", "db.t", path]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    assert!(
        lines
            .next()
            .unwrap()
            .starts_with(r#"{"offset":0,"timestamp":555,"event_type":"table_map"#,),
        "{stdout}"
    );
    assert!(
        lines
            .next()
            .unwrap()
            .starts_with(r#"{"offset":38,"timestamp":555,"event_type":"write_rows"#,),
        "{stdout}"
    );
    assert_eq!(lines.next(), None);
    assert!(
        stdout.contains(r#""parent_offset":125,"inner_index":0}"#),
        "{stdout}"
    );
    assert!(
        stdout.contains(r#""parent_offset":125,"inner_index":1}"#),
        "{stdout}"
    );
}

/// `--include-gtid` matches a GTID event inside a payload: only the inner
/// GTID line is kept (the streamed payload start and the inner XID are not
/// GTID payload events).
#[test]
fn stream_gtid_filter_matches_inner_gtid() {
    let content = [inner_gtid([0x11u8; 16], 1), inner_xid(9)].concat();
    let f = binlog(&[format_description(), {
        library_payload_event(TransactionPayloadCompressionType::NONE, 0, &content)
    }]);
    let path = f.path().to_str().unwrap();
    let output = run_cli(&[
        "--stream-payload-events",
        "--include-gtid",
        "11111111-1111-1111-1111-111111111111:1",
        path,
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        concat!(
            r#"{"offset":0,"timestamp":555,"event_type":"gtid","event_type_code":33,"server_id":99,"event_size":44,"log_pos":44,"payload":{"kind":"gtid","gtid":"11111111-1111-1111-1111-111111111111:1","tag":null},"parent_offset":125,"inner_index":0}"#,
            "\n",
        )
    );
}

/// Position-range filters gate only the outer payload event: an inner event's
/// offset counts from the start of the decompressed stream, so the inner
/// lines are never dropped by `--start-position`/`--stop-position`.
#[test]
fn stream_position_filters_gate_only_the_outer_event() {
    let f = none_payload_sample();
    let path = f.path().to_str().unwrap();

    // The outer record starts exactly at 125: it is kept, and every inner
    // line (offsets 0, 38, 74 — all below the start bound) is kept too. The
    // ordinary format-description event (offset 4 < 125) is still dropped.
    let output = run_cli(&["--stream-payload-events", "--start-position", "125", path]);
    assert_eq!(output.status.code(), Some(0));
    let expected = STREAM_SAMPLE_OUTPUT
        .split_once('\n')
        .map(|(_, rest)| rest)
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&output.stdout), expected);

    // The exclusive stop bound drops the outer record (offset 125 >= 125)
    // while the inner lines still stream through. The ordinary
    // format-description event (offset 4 < 125) is kept as usual.
    let output = run_cli(&["--stream-payload-events", "--stop-position", "125", path]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(r#""event_type":"transaction_payload""#),
        "{stdout}"
    );
    assert_eq!(stdout.lines().count(), 4, "{stdout}");
}

/// Streaming mode is JSONL-only: `--format text`, `--format csv` and
/// `--stats` are usage errors (exit code 2) at argument-parse time, each
/// naming its actual conflict.
#[test]
fn stream_payload_events_rejects_text_csv_stats() {
    for (args, expected) in [
        (
            vec!["--format", "text"],
            "--stream-payload-events requires --format jsonl",
        ),
        (
            vec!["--format", "csv"],
            "--stream-payload-events requires --format jsonl",
        ),
        (
            vec!["--stats"],
            "--stream-payload-events cannot be combined with --stats",
        ),
    ] {
        let f = none_payload_sample();
        let mut argv = vec!["--stream-payload-events"];
        argv.extend(&args);
        argv.push(f.path().to_str().unwrap());
        let output = run_cli(&argv);
        assert_eq!(output.status.code(), Some(2), "{argv:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{stderr}");
        assert!(String::from_utf8_lossy(&output.stdout).is_empty());
    }
}

/// A mid-payload error keeps the lines already emitted (the outer streamed
/// record): the default mode reports Partial (exit 3) with the per-file
/// summary on stderr, and an `--output` file is published with that prefix.
#[test]
fn stream_payload_events_partial_exit_keeps_emitted_lines() {
    // The payload event itself is consistent, but its inner XID event is
    // truncated: the streamed record is emitted, then decoding fails.
    let content = inner_xid(11);
    let f = binlog(&[format_description(), {
        library_payload_event(
            TransactionPayloadCompressionType::NONE,
            0,
            &content[..content.len() - 2],
        )
    }]);
    let path = f.path().to_str().unwrap();

    let output = run_cli(&["--stream-payload-events", path]);
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(r#""streamed":true"#), "{stdout}");
    assert_eq!(stdout.lines().count(), 2, "{stdout}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("could not be fully parsed"), "{stderr}");
    assert!(
        stderr.contains("binlog error at offset 125: transaction payload at inner offset 0: truncated transaction payload"),
        "{stderr}"
    );

    // The same run through --output publishes the successfully streamed
    // prefix (the intentional exit-3 semantics): the format-description line
    // and the streamed outer record (event size 57 for the truncated payload).
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("out.jsonl");
    let output = run_cli(&[
        "--stream-payload-events",
        "--output",
        target.to_str().unwrap(),
        path,
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stdout).is_empty());
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        concat!(
            r#"{"offset":4,"timestamp":555,"event_type":"format_description","event_type_code":15,"server_id":99,"event_size":121,"log_pos":0,"payload":{"kind":"format_description","server_version":"8.0.30"}}"#,
            "\n",
            r#"{"offset":125,"timestamp":555,"event_type":"transaction_payload","event_type_code":40,"server_id":99,"event_size":57,"log_pos":0,"payload":{"kind":"transaction_payload","compression":"NONE","uncompressed_size":0,"streamed":true}}"#,
            "\n",
        )
    );
}

/// Under `--strict` a mid-payload error aborts with exit code 1 and the
/// `--output` temporary file is deleted: no output file is left behind.
#[test]
fn stream_payload_events_strict_exit_deletes_output() {
    let content = inner_xid(11);
    let f = binlog(&[format_description(), {
        library_payload_event(
            TransactionPayloadCompressionType::NONE,
            0,
            &content[..content.len() - 2],
        )
    }]);
    let path = f.path().to_str().unwrap();

    let output = run_cli(&["--stream-payload-events", "--strict", path]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot fully parse"), "{stderr}");

    // The temp file behind --output is removed on the hard error.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("out.jsonl");
    let output = run_cli(&[
        "--stream-payload-events",
        "--strict",
        "--output",
        target.to_str().unwrap(),
        path,
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!target.exists());
    // No hidden temporary files remain either.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

/// `--output` composes with streaming mode on a fully successful run: the
/// file receives exactly the bytes stdout would have received.
#[test]
fn stream_payload_events_output_composition() {
    let f = none_payload_sample();
    let path = f.path().to_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("out.jsonl");
    let output = run_cli(&[
        "--stream-payload-events",
        "--output",
        target.to_str().unwrap(),
        path,
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).is_empty());
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        STREAM_SAMPLE_OUTPUT
    );
}

/// Streaming mode works through standard input (`-`).
#[test]
fn stream_payload_events_reads_stdin() {
    let f = none_payload_sample();
    let mut bytes = Vec::new();
    std::fs::File::open(f.path())
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_binlog-inspect"))
        .args(["--stream-payload-events", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(&bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        STREAM_SAMPLE_OUTPUT
    );
}

/// `--max-inner-events` is accepted with streaming mode but has no effect:
/// `visit_events` is backpressured by the CLI writing each line, so no
/// payload ever hits the collecting path's bound.
#[test]
fn stream_payload_events_ignores_max_inner_events() {
    let f = none_payload_sample();
    let path = f.path().to_str().unwrap();
    let output = run_cli(&["--stream-payload-events", "--max-inner-events", "1", path]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        STREAM_SAMPLE_OUTPUT
    );
}
