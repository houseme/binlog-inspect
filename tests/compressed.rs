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
use std::{io::Write, process::Command};

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
