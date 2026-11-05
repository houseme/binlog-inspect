// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Partial JSON updates (WL#2955, `binlog_row_value_options=PARTIAL_JSON`).
//!
//! Such binlogs carry table map optional metadata types 14 and 15 that the
//! underlying library's metadata iterator rejects; the parser strips those
//! entries from the table map bytes before the library parses them, so the
//! file decodes and row images still resolve. All fixtures are crafted bytes.

use binlog_inspect::{
    event::{CellValue, EventPayload, EventType, Signedness},
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
    data.extend_from_slice(&0u32.to_le_bytes());
    data.push(code);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&(size as u32).to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
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

fn binlog(events: &[Vec<u8>]) -> tempfile::NamedTempFile {
    let mut bytes = b"\xfebin".to_vec();
    for event in events {
        bytes.extend_from_slice(event);
    }
    file(&bytes)
}

fn put_lenenc(out: &mut Vec<u8>, value: u64) {
    if value < 251 {
        out.push(value as u8);
    } else {
        out.push(0xfc);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    }
}

/// Appends one optional metadata TLV: type byte, length, value.
fn tlv(out: &mut Vec<u8>, field_type: u8, value: &[u8]) {
    out.push(field_type);
    put_lenenc(out, value.len() as u64);
    out.extend_from_slice(value);
}

/// The body of a table map for `d`.`t` with one LONG and one JSON column.
///
/// `partial` adds the PARTIAL_JSON_UPDATE (14) and UPDATED_COLUMN_TYPES (15)
/// entries a partial-JSON binlog carries; `signedness` adds the SIGNEDNESS
/// (1) entry marking the LONG column unsigned.
fn table_map_body(table_id: u64, partial: bool, signedness: bool) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&table_id.to_le_bytes()[..6]);
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.push(1);
    body.extend_from_slice(b"d");
    body.push(0);
    body.push(1);
    body.extend_from_slice(b"t");
    body.push(0);
    body.push(2); // two columns
    body.extend_from_slice(&[0x03, 0xf5]); // LONG (0x03), JSON (0xf5)
    body.push(0); // no column metadata
    body.push(1); // null bitmap
    let mut meta = Vec::new();
    if signedness {
        tlv(&mut meta, 1, &[0x80]); // the LONG column is unsigned
    }
    if partial {
        tlv(&mut meta, 14, &[0x40]); // the JSON column uses partial updates
        tlv(&mut meta, 15, &[0xf5, 0x00]);
    }
    body.extend_from_slice(&meta);
    body
}

fn table_map(table_id: u64, partial: bool, signedness: bool) -> Vec<u8> {
    raw_event(19, &table_map_body(table_id, partial, signedness), true)
}

/// Binary jsonb for `{"a": 1, "b": [1, 2]}` (small object form; offsets are
/// relative to the container's element-count field).
const JSONB_DOC: &[u8] = &[
    0x00, 0x02, 0x00, 0x1e, 0x00, // small object, two members, 30 bytes
    0x12, 0x00, 0x01, 0x00, // key entry: "a" at offset 18, length 1
    0x13, 0x00, 0x01, 0x00, // key entry: "b" at offset 19, length 1
    0x05, 0x01, 0x00, // value entry: int16 1 (inlined)
    0x02, 0x14, 0x00, // value entry: small array at offset 20
    b'a', b'b', 0x02, 0x00, 0x0a, 0x00, 0x05, 0x01, 0x00, 0x05, 0x02, 0x00,
];

/// Binary jsonb for `{"a": 1, "b": 44}` (a full after document).
const JSONB_AFTER: &[u8] = &[
    0x00, 0x02, 0x00, 0x14, 0x00, // small object, two members, 20 bytes
    0x12, 0x00, 0x01, 0x00, // key entry: "a" at offset 18, length 1
    0x13, 0x00, 0x01, 0x00, // key entry: "b" at offset 19, length 1
    0x05, 0x01, 0x00, // value entry at offset 12: int16 1 (inlined)
    0x05, 0x2c, 0x00, // value entry at offset 15: int16 44 (inlined)
    b'a', b'b', // key bytes at offsets 18, 19
];

/// A full JSON column value: u32 length prefix plus the jsonb bytes.
fn json_column_value(jsonb: &[u8]) -> Vec<u8> {
    let mut out = (jsonb.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(jsonb);
    out
}

/// A write rows event inserting one row (unsigned LONG, full JSON document).
fn write_rows(table_id: u64, long_value: u32, jsonb: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&table_id.to_le_bytes()[..6]);
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.extend_from_slice(&2u16.to_le_bytes()); // extra data length
    body.push(2); // column count
    body.push(0x03); // both columns present
    body.push(0); // null bitmap
    body.extend_from_slice(&long_value.to_le_bytes());
    body.extend_from_slice(&json_column_value(jsonb));
    raw_event(30, &body, true)
}

/// An update rows event whose images carry full JSON documents (a partial
/// JSON binlog still logs full values when no diffable change was made).
fn update_rows(table_id: u64) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&table_id.to_le_bytes()[..6]);
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.extend_from_slice(&2u16.to_le_bytes()); // extra data length
    body.push(2); // column count
    body.push(0x03); // before bitmap
    body.push(0x03); // after bitmap
    body.push(0); // null bitmap
    body.extend_from_slice(&7u32.to_le_bytes());
    body.extend_from_slice(&json_column_value(JSONB_DOC));
    body.push(0); // null bitmap
    body.extend_from_slice(&8u32.to_le_bytes());
    body.extend_from_slice(&json_column_value(JSONB_AFTER));
    raw_event(31, &body, true)
}

/// A partial update rows event: the before image is a full row image, the
/// after image starts with the value options and the partial bitmap (WL#2955)
/// and stores a diff sequence in the JSON column.
fn partial_update_rows(table_id: u64, before_jsonb: &[u8], diffs: &[u8]) -> Vec<u8> {
    let body = partial_update_rows_body(table_id, before_jsonb, diffs);
    raw_event(39, &body, true)
}

fn partial_update_rows_body(table_id: u64, before_jsonb: &[u8], diffs: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&table_id.to_le_bytes()[..6]);
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.extend_from_slice(&2u16.to_le_bytes()); // extra data length
    body.push(2); // column count
    body.push(0x03); // before bitmap
    body.push(0x03); // after bitmap
    // Before image: a full row image.
    body.push(0); // null bitmap
    body.extend_from_slice(&7u32.to_le_bytes());
    body.extend_from_slice(&json_column_value(before_jsonb));
    // After image: value options, partial bitmap, then the row values —
    // every present column still carries a value; partial-JSON columns
    // carry their diff sequence instead of a full document.
    body.push(1); // value options: PARTIAL_JSON_UPDATES
    body.push(1); // partial bitmap: the table's one JSON column is partial
    body.push(0); // null bitmap
    body.extend_from_slice(&8u32.to_le_bytes());
    body.extend_from_slice(&json_column_value(diffs));
    body
}

/// REPLACE `$.b[1]` with 99, as stored in a partial JSON after image.
fn replace_diff() -> Vec<u8> {
    let mut diff = vec![0x00]; // REPLACE
    put_lenenc(&mut diff, 6); // path length
    diff.extend_from_slice(b"$.b[1]");
    put_lenenc(&mut diff, 3); // value length
    diff.extend_from_slice(&[0x05, 99, 0x00]); // int16 99
    diff
}

/// A table map with the partial-JSON metadata types parses, and following row
/// events resolve the table map with the SIGNEDNESS entry intact — offsets
/// keep counting the original (unstripped) event size.
#[test]
fn table_map_with_partial_json_metadata_parses() {
    let tme = table_map(1, true, true);
    let rows = write_rows(1, 7, JSONB_DOC);
    let mut parser_events =
        BinlogParser::open(binlog(&[format_description(), tme.clone(), rows]).path()).unwrap();
    let mut events = parser_events.events();
    assert!(events.next().unwrap().is_ok()); // format description
    let event = events.next().unwrap().unwrap();
    assert_eq!(event.event_type, EventType::TableMap);
    assert_eq!(
        event.payload,
        EventPayload::TableMap {
            table_id: 1,
            database: "d".into(),
            table: "t".into(),
            column_count: 2,
        }
    );
    assert_eq!(event.event_size, tme.len() as u32);
    let rows_event = events.next().unwrap().unwrap();
    assert_eq!(rows_event.event_type, EventType::WriteRows);
    // The row event starts exactly after the original table map size.
    assert_eq!(
        rows_event.offset,
        (4 + format_description().len() + tme.len()) as u64
    );
    let EventPayload::Rows { changes, .. } = rows_event.payload else {
        panic!("expected rows payload");
    };
    assert!(changes[0].before.is_none());
    let after = changes[0].after.as_ref().unwrap();
    // The underlying library decodes unsigned binlog LONG columns as a
    // signed value; the unsigned-ness lives in the signedness metadata.
    assert_eq!(after.columns[0].value, CellValue::Int(7));
    assert_eq!(after.columns[0].signedness, Some(Signedness::Unsigned));
    assert_eq!(
        after.columns[1].value,
        CellValue::Json(serde_json::json!({"a": 1, "b": [1, 2]}))
    );
    assert!(events.next().is_none());
}

/// A partial update rows event (code 39) decodes its before image (a full
/// row image) while the diff-bearing after image is consumed without error;
/// the table map's partial-JSON metadata no longer aborts the file.
#[test]
fn partial_update_rows_with_diffs_decode_the_before_image() {
    let mut parser_events = BinlogParser::open(
        binlog(&[
            format_description(),
            table_map(1, true, true),
            partial_update_rows(1, JSONB_DOC, &replace_diff()),
        ])
        .path(),
    )
    .unwrap();
    let mut events = parser_events.events();
    assert!(events.next().unwrap().is_ok()); // format description
    assert!(events.next().unwrap().is_ok()); // table map
    let event = events.next().unwrap().unwrap();
    assert_eq!(event.event_type, EventType::PartialUpdateRows);
    let EventPayload::PartialUpdateRows { before, .. } = event.payload else {
        panic!("expected a partial update rows payload");
    };
    let before = before[0].as_ref().unwrap();
    assert_eq!(before.columns[0].value, CellValue::Int(7));
    assert_eq!(before.columns[0].signedness, Some(Signedness::Unsigned));
    assert_eq!(
        before.columns[1].value,
        CellValue::Json(serde_json::json!({"a": 1, "b": [1, 2]}))
    );
    assert!(events.next().is_none());
}

/// Updates without partial JSON decode both images as full documents, with
/// and without the partial-JSON table map metadata present.
#[test]
fn update_rows_without_diffs_decode_both_images() {
    for partial in [false, true] {
        let mut parser_events = BinlogParser::open(
            binlog(&[
                format_description(),
                table_map(1, partial, true),
                update_rows(1),
            ])
            .path(),
        )
        .unwrap();
        let mut events = parser_events.events();
        assert!(events.next().unwrap().is_ok()); // format description
        assert!(events.next().unwrap().is_ok()); // table map
        let event = events.next().unwrap().unwrap();
        assert_eq!(event.event_type, EventType::UpdateRows);
        let EventPayload::Rows { changes, .. } = event.payload else {
            panic!("expected rows payload");
        };
        let after = changes[0].after.as_ref().unwrap();
        assert_eq!(after.columns[0].value, CellValue::Int(8));
        assert_eq!(
            after.columns[1].value,
            CellValue::Json(serde_json::json!({"a": 1, "b": 44}))
        );
        let before = changes[0].before.as_ref().unwrap();
        assert_eq!(
            before.columns[1].value,
            CellValue::Json(serde_json::json!({"a": 1, "b": [1, 2]}))
        );
        assert!(events.next().is_none());
    }
}

/// Hostile partial-JSON metadata: an absurd declared TLV length must return a
/// clean `InvalidData` error, never abort the process.
#[test]
fn hostile_partial_json_tlv_lengths_are_rejected_cleanly() {
    for name in ["partial json update", "updated column types"] {
        let field_type = if name == "partial json update" {
            14
        } else {
            15
        };
        let mut tlv_bytes = vec![field_type, 0xfe];
        tlv_bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        let mut body = Vec::new();
        body.extend_from_slice(&1u64.to_le_bytes()[..6]); // table id
        body.extend_from_slice(&0u16.to_le_bytes()); // flags
        body.push(1);
        body.extend_from_slice(b"d");
        body.push(0);
        body.push(1);
        body.extend_from_slice(b"t");
        body.push(0);
        body.push(1); // one column
        body.push(0x03); // LONG
        body.push(0); // no column metadata
        body.push(1); // null bitmap
        body.extend_from_slice(&tlv_bytes);
        let f = binlog(&[format_description(), raw_event(19, &body, true)]);
        let outcome = std::panic::catch_unwind(move || {
            let mut parser = BinlogParser::open(f.path()).unwrap();
            let mut events = parser.events();
            assert!(events.next().unwrap().is_ok()); // format description
            let err = events.next().unwrap().unwrap_err();
            assert!(
                err.to_string().contains("exceeds table map bounds"),
                "unexpected error for {name}: {err}"
            );
        });
        assert!(outcome.is_ok(), "hostile {name} metadata caused a panic");
    }
}

/// An inner event of a decompressed payload: 19-byte header plus body, no
/// checksum (WL#3549).
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

/// An inner table map with the partial-JSON metadata types.
fn inner_table_map(table_id: u64) -> Vec<u8> {
    inner_event(19, &table_map_body(table_id, true, true))
}

/// An inner write rows event inserting one row (unsigned LONG, full JSON).
fn inner_write_rows(table_id: u64, long_value: u32, jsonb: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&table_id.to_le_bytes()[..6]);
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.extend_from_slice(&2u16.to_le_bytes()); // extra data length
    body.push(2); // column count
    body.push(0x03); // both columns present
    body.push(0); // null bitmap
    body.extend_from_slice(&long_value.to_le_bytes());
    body.extend_from_slice(&json_column_value(jsonb));
    inner_event(30, &body)
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

/// Builds a valid zstd frame (RFC 8878) whose content is stored in
/// uncompressed ("raw") blocks; the reference decoder reconstructs it exactly.
fn zstd_raw_frame(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 32);
    out.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd]); // magic
    let (fcs_flag, fcs_bytes): (u8, Vec<u8>) = if content.len() < 256 {
        (0, vec![content.len() as u8])
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

/// Sanity check for the zstd frame helper: the system `zstd` binary, when
/// available, reconstructs the original content from the crafted frame.
#[test]
fn zstd_frame_helper_round_trips() {
    let content = b"binlog-inspect zstd frame helper";
    let frame = zstd_raw_frame(content);
    let dir = tempfile::tempdir().unwrap();
    let frame_path = dir.path().join("frame.zst");
    std::fs::write(&frame_path, &frame).unwrap();
    let Ok(output) = Command::new("zstd")
        .arg("-d")
        .arg(&frame_path)
        .arg("-o")
        .arg(dir.path().join("out"))
        .output()
    else {
        // No zstd binary on this machine: nothing to compare against.
        return;
    };
    assert!(output.status.success(), "{output:?}");
    let decoded = std::fs::read(dir.path().join("out")).unwrap();
    assert_eq!(decoded, content);
}

/// An inner table map of a compressed transaction payload carrying the
/// partial-JSON metadata is stripped the same way as an outer one, so the
/// inner row events decode; inner sizes still report the declared values.
#[test]
fn inner_table_map_with_partial_json_metadata_is_stripped() {
    let content = [
        inner_table_map(5),
        inner_write_rows(5, 9, JSONB_DOC),
        inner_event(16, &77u64.to_le_bytes()), // XID
    ]
    .concat();
    let tme_size = {
        let body = table_map_body(5, true, true);
        19 + body.len()
    };
    let mut parser_events = BinlogParser::open(
        binlog(&[
            format_description(),
            library_payload_event(
                TransactionPayloadCompressionType::ZSTD,
                content.len() as u64,
                &zstd_raw_frame(&content),
            ),
        ])
        .path(),
    )
    .unwrap();
    let mut events = parser_events.events();
    assert!(events.next().unwrap().is_ok()); // format description
    let event = events.next().unwrap().unwrap();
    let EventPayload::TransactionPayload { events: inner, .. } = event.payload else {
        panic!("expected a transaction payload");
    };
    assert_eq!(inner.len(), 3);
    assert_eq!(inner[0].event_type_code, 19);
    assert_eq!(inner[0].event_size, tme_size as u32);
    let EventPayload::Rows { changes, .. } = &inner[1].payload else {
        panic!("expected inner rows payload");
    };
    let after = changes[0].after.as_ref().unwrap();
    assert_eq!(after.columns[0].value, CellValue::Int(9));
    assert_eq!(after.columns[0].signedness, Some(Signedness::Unsigned));
    assert_eq!(
        after.columns[1].value,
        CellValue::Json(serde_json::json!({"a": 1, "b": [1, 2]}))
    );
    assert!(matches!(inner[2].payload, EventPayload::Xid { xid: 77 }));
}
