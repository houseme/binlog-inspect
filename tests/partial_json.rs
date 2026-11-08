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
    filter::EventFilter,
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
    body.extend_from_slice(&[1, 4]); // JSON uses a four-byte length prefix
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

#[test]
fn partial_json_quoted_paths_decode_without_targeting_another_member() {
    // Two keys with distinct values ensure that decoding \\f as the letter
    // f would silently change the wrong member.
    let mut before = JSONB_AFTER.to_vec();
    let key_start = before.len() - 2;
    before[key_start..].copy_from_slice(&[0x0c, b'f']);
    for path in [r#"$."\f""#, r#"$."\x66""#] {
        let mut diffs = vec![0x00]; // REPLACE
        put_lenenc(&mut diffs, path.len() as u64);
        diffs.extend_from_slice(path.as_bytes());
        put_lenenc(&mut diffs, 3);
        diffs.extend_from_slice(&[0x05, 9, 0]); // int16 9
        let file = binlog(&[
            format_description(),
            table_map(1, true, true),
            partial_update_rows(1, &before, &diffs),
        ]);
        let mut parser = BinlogParser::open(file.path()).unwrap();
        let events = parser.events().collect::<Result<Vec<_>, _>>().unwrap();
        let EventPayload::PartialUpdateRows { after, .. } = &events[2].payload else {
            panic!("expected partial update rows");
        };
        let cell = &after[0].as_ref().unwrap().columns[1].value;
        if path.contains("\\f") {
            assert_eq!(
                cell,
                &CellValue::Json(serde_json::json!({"\u{000c}": 9, "f": 44}))
            );
        } else {
            let CellValue::PartialJson { diffs, reason } = cell else {
                panic!("expected a loss-marked invalid path");
            };
            assert_eq!(diffs[0].path, path);
            assert!(reason.contains("invalid JSON path"), "{reason}");
        }
    }
}

/// A full JSON column value: u32 length prefix plus the jsonb bytes.
fn json_column_value(jsonb: &[u8]) -> Vec<u8> {
    let mut out = (jsonb.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(jsonb);
    out
}

/// The body of a write rows event inserting one row (unsigned LONG, full
/// JSON document). Used for both the V2 (code 30) and V1 (code 23) events:
/// the fixture's format description leaves the post-header length array
/// zeroed, so the library reads the V1 event with the V2 layout (6-byte
/// table id, extra-data length present) — real V1 files declare a post
/// header of 8 and carry no extra-data field.
fn write_rows_body(table_id: u64, long_value: u32, jsonb: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&table_id.to_le_bytes()[..6]);
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.extend_from_slice(&2u16.to_le_bytes()); // extra data length
    body.push(2); // column count
    body.push(0x03); // both columns present
    body.push(0); // null bitmap
    body.extend_from_slice(&long_value.to_le_bytes());
    body.extend_from_slice(&json_column_value(jsonb));
    body
}

/// A write rows event inserting one row (unsigned LONG, full JSON document).
fn write_rows(table_id: u64, long_value: u32, jsonb: &[u8]) -> Vec<u8> {
    raw_event(30, &write_rows_body(table_id, long_value, jsonb), true)
}

/// A V1 write rows event (code 23, MySQL 5.5 era) with the same body layout.
fn v1_write_rows(table_id: u64, long_value: u32, jsonb: &[u8]) -> Vec<u8> {
    raw_event(23, &write_rows_body(table_id, long_value, jsonb), true)
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

/// Binary jsonb for `{"price": <opaque NEWDECIMAL 12.5>}`.
///
/// The opaque member is what MySQL writes for a decimal literal or a
/// DECIMAL column value inside a JSON document: a JSONB opaque value whose
/// payload is the column type (NEWDECIMAL = 246), a variable-length data
/// length, and the packed binlog decimal (precision, scale, packed digits).
/// Nested values carry no type byte of their own — the value entry names
/// the type and points at the payload.
fn jsonb_with_decimal_member() -> Vec<u8> {
    let dec = mysql_common::binlog::decimal::Decimal::parse_str_bytes(b"12.5").unwrap();
    let mut out = vec![0x00]; // small object
    out.extend(1u16.to_le_bytes()); // one member
    out.extend(18u16.to_le_bytes()); // size, from the element-count field on
    out.extend(11u16.to_le_bytes()); // key entry: offset 11, length 1
    out.extend(1u16.to_le_bytes());
    out.push(0x0f); // value entry: JSONB_TYPE_OPAQUE
    out.extend(12u16.to_le_bytes()); // value payload offset
    out.push(b'p'); // key byte at offset 11
    out.push(0xf6); // opaque payload: column type NEWDECIMAL
    out.push(4); // variable-length data length
    out.extend([3, 1]); // precision 3, scale 1
    dec.write_bin(&mut out).unwrap(); // packed digits
    out
}

/// A JSON column whose document contains an opaque NEWDECIMAL member decodes
/// (the decimal renders as its string form per the library's JsonDom rules)
/// and the file's event count stays intact.
#[test]
fn opaque_decimal_json_member_decodes_and_keeps_the_event_count() {
    let mut parser = BinlogParser::open(
        binlog(&[
            format_description(),
            table_map(1, false, true),
            write_rows(1, 7, &jsonb_with_decimal_member()),
        ])
        .path(),
    )
    .unwrap();
    let events: Vec<_> = parser.events().collect();
    assert_eq!(events.len(), 3, "every event still decodes: {events:?}");
    let rows = events[2].as_ref().unwrap();
    assert_eq!(rows.event_type, EventType::WriteRows);
    let EventPayload::Rows { changes, .. } = &rows.payload else {
        panic!("expected rows payload");
    };
    assert_eq!(
        changes[0].after.as_ref().unwrap().columns[1].value,
        CellValue::Json(serde_json::json!({"p": "12.5"}))
    );
}

/// A nested large jsonb array holding three elements: element 0 is the child
/// container (or, at the bottom of a chain, another inlined int16), elements
/// 1 and 2 are inlined int16s. Nested values carry no type byte of their
/// own — the value entry names the type and points at the payload, so the
/// payload starts with the element count field.
fn nested_large_array(child: Option<&[u8]>) -> Vec<u8> {
    let mut out = vec![0x03, 0x00, 0x00, 0x00]; // payload: element count = 3
    let size_pos = out.len();
    out.extend(0u32.to_le_bytes()); // size counts from the element-count field
    if child.is_some() {
        out.push(0x03); // element 0: the child container
        out.extend(23u32.to_le_bytes()); // offset from the element-count field
    } else {
        out.push(0x05); // element 0: inlined int16
        out.extend(1i16.to_le_bytes());
        out.extend([0, 0]);
    }
    out.push(0x05); // elements 1 and 2: inlined int16s
    out.extend(1i16.to_le_bytes());
    out.extend([0, 0]);
    out.push(0x05);
    out.extend(1i16.to_le_bytes());
    out.extend([0, 0]);
    if let Some(nested) = child {
        out.extend(nested);
    }
    let total = out.len() as u32;
    out[size_pos..size_pos + 4].copy_from_slice(&total.to_le_bytes());
    out
}

/// A top-level large array wrapping a chain of `depth - 1` nested
/// containers, so `depth` counts the containers in total. Large arrays carry
/// 4-byte offsets and sizes, so deep chains cannot be built from the small
/// format.
fn deep_jsonb(depth: usize) -> Vec<u8> {
    let mut chain = nested_large_array(None);
    for _ in 1..depth - 1 {
        chain = nested_large_array(Some(&chain));
    }
    let mut out = vec![0x03];
    out.extend(3u32.to_le_bytes()); // real element count
    let size_pos = out.len();
    out.extend(0u32.to_le_bytes()); // size counts from the element-count field
    out.push(0x03); // element 0: the nested chain
    out.extend(23u32.to_le_bytes()); // offset from the element-count field
    out.push(0x05); // elements 1 and 2: inlined int16s
    out.extend(1i16.to_le_bytes());
    out.extend([0, 0]);
    out.push(0x05);
    out.extend(1i16.to_le_bytes());
    out.extend([0, 0]);
    out.extend(chain);
    let total = (out.len() - 1) as u32;
    out[size_pos..size_pos + 4].copy_from_slice(&total.to_le_bytes());
    out
}

/// Hostile jsonb nested far beyond MySQL's 100-level limit yields a clean
/// `InvalidData` error carrying the event offset instead of aborting the
/// process with a stack overflow.
#[test]
fn over_deep_jsonb_yields_invalid_data_not_an_abort() {
    let rows_offset = 4 + format_description().len() + table_map(1, false, false).len();
    let mut parser = BinlogParser::open(
        binlog(&[
            format_description(),
            table_map(1, false, false),
            write_rows(1, 7, &deep_jsonb(60_000)),
        ])
        .path(),
    )
    .unwrap();
    let mut events = parser.events();
    assert!(events.next().unwrap().is_ok()); // format description
    assert!(events.next().unwrap().is_ok()); // table map
    let err = events.next().unwrap().unwrap_err();
    let message = err.to_string();
    assert!(message.contains("jsonb nesting depth"), "{message}");
    assert!(
        message.contains(&format!("offset {rows_offset}")),
        "{message}"
    );
}

/// Flipping a byte inside the partial-JSON TLV region of a checksummed table
/// map fails with "event checksum mismatch": the CRC is verified on the
/// original bytes before the library ever sees the stripped table map.
#[test]
fn flipped_partial_json_tlv_byte_fails_the_checksum() {
    let build = |flip: bool| {
        let mut tme = table_map(1, true, true);
        if flip {
            // The TLV region ends the body; the PARTIAL_JSON_UPDATE (type 14)
            // value byte sits nine bytes before the end (TLV 15 occupies the
            // last four data bytes, the CRC the last four bytes overall).
            // Flipping a value byte keeps the TLV structure valid for the
            // pre-validation walk while breaking the CRC.
            let flip_index = tme.len() - 9;
            tme[flip_index] ^= 0xff;
        }
        binlog(&[format_description(), tme])
    };
    // Control: the intact table map parses.
    let mut parser = BinlogParser::open(build(false).path()).unwrap();
    assert!(parser.events().next().unwrap().is_ok()); // format description
    assert!(parser.events().next().unwrap().is_ok()); // table map

    let mut parser = BinlogParser::open(build(true).path()).unwrap();
    let mut events = parser.events();
    assert!(events.next().unwrap().is_ok()); // format description
    let err = events.next().unwrap().unwrap_err();
    assert!(err.to_string().contains("event checksum mismatch"), "{err}");
}

/// A diff that composes a document deeper than the nesting limit (path depth
/// plus inserted-value depth) is rejected before mutation and renders as a
/// loss-marked `partial_json` cell: the composite would overflow the stack
/// on drop or serialization if it were ever built (verification finding D1).
#[test]
fn composed_diff_depth_beyond_the_limit_is_loss_marked() {
    let mut diff = vec![0x00]; // REPLACE
    put_lenenc(&mut diff, 3); // path length
    diff.extend_from_slice(b"$.b");
    let value = deep_jsonb(100);
    put_lenenc(&mut diff, value.len() as u64);
    diff.extend_from_slice(&value);

    let mut parser_events = BinlogParser::open(
        binlog(&[
            format_description(),
            table_map(1, true, true),
            partial_update_rows(1, JSONB_DOC, &diff),
        ])
        .path(),
    )
    .unwrap();
    let mut events = parser_events.events();
    assert!(events.next().unwrap().is_ok()); // format description
    assert!(events.next().unwrap().is_ok()); // table map
    let event = events.next().unwrap().unwrap();
    let EventPayload::PartialUpdateRows { after, .. } = event.payload else {
        panic!("expected a partial update rows payload");
    };
    let after = after[0].as_ref().unwrap();
    let CellValue::PartialJson { diffs, reason } = &after.columns[1].value else {
        panic!(
            "expected a loss-marked JSON cell, got {:?}",
            after.columns[1].value
        );
    };
    assert_eq!(diffs.len(), 1);
    assert!(reason.contains("nesting limit"), "{reason}");
    assert!(events.next().is_none());
}

/// Binary jsonb for `{"a": 1, "b": [1]}`.
const JSONB_EDGE_BEFORE: &[u8] = &[
    0x00, 0x02, 0x00, 0x1b, 0x00, // small object, two members, 27 bytes
    0x12, 0x00, 0x01, 0x00, // key entry: "a" at offset 18, length 1
    0x13, 0x00, 0x01, 0x00, // key entry: "b" at offset 19, length 1
    0x05, 0x01, 0x00, // value entry: int16 1 (inlined)
    0x02, 0x14, 0x00, // value entry: small array payload at offset 20
    b'a', b'b', // key bytes at offsets 18, 19
    0x01, 0x00, 0x07, 0x00, // array payload: one element, 7 bytes
    0x05, 0x01, 0x00, // int16 1 (inlined)
];

/// The diff sequences of the edge-case tests: REPLACE `$.c` (a member the
/// before value does not have) and INSERT `$.b[1]` / `$.b[2]` (at and past
/// the end of the one-element array).
fn edge_case_diffs(insert_index: u8) -> Vec<u8> {
    let mut diffs = vec![0x00]; // REPLACE
    put_lenenc(&mut diffs, 3); // path "$.c"
    diffs.extend(b"$.c");
    put_lenenc(&mut diffs, 3); // int16 2
    diffs.extend([0x05, 2, 0x00]);
    diffs.push(0x01); // INSERT
    let path = format!("$.b[{insert_index}]");
    put_lenenc(&mut diffs, path.len() as u64);
    diffs.extend(path.as_bytes());
    put_lenenc(&mut diffs, 3); // int16 3
    diffs.extend([0x05, 3, 0x00]);
    diffs
}

/// The pinned JSON-diff edge-case semantics (see `row_decode`'s `json_diff`
/// module, mirroring MySQL's `sql/json_diff.cc`): object REPLACE behaves as
/// an upsert and array INSERT at index == length appends, while an INSERT
/// past the end cannot apply and renders as the loss-marking `partial_json`
/// value. Real server diffs always target existing paths.
#[test]
fn json_diff_edge_case_semantics_are_pinned() {
    let parse = |diffs: &[u8]| {
        let mut parser = BinlogParser::open(
            binlog(&[
                format_description(),
                table_map(1, true, true),
                partial_update_rows(1, JSONB_EDGE_BEFORE, diffs),
            ])
            .path(),
        )
        .unwrap();
        let mut events = parser.events();
        assert!(events.next().unwrap().is_ok()); // format description
        assert!(events.next().unwrap().is_ok()); // table map
        let event = events.next().unwrap().unwrap();
        assert_eq!(event.event_type, EventType::PartialUpdateRows);
        let EventPayload::PartialUpdateRows { after, .. } = event.payload else {
            panic!("expected a partial update rows payload");
        };
        after[0].as_ref().unwrap().columns[1].value.clone()
    };
    // REPLACE on a missing member upserts it; INSERT at index == len appends.
    assert_eq!(
        parse(&edge_case_diffs(1)),
        CellValue::Json(serde_json::json!({"a": 1, "b": [1, 3], "c": 2}))
    );
    // INSERT past the end is unappliable and stays a recorded loss.
    let CellValue::PartialJson { diffs, reason } = parse(&edge_case_diffs(2)) else {
        panic!("expected a partial JSON record");
    };
    assert_eq!(reason, "path `$.b[2]`: insert target is not applicable");
    assert_eq!(diffs.len(), 2);
    assert_eq!(diffs[1].path, "$.b[2]");
    assert_eq!(diffs[1].operation, "insert");
    assert_eq!(diffs[1].value, Some(serde_json::json!(3)));
}

/// A V1 write rows event (code 23, MySQL 5.5 era) is labeled `write_rows`
/// and decodes a full row payload like its V2 counterpart (code 30), and the
/// `--events write_rows` whitelist — the library `EventFilter` keyed on the
/// canonical event type — selects it.
#[test]
fn v1_write_rows_are_labeled_and_decoded() {
    let mut parser = BinlogParser::open(
        binlog(&[
            format_description(),
            table_map(1, false, true),
            v1_write_rows(1, 9, JSONB_DOC),
        ])
        .path(),
    )
    .unwrap();
    let mut events = parser.events();
    assert!(events.next().unwrap().is_ok()); // format description
    assert!(events.next().unwrap().is_ok()); // table map
    let event = events.next().unwrap().unwrap();
    assert_eq!(event.event_type_code, 23);
    assert_eq!(event.event_type, EventType::WriteRows);
    let EventPayload::Rows { changes, .. } = &event.payload else {
        panic!("expected rows payload");
    };
    let after = changes[0].after.as_ref().unwrap();
    assert_eq!(after.columns[0].value, CellValue::Int(9));
    assert_eq!(after.columns[0].signedness, Some(Signedness::Unsigned));
    assert_eq!(
        after.columns[1].value,
        CellValue::Json(serde_json::json!({"a": 1, "b": [1, 2]}))
    );
    let filter = EventFilter {
        kinds: [EventType::WriteRows].into_iter().collect(),
        ..Default::default()
    };
    assert!(filter.keep(&event));
}

/// The R48 aliased-jsonb bomb: `depth` chained small-array containers whose
/// two entries both point at the same next container; the last container
/// holds two inlined int16 leaves. Ten wire bytes per container plus the
/// top-level type byte decode into `2^(depth+1) - 1` serde nodes.
fn aliased_jsonb_bomb(depth: usize) -> Vec<u8> {
    let mut chain = [0x02, 0x00, 0x0a, 0x00, 0x05, 0x01, 0x00, 0x05, 0x01, 0x00].to_vec();
    for _ in 1..depth {
        let mut container = 2u16.to_le_bytes().to_vec();
        container.extend(((10 + chain.len()) as u16).to_le_bytes());
        // Both entries are small-array references to the same child at
        // offset 10 (relative to the element-count field).
        container.extend([0x02, 10, 0x00, 0x02, 10, 0x00]);
        container.extend_from_slice(&chain);
        chain = container;
    }
    let mut out = vec![0x02];
    out.extend_from_slice(&chain);
    out
}

/// The same aliased shape as the wire-properties corpus, through a JSON
/// column end to end: the rows event fails with the node-budget error at its
/// offset instead of amplifying into gigabytes (R48).
#[test]
fn aliased_jsonb_bomb_through_a_json_column_fails_at_its_offset() {
    let rows_offset = 4 + format_description().len() + table_map(1, false, false).len();
    let mut parser = BinlogParser::open(
        binlog(&[
            format_description(),
            table_map(1, false, false),
            write_rows(1, 7, &aliased_jsonb_bomb(22)),
        ])
        .path(),
    )
    .unwrap();
    let mut events = parser.events();
    assert!(events.next().unwrap().is_ok()); // format description
    assert!(events.next().unwrap().is_ok()); // table map
    let err = events.next().unwrap().unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("jsonb decoding exceeds the node budget of 1000000 nodes"),
        "{message}"
    );
    assert!(
        message.contains(&format!("offset {rows_offset}")),
        "{message}"
    );
    // The parser is fused after the error.
    assert!(events.next().is_none());
}

/// The aliased bomb as a partial-JSON diff value: the diff's value conversion
/// hits the shared node budget, the diff is preserved with its value dropped,
/// and the event still decodes as a loss record instead of amplifying or
/// failing (R48). The budget message itself is pinned at the `parse_diffs`
/// unit level in `row_decode`; re-application supersedes the provisional
/// reason with its own.
#[test]
fn aliased_jsonb_bomb_as_a_diff_value_is_loss_marked() {
    let bomb = aliased_jsonb_bomb(22);
    let mut diff = vec![0x00]; // REPLACE
    put_lenenc(&mut diff, 3); // path length
    diff.extend_from_slice(b"$.b");
    put_lenenc(&mut diff, bomb.len() as u64);
    diff.extend_from_slice(&bomb);
    let mut parser_events = BinlogParser::open(
        binlog(&[
            format_description(),
            table_map(1, true, true),
            partial_update_rows(1, JSONB_DOC, &diff),
        ])
        .path(),
    )
    .unwrap();
    let mut events = parser_events.events();
    assert!(events.next().unwrap().is_ok()); // format description
    assert!(events.next().unwrap().is_ok()); // table map
    let event = events.next().unwrap().unwrap();
    assert_eq!(event.event_type, EventType::PartialUpdateRows);
    let EventPayload::PartialUpdateRows { after, .. } = event.payload else {
        panic!("expected a partial update rows payload");
    };
    let after = after[0].as_ref().unwrap();
    let CellValue::PartialJson { diffs, reason } = &after.columns[1].value else {
        panic!(
            "expected a loss-marked JSON cell, got {:?}",
            after.columns[1].value
        );
    };
    assert_eq!(diffs.len(), 1);
    assert_eq!(diffs[0].path, "$.b");
    assert_eq!(diffs[0].operation, "replace");
    assert_eq!(diffs[0].value, None);
    assert!(reason.contains("carries no value"), "{reason}");
    assert!(events.next().is_none());
}

/// Re-registering a table id replaces the cached signedness: rows decoded
/// after the second table map carry the second registration's metadata, not
/// the first one's (the R42 signedness cache must be invalidated on
/// re-registration).
#[test]
fn re_registered_table_map_signedness_wins_for_subsequent_rows() {
    let mut parser_events = BinlogParser::open(
        binlog(&[
            format_description(),
            table_map(1, false, true), // SIGNEDNESS: the LONG column is unsigned
            write_rows(1, 7, JSONB_DOC),
            table_map(1, false, false), // re-registration without SIGNEDNESS
            write_rows(1, 8, JSONB_DOC),
        ])
        .path(),
    )
    .unwrap();
    let events = parser_events
        .events()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(events.len(), 5);
    let EventPayload::Rows { changes, .. } = &events[2].payload else {
        panic!("expected rows payload");
    };
    let first = changes[0].after.as_ref().unwrap();
    assert_eq!(first.columns[0].value, CellValue::Int(7));
    assert_eq!(first.columns[0].signedness, Some(Signedness::Unsigned));
    let EventPayload::Rows { changes, .. } = &events[4].payload else {
        panic!("expected rows payload");
    };
    let second = changes[0].after.as_ref().unwrap();
    assert_eq!(second.columns[0].value, CellValue::Int(8));
    assert_eq!(second.columns[0].signedness, Some(Signedness::Unknown));
}
