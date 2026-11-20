// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Coverage-guided fuzzing of the JSON decoding paths through the public API.
//!
//! Each input drives two minimal synthetic binlogs built from the byte
//! layouts of `tests/partial_json.rs`:
//!
//! 1. **Full-document route** — a write-rows event carrying
//!    `<u32 length><input bytes>` as the value of a JSON column. The parser
//!    exercises the row decoder's jsonb conversion: container framing, the
//!    100-container depth cap, opaque member rendering, and the decoded-node
//!    budget.
//! 2. **Diff route** — a partial-update-rows event (WL#2955) whose after
//!    image carries `<u32 length><input bytes>` as the JSON column's diff
//!    sequence against a fixed before document. The parser then exercises
//!    `parse_diffs`, the diff value conversion, and the hand-written path
//!    parser and applier (`parse_path` / `apply_json_diffs`) — historically
//!    the riskiest string-processing code in the crate.
//!
//! This is the harness class that historically reproduced the ROADMAP R48
//! amplification: aliased jsonb offsets decoded a 221-byte value into
//! 8,388,607 nodes, and ~331 wire bytes demanded ~275 GB before the depth cap
//! ever fired. `-rss_limit_mb=2048` (see fuzz/README.md) turns any regression
//! of that class back into a libFuzzer OOM report instead of an allocator
//! abort that loses the repro.

#![no_main]

use libfuzzer_sys::fuzz_target;

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

/// One framed event with a CRC32 trailer (the checksummed-file layout).
fn raw_event(code: u8, body: &[u8]) -> Vec<u8> {
    let size = 19 + body.len() + 4; // header + body + CRC32
    let mut data = Vec::new();
    data.extend_from_slice(&0u32.to_le_bytes()); // timestamp
    data.push(code);
    data.extend_from_slice(&1u32.to_le_bytes()); // server id
    data.extend_from_slice(&(size as u32).to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes()); // log_pos
    data.extend_from_slice(&0u16.to_le_bytes()); // flags
    data.extend_from_slice(body);
    data.extend_from_slice(&crc32(&data).to_le_bytes());
    data
}

/// A checksummed format description enabling CRC32 event checksums, with the
/// post-header length array left zeroed (6-byte table ids, extra-data length
/// present in row events) — byte-for-byte the layout of tests/partial_json.rs.
fn format_description() -> Vec<u8> {
    let mut body = vec![0; 57];
    body[0..2].copy_from_slice(&4u16.to_le_bytes());
    body[2..8].copy_from_slice(b"8.0.30");
    body[56] = 19;
    body.extend([0; 40]);
    body.push(1); // checksum algorithm: CRC32
    raw_event(15, &body)
}

/// Table map for `d`.`t` with a single JSON column whose values use a
/// four-byte length prefix (the full-document route's map).
fn table_map() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1u64.to_le_bytes()[..6]); // table id
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.push(1); // database name length
    body.extend_from_slice(b"d\0");
    body.push(1); // table name length
    body.extend_from_slice(b"t\0");
    body.push(1); // one column
    body.push(0xf5); // JSON
    body.push(1); // metadata block length (lenenc)
    body.push(4); // JSON metadata: four-byte value length prefix
    body.push(1); // null bitmap
    raw_event(19, &body)
}

/// Table map for `d`.`t` with an unsigned LONG and a partial-update JSON
/// column, including the WL#2955 optional metadata types the crate strips
/// for the underlying library (the diff route's map).
fn partial_table_map() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1u64.to_le_bytes()[..6]); // table id
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.push(1); // database name length
    body.extend_from_slice(b"d\0");
    body.push(1); // table name length
    body.extend_from_slice(b"t\0");
    body.push(2); // two columns
    body.extend_from_slice(&[0x03, 0xf5]); // LONG, JSON
    body.extend_from_slice(&[1, 4]); // JSON uses a four-byte length prefix
    body.push(1); // null bitmap
    // Optional metadata: SIGNEDNESS (unsigned LONG), PARTIAL_JSON_UPDATE
    // (the JSON column is partial), UPDATED_COLUMN_TYPES (JSON stays JSON).
    body.extend_from_slice(&[1, 1, 0x80]);
    body.extend_from_slice(&[14, 1, 0x40]);
    body.extend_from_slice(&[15, 2, 0xf5, 0x00]);
    raw_event(19, &body)
}

/// Write rows event (code 30) inserting one row whose JSON column value is
/// `<u32 length><data>` — the fuzz input becomes the raw jsonb document.
fn write_rows(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1u64.to_le_bytes()[..6]); // table id
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.extend_from_slice(&2u16.to_le_bytes()); // extra data length
    body.push(1); // column count
    body.push(0x01); // present bitmap: the JSON column
    body.push(0); // null bitmap
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend_from_slice(data);
    raw_event(30, &body)
}

/// Partial update rows event (code 39): a full before image (LONG 7 plus the
/// fixed `{"a": 1, "b": [1, 2]}` document) and a partial after image whose
/// JSON column carries `<u32 length><data>` — the fuzz input becomes the raw
/// binlog JSON diff sequence, which `parse_diffs` and the path applier
/// consume.
fn partial_update_rows(diffs: &[u8]) -> Vec<u8> {
    let before_doc: &[u8] = &[
        0x00, 0x02, 0x00, 0x1e, 0x00, // small object, two members, 30 bytes
        0x12, 0x00, 0x01, 0x00, // key entry: "a" at offset 18, length 1
        0x13, 0x00, 0x01, 0x00, // key entry: "b" at offset 19, length 1
        0x05, 0x01, 0x00, // value entry: int16 1 (inlined)
        0x02, 0x14, 0x00, // value entry: small array at offset 20
        b'a', b'b', 0x02, 0x00, 0x0a, 0x00, 0x05, 0x01, 0x00, 0x05, 0x02, 0x00,
    ];
    let mut body = Vec::new();
    body.extend_from_slice(&1u64.to_le_bytes()[..6]); // table id
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.extend_from_slice(&2u16.to_le_bytes()); // extra data length
    body.push(2); // column count
    body.push(0x03); // before bitmap: both columns
    body.push(0x03); // after bitmap: both columns
    // Before image: null bitmap, LONG value, JSON document.
    body.push(0);
    body.extend_from_slice(&7u32.to_le_bytes());
    body.extend_from_slice(&(before_doc.len() as u32).to_le_bytes());
    body.extend_from_slice(before_doc);
    // After image: value options (PARTIAL_JSON_UPDATES), partial bitmap over
    // the JSON columns, null bitmap, LONG value, diff sequence.
    body.push(1);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&8u32.to_le_bytes());
    body.extend_from_slice(&(diffs.len() as u32).to_le_bytes());
    body.extend_from_slice(diffs);
    raw_event(39, &body)
}

/// Drives the whole collecting parse of one synthetic binlog.
fn parse_all(binlog: Vec<u8>) {
    if let Ok(mut parser) =
        binlog_inspect::parser::BinlogParser::from_reader(std::io::Cursor::new(binlog))
    {
        for event in parser.events() {
            // Errors are expected on hostile input; only crashes and
            // resource exhaustion are findings.
            let _ = event;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut full_document = b"\xfebin".to_vec();
    full_document.extend(format_description());
    full_document.extend(table_map());
    full_document.extend(write_rows(data));
    parse_all(full_document);

    let mut diff_route = b"\xfebin".to_vec();
    diff_route.extend(format_description());
    diff_route.extend(partial_table_map());
    diff_route.extend(partial_update_rows(data));
    parse_all(diff_route);
});
