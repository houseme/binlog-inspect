// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Coverage-guided fuzzing of the jsonb decoding path through the public API.
//!
//! The target wraps each input as the JSON column value of a minimal
//! synthetic binlog — the 4-byte magic, a checksummed format description that
//! enables CRC32 event checksums, a table map for `d`.`t` with one JSON
//! column, and one write-rows event carrying `<u32 length><input bytes>` as
//! the column value. The byte layouts mirror the fixtures of
//! tests/partial_json.rs. The parser then exercises the row decoder's jsonb
//! conversion: container framing, the 100-container depth cap, opaque member
//! rendering, and the decoded-node budget.
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
/// four-byte length prefix (optional metadata is not needed for the target).
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

fuzz_target!(|data: &[u8]| {
    let mut binlog = b"\xfebin".to_vec();
    binlog.extend(format_description());
    binlog.extend(table_map());
    binlog.extend(write_rows(data));
    if let Ok(mut parser) =
        binlog_inspect::parser::BinlogParser::from_reader(std::io::Cursor::new(binlog))
    {
        for event in parser.events() {
            // Errors are expected on hostile input; only crashes and
            // resource exhaustion are findings.
            let _ = event;
        }
    }
});
