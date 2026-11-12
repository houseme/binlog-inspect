// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Performance acceptance harness (R42).
//!
//! Deterministic synthetic workloads timed end to end through the public
//! library API — no RNG and no real data; the byte-crafting techniques are
//! shared with `tests/wire_properties.rs`. Every test is `#[ignore]`d so the
//! normal suite stays fast; the acceptance run is
//!
//! ```sh
//! cargo test --locked --release --test perf_acceptance -- --ignored --nocapture
//! ```
//!
//! The harness asserts nothing about absolute speed: it prints one median per
//! metric for the "Performance Acceptance Record" section of EXECUTION.md and
//! checks structural invariants only (fixture shape, consumed event counts,
//! every diff applied), so each metric remains a correct test.

use binlog_inspect::{
    event::{CellValue, EventPayload},
    formatter::{CsvFormatter, Formatter, JsonLinesFormatter},
    parser::BinlogParser,
};
use std::{
    io::{self, Cursor, Write},
    time::{Duration, Instant},
};

/// Warmup executions before the timed runs (caches, page-ins, branch state).
const WARMUP_RUNS: usize = 3;
/// Timed executions per metric; the median of these is the recorded number.
const TIMED_RUNS: usize = 11;

// —— deterministic wire fixtures (techniques from tests/wire_properties.rs) ——

struct WireEvent {
    code: u8,
    body: Vec<u8>,
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

/// One checksummed event: a 19-byte header (artificial: zero timestamp and
/// log_pos), the body, and a CRC32 over the preceding bytes.
fn encode_event(event: &WireEvent) -> Vec<u8> {
    let size = 19 + event.body.len() + 4;
    let mut bytes = Vec::with_capacity(size);
    bytes.extend(123u32.to_le_bytes()); // timestamp
    bytes.push(event.code);
    bytes.extend(7u32.to_le_bytes()); // server id
    bytes.extend((size as u32).to_le_bytes());
    bytes.extend(0u32.to_le_bytes()); // log_pos: artificial events carry none
    bytes.extend(0u16.to_le_bytes()); // flags
    bytes.extend_from_slice(&event.body);
    bytes.extend(crc32(&bytes).to_le_bytes());
    bytes
}

/// The four-byte magic, a checksummed format description, then the events.
///
/// The format description leaves the post-header length array zeroed, so the
/// library reads row events with the V2 layout (6-byte table ids, an
/// extra-data length field) — exactly like the other crafted fixtures.
fn binlog(events: Vec<WireEvent>) -> Vec<u8> {
    let mut description = vec![0; 57];
    description[..2].copy_from_slice(&4u16.to_le_bytes());
    description[2..8].copy_from_slice(b"8.0.30");
    description[56] = 19;
    description.extend([0; 40]);
    description.push(1); // CRC32
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(encode_event(&WireEvent {
        code: 15,
        body: description,
    }));
    for event in &events {
        bytes.extend(encode_event(event));
    }
    bytes
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

/// The fixed part of a table map for `app`.`table` with the given types.
fn table_map_prefix(table_id: u64, table: &[u8], types: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&table_id.to_le_bytes()[..6]);
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.push(3); // database length
    body.extend_from_slice(b"app");
    body.push(0);
    body.push(table.len() as u8); // table name length
    body.extend_from_slice(table);
    body.push(0);
    body.push(types.len() as u8); // column count
    body.extend_from_slice(types);
    body
}

/// A table map for `app`.`t` with `columns` signed LONG columns, carrying
/// COLUMN_NAME and SIGNEDNESS optional metadata (bitmaps are MSB-first).
fn table_map_long(table_id: u64, columns: usize) -> WireEvent {
    let types = vec![0x03u8; columns]; // LONG
    let mut body = table_map_prefix(table_id, b"t", &types);
    body.push(0); // LONG columns have no column metadata
    let null_bitmap = vec![0u8; columns.div_ceil(8)];
    body.extend_from_slice(&null_bitmap);
    let mut meta = Vec::new();
    let mut names = Vec::new();
    for column in 0..columns {
        let name = format!("c{column}");
        names.push(name.len() as u8);
        names.extend_from_slice(name.as_bytes());
    }
    tlv(&mut meta, 4, &names); // COLUMN_NAME
    let signedness = vec![0u8; columns.div_ceil(8)]; // every column signed
    tlv(&mut meta, 1, &signedness); // SIGNEDNESS
    body.extend_from_slice(&meta);
    WireEvent { code: 19, body }
}

/// A table map for `app`.`p` with `columns` JSON columns carrying the
/// partial-JSON optional metadata (types 14 and 15) that the parser strips
/// before the library parses the event (R33).
fn table_map_json(table_id: u64, columns: usize) -> WireEvent {
    let types = vec![0xf5u8; columns]; // JSON
    let mut body = table_map_prefix(table_id, b"p", &types);
    let metadata = vec![4u8; columns]; // four-byte length prefixes
    put_lenenc(&mut body, metadata.len() as u64);
    body.extend_from_slice(&metadata);
    let null_bitmap = vec![0u8; columns.div_ceil(8)];
    body.extend_from_slice(&null_bitmap);
    let mut meta = Vec::new();
    let partial = vec![0xffu8; columns.div_ceil(8)]; // every JSON column partial
    tlv(&mut meta, 14, &partial); // PARTIAL_JSON_UPDATE
    tlv(&mut meta, 15, &types); // UPDATED_COLUMN_TYPES: one byte per column
    body.extend_from_slice(&meta);
    WireEvent { code: 19, body }
}

/// A write rows event (V2 layout, extra-data length field only) with `rows`
/// full images of four signed LONG columns; the value of column `c` of row
/// `r` is derived from the absolute row index so the data stays
/// deterministic without any randomness.
fn write_rows_long(table_id: u64, first_row: usize, rows: usize) -> WireEvent {
    const COLUMNS: usize = 4;
    let mut body = Vec::new();
    body.extend_from_slice(&table_id.to_le_bytes()[..6]);
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.extend_from_slice(&2u16.to_le_bytes()); // extra data length: the field alone
    body.push(COLUMNS as u8);
    body.push(0x0f); // all four columns present
    for row in first_row..first_row + rows {
        body.push(0); // null bitmap: nothing NULL
        for column in 0..COLUMNS {
            let value = (row * COLUMNS + column) as u32;
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
    WireEvent { code: 30, body }
}

/// An untagged GTID event: flags, sid, gno, logical-timestamp typecode, and
/// the two commit-order fields a real server writes.
fn gtid_event(gno: u64, last_committed: u64) -> WireEvent {
    let mut body = Vec::with_capacity(42);
    body.push(0); // flags
    body.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]); // sid
    body.extend_from_slice(&gno.to_le_bytes());
    body.push(2); // logical timestamp typecode
    body.extend_from_slice(&last_committed.to_le_bytes());
    body.extend_from_slice(&(last_committed + 1).to_le_bytes());
    WireEvent { code: 33, body }
}

/// A query event logging `BEGIN` on the fixture database.
fn query_begin() -> WireEvent {
    let mut body = Vec::with_capacity(22);
    body.extend_from_slice(&1u32.to_le_bytes()); // thread id
    body.extend_from_slice(&0u32.to_le_bytes()); // execution time
    body.push(3); // schema length
    body.extend_from_slice(&0u16.to_le_bytes()); // error code
    body.extend_from_slice(&0u16.to_le_bytes()); // status variables length
    body.extend_from_slice(b"app"); // schema
    body.push(0); // schema NUL terminator (the parser skips one byte)
    body.extend_from_slice(b"BEGIN");
    WireEvent { code: 2, body }
}

fn xid_event(xid: u64) -> WireEvent {
    WireEvent {
        code: 16,
        body: xid.to_le_bytes().to_vec(),
    }
}

// —— the partial-JSON diff workload ——

const DIFF_ROWS: usize = 1_000;
/// Rows per partial update rows event.
const ROWS_PER_EVENT: usize = 10;
const DIFF_EVENTS: usize = DIFF_ROWS / ROWS_PER_EVENT;
const JSON_COLUMNS: usize = 8;
const DIFFS_PER_COLUMN: usize = 4;
/// Members of each column's before document.
const MEMBERS: usize = 6;

/// The six member values of a column's before document (varies by column so
/// the spot-check below cannot pass on unchanged data).
fn before_values(column: usize) -> [i16; MEMBERS] {
    core::array::from_fn(|member| ((column * MEMBERS + member) * 3 + 7) as i16)
}

/// The int16 replacement value of one diff (varies by row so every cell's
/// application is distinct work).
fn diff_value(row: usize, column: usize, diff: usize) -> i16 {
    ((row * JSON_COLUMNS + column) * DIFFS_PER_COLUMN + diff) as i16
}

/// One column's diff sequence as stored in a partial JSON after image:
/// `DIFFS_PER_COLUMN` REPLACE operations on members `k0`.. with an inlined
/// int16 leaf each (type byte plus two value bytes).
fn diff_sequence(row: usize, column: usize) -> Vec<u8> {
    let mut diffs = Vec::new();
    for diff in 0..DIFFS_PER_COLUMN {
        let path = format!("$.k{diff}");
        let value = diff_value(row, column, diff).to_le_bytes();
        diffs.push(0x00); // REPLACE
        put_lenenc(&mut diffs, path.len() as u64);
        diffs.extend_from_slice(path.as_bytes());
        put_lenenc(&mut diffs, 3); // the int16 leaf
        diffs.push(0x05);
        diffs.extend_from_slice(&value);
    }
    diffs
}

/// Binary jsonb for `{"k0": v0, ..., "k5": v5}` — a small object with six
/// inlined int16 members (entry layout per tests/partial_json.rs: four-byte
/// key entries, three-byte value entries, offsets relative to the
/// element-count field).
fn six_member_object(values: &[i16; MEMBERS]) -> Vec<u8> {
    let mut body = vec![0x00]; // small object
    body.extend_from_slice(&(MEMBERS as u16).to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // size, patched below
    let keys = 4 + MEMBERS * 4 + MEMBERS * 3; // relative offset of the key bytes
    for member in 0..MEMBERS {
        body.extend_from_slice(&((keys + member * 2) as u16).to_le_bytes());
        body.extend_from_slice(&2u16.to_le_bytes());
    }
    for value in values {
        body.push(0x05); // inlined int16
        body.extend_from_slice(&value.to_le_bytes());
    }
    for member in 0..MEMBERS {
        body.push(b'k');
        body.push(b'0' + member as u8);
    }
    let size = (body.len() - 1) as u16; // counts from the element-count field on
    body[3..5].copy_from_slice(&size.to_le_bytes());
    body
}

/// A partial update rows event (code 39) with `rows` row pairs: the before
/// image holds a full document per JSON column, the after image starts with
/// the value options and the partial bitmap (WL#2955) and stores a diff
/// sequence per column instead of a full document.
fn partial_update_rows(table_id: u64, first_row: usize, rows: usize) -> WireEvent {
    let mut body = Vec::new();
    body.extend_from_slice(&table_id.to_le_bytes()[..6]);
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.extend_from_slice(&2u16.to_le_bytes()); // extra data length
    body.push(JSON_COLUMNS as u8);
    body.push(0xff); // before bitmap: all columns present
    body.push(0xff); // after bitmap: all columns present
    for row in first_row..first_row + rows {
        // Before image: a full row image.
        body.push(0); // null bitmap
        for column in 0..JSON_COLUMNS {
            let document = six_member_object(&before_values(column));
            body.extend_from_slice(&(document.len() as u32).to_le_bytes());
            body.extend_from_slice(&document);
        }
        // After image: value options, partial bitmap, null bitmap, then a
        // diff sequence per column.
        body.push(1); // value options: PARTIAL_JSON_UPDATES
        body.push(0xff); // partial bitmap: every JSON column is partial
        body.push(0); // null bitmap
        for column in 0..JSON_COLUMNS {
            let diffs = diff_sequence(row, column);
            body.extend_from_slice(&(diffs.len() as u32).to_le_bytes());
            body.extend_from_slice(&diffs);
        }
    }
    WireEvent { code: 39, body }
}

// —— fixtures and metrics ——

struct Fixture {
    bytes: Vec<u8>,
    /// Human-readable workload shape for the printed record.
    shape: String,
}

const FRAMING_TRANSACTIONS: usize = 3_333;
const FRAMING_ROWS_PER_EVENT: usize = 80;
const FRAMING_COLUMNS: usize = 4;
/// The format description plus six events per transaction.
const FRAMING_EVENTS: usize = 1 + FRAMING_TRANSACTIONS * 6;

/// The ~10 MB / ~20k-event transactional fixture: per transaction a gtid, a
/// `BEGIN` query, a table map, two 80-row write rows events and an xid, over
/// four signed LONG columns.
fn framing_fixture() -> Fixture {
    let mut events = Vec::with_capacity(FRAMING_EVENTS - 1);
    for transaction in 0..FRAMING_TRANSACTIONS {
        let base = transaction * FRAMING_ROWS_PER_EVENT * 2;
        events.push(gtid_event(transaction as u64 + 1, transaction as u64));
        events.push(query_begin());
        events.push(table_map_long(9, FRAMING_COLUMNS));
        events.push(write_rows_long(9, base, FRAMING_ROWS_PER_EVENT));
        events.push(write_rows_long(
            9,
            base + FRAMING_ROWS_PER_EVENT,
            FRAMING_ROWS_PER_EVENT,
        ));
        events.push(xid_event(transaction as u64 + 1));
    }
    assert_eq!(events.len() + 1, FRAMING_EVENTS, "fixture shape drifted");
    let bytes = binlog(events);
    assert!(
        (9 * 1024 * 1024..11 * 1024 * 1024).contains(&bytes.len()),
        "the framing fixture targets ~10 MB, got {} bytes",
        bytes.len()
    );
    Fixture {
        shape: format!("{FRAMING_EVENTS} events over {} bytes", bytes.len()),
        bytes,
    }
}

const CSV_EVENTS: usize = 10;
const CSV_ROWS_PER_EVENT: usize = 500;
const CSV_ROWS: usize = CSV_EVENTS * CSV_ROWS_PER_EVENT;

/// The CSV fixture: one table map plus ten write rows events of 500 rows
/// each — 5,000 row changes.
fn csv_fixture() -> Fixture {
    let mut events = Vec::with_capacity(CSV_EVENTS);
    events.push(table_map_long(9, FRAMING_COLUMNS));
    for event in 0..CSV_EVENTS {
        events.push(write_rows_long(
            9,
            event * CSV_ROWS_PER_EVENT,
            CSV_ROWS_PER_EVENT,
        ));
    }
    let bytes = binlog(events);
    Fixture {
        shape: format!("{CSV_ROWS} row changes over {} bytes", bytes.len()),
        bytes,
    }
}

/// The partial-JSON fixture: one table map with eight JSON columns plus 100
/// partial update events of 10 rows each — 1,000 rows x 8 columns x 4 diffs.
fn partial_json_fixture() -> Fixture {
    let mut events = Vec::with_capacity(DIFF_EVENTS);
    events.push(table_map_json(9, JSON_COLUMNS));
    for event in 0..DIFF_EVENTS {
        events.push(partial_update_rows(
            9,
            event * ROWS_PER_EVENT,
            ROWS_PER_EVENT,
        ));
    }
    let bytes = binlog(events);
    Fixture {
        shape: format!(
            "{DIFF_ROWS} rows x {JSON_COLUMNS} JSON columns x {DIFFS_PER_COLUMN} diffs \
             ({DIFF_EVENTS} events) over {} bytes",
            bytes.len()
        ),
        bytes,
    }
}

struct Metric {
    name: &'static str,
    fixture: fn() -> Fixture,
    /// Executes one full run; asserts structural invariants and returns a
    /// one-line confirmation of what was consumed.
    workload: fn(&[u8]) -> String,
}

/// Adding a metric later is one builder, one workload function, and one
/// entry here.
const METRICS: [Metric; 4] = [
    Metric {
        name: "framing_loop",
        fixture: framing_fixture,
        workload: run_framing_loop,
    },
    Metric {
        name: "jsonl_hot_loop",
        fixture: framing_fixture,
        workload: run_jsonl_hot_loop,
    },
    Metric {
        name: "partial_json_diffs",
        fixture: partial_json_fixture,
        workload: run_partial_json_diffs,
    },
    Metric {
        name: "csv_output",
        fixture: csv_fixture,
        workload: run_csv_output,
    },
];

/// Parse-only: drains every event of the fixture through the framing,
/// checksum and decoding pipeline without any formatter output.
fn run_framing_loop(bytes: &[u8]) -> String {
    let mut parser = BinlogParser::from_reader(Cursor::new(bytes)).expect("fixture framing");
    let mut events = 0usize;
    for event in parser.events() {
        event.expect("fixture parses");
        events += 1;
    }
    assert_eq!(events, FRAMING_EVENTS, "fixture shape drifted");
    format!("{events} events consumed")
}

/// The JSON Lines hot loop over the framing fixture (the R42 regression
/// metric): every event serialized straight into the sink.
fn run_jsonl_hot_loop(bytes: &[u8]) -> String {
    let mut parser = BinlogParser::from_reader(Cursor::new(bytes)).expect("fixture framing");
    let mut formatter = JsonLinesFormatter;
    let mut out = io::sink();
    let mut events = 0usize;
    for event in parser.events() {
        let event = event.expect("fixture parses");
        assert!(
            formatter.format(&event, &mut out).expect("sink writes"),
            "every event produces one JSON line"
        );
        events += 1;
    }
    assert_eq!(events, FRAMING_EVENTS, "fixture shape drifted");
    format!("{events} events serialized to JSON lines")
}

/// The partial-JSON diff path: 1,000 rows x 8 JSON columns x 4 REPLACE diffs
/// pinned through the `apply_pair` merge — every after cell must come back
/// as a full document with all members preserved.
fn run_partial_json_diffs(bytes: &[u8]) -> String {
    let mut parser = BinlogParser::from_reader(Cursor::new(bytes)).expect("fixture framing");
    let mut events = 0usize;
    let mut rows = 0usize;
    let mut cells = 0usize;
    for event in parser.events() {
        let event = event.expect("fixture parses");
        events += 1;
        let EventPayload::PartialUpdateRows { before, after, .. } = &event.payload else {
            continue;
        };
        assert_eq!(before.len(), after.len(), "both images decode");
        for (index, (before_row, after_row)) in before.iter().zip(after.iter()).enumerate() {
            let before_row = before_row.as_ref().expect("before image present");
            let after_row = after_row.as_ref().expect("after image present");
            rows += 1;
            assert_eq!(
                before_row.columns.len(),
                JSON_COLUMNS,
                "row {index} image shape drifted"
            );
            for column in 0..JSON_COLUMNS {
                let CellValue::Json(_) = &before_row.columns[column].value else {
                    panic!("before image holds full documents: row {index} column {column}");
                };
                let CellValue::Json(after_doc) = &after_row.columns[column].value else {
                    panic!("every diff applied: row {index} column {column}");
                };
                cells += 1;
                let members = after_doc.as_object().expect("document object").len();
                assert_eq!(
                    members, MEMBERS,
                    "members preserved: row {index} column {column}"
                );
            }
            // Spot-check one cell end to end: the first row's first column
            // replaced k0 with the row's first diff value and kept k4.
            if rows == 1 {
                let CellValue::Json(after_doc) = &after_row.columns[0].value else {
                    panic!("spot-check cell applied");
                };
                assert_eq!(after_doc["k0"], serde_json::json!(diff_value(0, 0, 0)));
                assert_eq!(after_doc["k4"], serde_json::json!(before_values(0)[4]));
                let CellValue::Json(before_doc) = &before_row.columns[0].value else {
                    panic!("spot-check before cell is a document");
                };
                assert_eq!(before_doc["k0"], serde_json::json!(before_values(0)[0]));
            }
        }
    }
    assert_eq!(events, DIFF_EVENTS + 2, "fixture shape drifted");
    assert_eq!(rows, DIFF_ROWS, "fixture shape drifted");
    assert_eq!(
        cells,
        DIFF_ROWS * JSON_COLUMNS,
        "every cell went through the diff path"
    );
    format!(
        "{rows} rows, {cells} JSON columns, {} diffs applied",
        rows * JSON_COLUMNS * DIFFS_PER_COLUMN
    )
}

/// The CSV output loop: the header line plus one record per row change of
/// the fixture, serialized through `CsvFormatter` into the sink.
fn run_csv_output(bytes: &[u8]) -> String {
    let mut parser = BinlogParser::from_reader(Cursor::new(bytes)).expect("fixture framing");
    let mut formatter = CsvFormatter;
    let mut out = io::sink();
    if let Some(header) = formatter.header() {
        out.write_all(header.as_bytes()).expect("sink writes");
        out.write_all(b"\n").expect("sink writes");
    }
    let mut events = 0usize;
    let mut rows = 0usize;
    let mut records = 0usize;
    for event in parser.events() {
        let event = event.expect("fixture parses");
        events += 1;
        if let EventPayload::Rows { changes, .. } = &event.payload {
            rows += changes.len();
        }
        if formatter.format(&event, &mut out).expect("sink writes") {
            records += 1;
        }
    }
    assert_eq!(events, CSV_EVENTS + 2, "fixture shape drifted");
    assert_eq!(rows, CSV_ROWS, "fixture shape drifted");
    assert_eq!(
        records, CSV_EVENTS,
        "every write rows event produced records"
    );
    format!("{rows} row changes serialized to CSV records")
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// Runs one metric: builds the fixture once, performs the warmups, times
/// eleven runs, and prints the median, the spread and the fixture-derived
/// throughput for the EXECUTION.md record.
fn bench(metric: &Metric) {
    let Fixture { bytes, shape } = (metric.fixture)();
    let workload = metric.workload;
    for _ in 0..WARMUP_RUNS {
        workload(&bytes);
    }
    let mut runs = Vec::with_capacity(TIMED_RUNS);
    let mut summary = String::new();
    for _ in 0..TIMED_RUNS {
        let start = Instant::now();
        summary = workload(&bytes);
        runs.push(start.elapsed());
    }
    runs.sort();
    let median = runs[TIMED_RUNS / 2];
    let mib_per_second = bytes.len() as f64 / median.as_secs_f64() / (1024.0 * 1024.0);
    println!(
        "{:<20} median {:>9.3} ms  min {:>9.3} ms  max {:>9.3} ms  {} | {:.1} MiB/s | {}",
        metric.name,
        ms(median),
        ms(runs[0]),
        ms(runs[TIMED_RUNS - 1]),
        shape,
        mib_per_second,
        summary,
    );
}

/// Runs every registered metric in order and prints the record line per
/// metric. Acceptance rules and the record format live in EXECUTION.md.
#[test]
#[ignore = "performance acceptance: run in release mode per EXECUTION.md (R42)"]
fn performance_acceptance_record() {
    println!("binlog-inspect performance acceptance harness (R42)");
    println!(
        "{WARMUP_RUNS} warmup runs and the median of {TIMED_RUNS} timed runs per metric; \
         all output is discarded to std::io::sink()"
    );
    println!("--");
    for metric in &METRICS {
        bench(metric);
    }
}
