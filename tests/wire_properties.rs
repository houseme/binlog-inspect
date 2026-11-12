// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Deterministic, bounded wire-format properties exercised through the public parser.
//!
//! The seed, family, case and mutation are printed on failure. These cases use
//! synthetic data and run on stable with either feature configuration. They
//! complement coverage-guided fuzzing: they do not generate arbitrary format
//! descriptions or compressed streams, and the resource-amplifying JSONB
//! shapes (R48) are covered by dedicated budget-bounded fixtures below.

use binlog_inspect::{
    event::{CellValue, EventPayload, EventType, ParsedEvent},
    parser::{BinlogParser, ParserError},
};
use mysql_common::{
    binlog::{consts::TransactionPayloadCompressionType, events::TransactionPayloadEvent},
    proto::MySerialize,
};
use std::io::{self, Cursor, Read};

const SEED: u64 = 0x5247_3437_6269_6e6c;
const EVENT_CAP: u32 = 4096;
/// Event cap for the large legitimate and bomb fixtures of the R50/R48
/// refinement acceptance, which exceed the mutation-corpus cap above.
const LARGE_EVENT_CAP: u32 = 1 << 16;
const CASES_PER_FAMILY: usize = 24;
const FAMILIES: [&str; 4] = [
    "previous_gtids",
    "table_map",
    "transaction_payload",
    "jsonb",
];

struct Generator(u64);

impl Generator {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit as u64) as usize
    }
}

#[derive(Clone)]
struct WireEvent {
    code: u8,
    body: Vec<u8>,
}

struct Fixture {
    events: Vec<WireEvent>,
    expected_cells: Vec<CellValue>,
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

fn encode_event(event: &WireEvent, checksum: bool) -> Vec<u8> {
    encode_event_within(event, checksum, EVENT_CAP)
}

/// The same framing with a larger cap, for the large acceptance fixtures.
fn encode_event_within(event: &WireEvent, checksum: bool, cap: u32) -> Vec<u8> {
    let size = 19 + event.body.len() + usize::from(checksum) * 4;
    assert!(size <= cap as usize);
    let mut bytes = Vec::with_capacity(size);
    bytes.extend(123u32.to_le_bytes());
    bytes.push(event.code);
    bytes.extend(7u32.to_le_bytes());
    bytes.extend((size as u32).to_le_bytes());
    bytes.extend(0u32.to_le_bytes()); // Artificial events have no log_pos.
    bytes.extend(0u16.to_le_bytes());
    bytes.extend_from_slice(&event.body);
    if checksum {
        bytes.extend(crc32(&bytes).to_le_bytes());
    }
    bytes
}

fn binlog(events: &[WireEvent]) -> Vec<u8> {
    let mut bytes = b"\xfebin".to_vec();
    let mut description = vec![0; 57];
    description[..2].copy_from_slice(&4u16.to_le_bytes());
    description[2..8].copy_from_slice(b"8.0.30");
    description[56] = 19;
    description.extend([0; 40]);
    description.push(1); // CRC32
    bytes.extend(encode_event(
        &WireEvent {
            code: 15,
            body: description,
        },
        true,
    ));
    for event in events {
        bytes.extend(encode_event(event, true));
    }
    bytes
}

/// The same framing with the large per-event cap of the acceptance fixtures.
fn binlog_large(events: &[WireEvent]) -> Vec<u8> {
    let mut bytes = b"\xfebin".to_vec();
    let mut description = vec![0; 57];
    description[..2].copy_from_slice(&4u16.to_le_bytes());
    description[2..8].copy_from_slice(b"8.0.30");
    description[56] = 19;
    description.extend([0; 40]);
    description.push(1); // CRC32
    bytes.extend(encode_event_within(
        &WireEvent {
            code: 15,
            body: description,
        },
        true,
        LARGE_EVENT_CAP,
    ));
    for event in events {
        bytes.extend(encode_event_within(event, true, LARGE_EVENT_CAP));
    }
    bytes
}

fn table_map(column_type: u8, metadata: &[u8]) -> WireEvent {
    let mut body = vec![1, 0, 0, 0, 0, 0, 0, 0]; // Table id and flags.
    body.extend_from_slice(b"\x03app\0\x01t\0");
    body.extend([1, column_type, metadata.len() as u8]);
    body.extend_from_slice(metadata);
    body.push(0); // NULL bitmap.
    body.extend([4, 2, 1, b'v']); // COLUMN_NAME, one name.
    if column_type == 3 {
        body.extend([1, 1, 0]); // SIGNEDNESS, signed LONG.
    }
    // Exercise the metadata that is validated and stripped before the library.
    body.extend([14, 1, 0, 15, 1, column_type]);
    WireEvent { code: 19, body }
}

fn row_event(values: &[Vec<u8>]) -> WireEvent {
    let mut body = vec![1, 0, 0, 0, 0, 0, 0, 0];
    body.extend([2, 0, 1, 1]); // Extra-data length, column count, bitmap.
    for value in values {
        body.push(0); // This row's NULL bitmap.
        body.extend_from_slice(value);
    }
    WireEvent { code: 30, body }
}

fn integer_rows(generator: &mut Generator) -> (WireEvent, Vec<CellValue>) {
    let values: Vec<i32> = (0..1 + generator.below(3))
        .map(|_| generator.next() as i32)
        .collect();
    let wire_values: Vec<Vec<u8>> = values
        .iter()
        .map(|value| value.to_le_bytes().to_vec())
        .collect();
    let expected = values
        .iter()
        .map(|&value| CellValue::Int(i64::from(value)))
        .collect();
    (row_event(&wire_values), expected)
}

fn previous_gtids(generator: &mut Generator) -> WireEvent {
    let count = 1 + generator.below(3);
    let tagged = generator.below(2) == 0;
    let header = if tagged {
        (1u64 << 56) | ((count as u64) << 8) | 1
    } else {
        count as u64
    };
    let mut body = header.to_le_bytes().to_vec();
    for _ in 0..count {
        body.extend(generator.next().to_le_bytes());
        body.extend(generator.next().to_le_bytes());
        if tagged {
            let tag = format!("tag_{:04x}", generator.next() as u16);
            // MySQL serialization varlen integers encode short lengths << 1.
            body.push((tag.len() as u8) << 1);
            body.extend_from_slice(tag.as_bytes());
        }
        let intervals = 1 + generator.below(3);
        body.extend((intervals as u64).to_le_bytes());
        let mut start = 1 + generator.next() % 50;
        for _ in 0..intervals {
            let end = start + 1 + generator.next() % 20;
            body.extend(start.to_le_bytes());
            body.extend(end.to_le_bytes());
            start = end + generator.next() % 3;
        }
    }
    WireEvent { code: 35, body }
}

fn json_document(generator: &mut Generator) -> (Vec<u8>, serde_json::Value) {
    let number = generator.next() as i16;
    let text = format!("v\"\\\n-{:04x}😀", generator.next() as u16);
    assert!(text.len() < 128);
    // Small object {"n": number, "s": text}; entry offsets count from
    // the element-count field, excluding the JSONB type byte.
    let mut body = vec![2, 0, 0, 0, 18, 0, 1, 0, 19, 0, 1, 0, 5];
    body.extend(number.to_le_bytes());
    body.extend([12, 20, 0, b'n', b's', text.len() as u8]);
    body.extend_from_slice(text.as_bytes());
    let size = body.len() as u16;
    body[2..4].copy_from_slice(&size.to_le_bytes());
    let mut kind = 0; // Small object.
    let mut expected = serde_json::json!({"n": number, "s": text});
    // Each container owns a distinct child. Keep depth below five and never
    // manufacture aliasing offsets that could expand a tiny input repeatedly.
    for _ in 0..generator.below(4) {
        let size = (7 + body.len()) as u16;
        let mut parent = vec![1, 0];
        parent.extend(size.to_le_bytes());
        parent.extend([kind, 7, 0]);
        parent.extend(body);
        body = parent;
        kind = 2; // Small array.
        expected = serde_json::Value::Array(vec![expected]);
    }
    body.insert(0, kind);
    (body, expected)
}

fn fixture(family: &str, generator: &mut Generator) -> Fixture {
    match family {
        "previous_gtids" => Fixture {
            events: vec![previous_gtids(generator)],
            expected_cells: Vec::new(),
        },
        "table_map" => {
            let (rows, expected_cells) = integer_rows(generator);
            Fixture {
                events: vec![table_map(3, &[]), rows],
                expected_cells,
            }
        }
        "transaction_payload" => {
            let (rows, cells) = integer_rows(generator);
            let mut inner = encode_event(&table_map(3, &[]), false);
            inner.extend(encode_event(&rows, false));
            for _ in 0..1 + generator.below(4) {
                inner.extend(encode_event(
                    &WireEvent {
                        code: 16,
                        body: generator.next().to_le_bytes().to_vec(),
                    },
                    false,
                ));
            }
            let payload = TransactionPayloadEvent::new(
                inner.len() as u64,
                TransactionPayloadCompressionType::NONE,
                0,
                inner,
            );
            let mut body = Vec::new();
            payload.serialize(&mut body);
            Fixture {
                // The later outer row also checks that inner table maps persist.
                events: vec![WireEvent { code: 40, body }, rows],
                expected_cells: [cells.clone(), cells].concat(),
            }
        }
        "jsonb" => {
            let (jsonb, expected) = json_document(generator);
            let mut value = (jsonb.len() as u32).to_le_bytes().to_vec();
            value.extend(jsonb);
            Fixture {
                events: vec![table_map(245, &[4]), row_event(&[value])],
                expected_cells: vec![CellValue::Json(expected)],
            }
        }
        _ => unreachable!("the family list is fixed"),
    }
}

struct ShortReader<'a> {
    input: Cursor<&'a [u8]>,
    chunk: usize,
}

impl Read for ShortReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = out.len().min(self.chunk);
        self.input.read(&mut out[..count])
    }
}

#[derive(Debug, PartialEq)]
struct Outcome {
    events: Vec<ParsedEvent>,
    error: Option<String>,
}

fn check_event(event: &ParsedEvent) {
    check_event_within(event, EVENT_CAP);
}

fn check_event_within(event: &ParsedEvent, cap: u32) {
    assert!((19..=cap).contains(&event.event_size));
    let json = serde_json::to_vec(event).unwrap();
    let decoded: ParsedEvent = serde_json::from_slice(&json).unwrap();
    assert_eq!(&decoded, event);
    if let EventPayload::TransactionPayload { events, .. } = &event.payload {
        let mut offset = 0;
        for inner in events {
            assert_eq!(inner.offset, offset);
            offset += u64::from(inner.event_size);
            check_event(inner);
        }
    }
}

fn parse(bytes: &[u8], chunk: usize, context: &str) -> Outcome {
    parse_with_cap(bytes, chunk, EVENT_CAP, context)
}

/// The same harness with a larger per-event cap, for the acceptance fixtures
/// whose wire size exceeds [`EVENT_CAP`].
fn parse_with_cap(bytes: &[u8], chunk: usize, cap: u32, context: &str) -> Outcome {
    std::panic::catch_unwind(|| {
        let reader = ShortReader {
            input: Cursor::new(bytes),
            chunk,
        };
        let mut parser = match BinlogParser::from_reader(reader) {
            Ok(parser) => parser.with_max_event_size(cap),
            Err(error) => {
                return Outcome {
                    events: Vec::new(),
                    error: Some(error.to_string()),
                };
            }
        };
        let mut outcome = Outcome {
            events: Vec::new(),
            error: None,
        };
        let mut offset = 4;
        for result in parser.events() {
            match result {
                Ok(event) => {
                    assert_eq!(event.offset, offset);
                    offset += u64::from(event.event_size);
                    assert!(offset <= bytes.len() as u64);
                    check_event_within(&event, cap);
                    outcome.events.push(event);
                    assert!(outcome.events.len() <= bytes.len() / 19);
                }
                Err(error) => {
                    outcome.error = Some(error.to_string());
                    break;
                }
            }
        }
        assert!(
            parser.events().next().is_none(),
            "stream must stay exhausted"
        );
        outcome
    })
    .unwrap_or_else(|_| panic!("seed={SEED:#x} {context} chunk={chunk}"))
}

fn collect_cells(events: &[ParsedEvent], cells: &mut Vec<CellValue>) {
    for event in events {
        match &event.payload {
            EventPayload::Rows { changes, .. } => {
                for change in changes {
                    let after = change
                        .after
                        .as_ref()
                        .expect("generated write row has an image");
                    cells.push(after.columns[0].value.clone());
                }
            }
            EventPayload::TransactionPayload { events, .. } => collect_cells(events, cells),
            _ => (),
        }
    }
}

#[test]
fn generated_events_preserve_values_and_short_read_results() {
    let mut generator = Generator(SEED);
    for family in FAMILIES {
        for case in 0..CASES_PER_FAMILY {
            let fixture = fixture(family, &mut generator);
            let bytes = binlog(&fixture.events);
            let context = format!("family={family} case={case} mutation=none");
            let expected = parse(&bytes, bytes.len(), &context);
            assert!(
                expected.error.is_none(),
                "seed={SEED:#x} {context}: {expected:?}"
            );
            assert_eq!(expected.events.len(), fixture.events.len() + 1, "{context}");
            for (decoded, wire) in expected.events[1..].iter().zip(&fixture.events) {
                assert_eq!(
                    decoded.event_type,
                    EventType::from_raw(wire.code),
                    "{context}"
                );
                if wire.code == 35 {
                    assert!(
                        matches!(&decoded.payload,
                        EventPayload::PreviousGtids { gtid_set } if !gtid_set.is_empty()),
                        "seed={SEED:#x} {context}"
                    );
                }
            }
            let mut cells = Vec::new();
            collect_cells(&expected.events, &mut cells);
            assert_eq!(cells, fixture.expected_cells, "seed={SEED:#x} {context}");
            for chunk in 1..=17 {
                assert_eq!(
                    parse(&bytes, chunk, &context),
                    expected,
                    "seed={SEED:#x} {context} chunk={chunk}"
                );
            }
        }
    }
}

#[test]
fn bounded_wire_mutations_and_truncations_are_deterministic_and_fused() {
    let mut generator = Generator(SEED);
    for family in FAMILIES {
        for case in 0..CASES_PER_FAMILY {
            let fixture = fixture(family, &mut generator);
            let bytes = binlog(&fixture.events);
            for cut in (0..bytes.len())
                .step_by((bytes.len() / 8).max(1))
                .chain([bytes.len() - 1])
            {
                let context = format!("family={family} case={case} mutation=file-prefix-{cut}");
                let expected = parse(&bytes[..cut], bytes.len(), &context);
                assert_eq!(
                    parse(&bytes[..cut], 1 + generator.below(17), &context),
                    expected,
                    "seed={SEED:#x} {context}"
                );
            }
            for mutation in 0..16 {
                let mut events = fixture.events.clone();
                let target = generator.below(events.len());
                let body = &mut events[target].body;
                let index = generator.below(body.len());
                if mutation < 8 {
                    body[index] ^= 1 << generator.below(8);
                } else {
                    body[index] = [0, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x80][mutation - 8];
                }
                let context = format!(
                    "family={family} case={case} mutation=bit-{mutation} event={target} byte={index}"
                );
                // Recompute framing and CRC so mutations reach the wire
                // validators and decoders instead of only the checksum gate.
                let mutated = binlog(&events);
                let expected = parse(&mutated, mutated.len(), &context);
                assert_eq!(
                    parse(&mutated, 1 + generator.below(17), &context),
                    expected,
                    "seed={SEED:#x} {context}"
                );
            }
            for target in 0..fixture.events.len() {
                let length = fixture.events[target].body.len();
                for cut in (0..length).step_by((length / 4).max(1)) {
                    let mut events = fixture.events.clone();
                    events[target].body.truncate(cut);
                    let context = format!(
                        "family={family} case={case} mutation=body-prefix-{cut} event={target}"
                    );
                    // Keep the outer frame valid to exercise partial fields
                    // inside the wire-format validators and the library.
                    let mutated = binlog(&events);
                    let expected = parse(&mutated, mutated.len(), &context);
                    assert_eq!(
                        parse(&mutated, 1 + generator.below(17), &context),
                        expected,
                        "seed={SEED:#x} {context}"
                    );
                }
            }
        }
    }
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

/// The event sizes of the fixed corpus framing: the format description body
/// is 57 + 40 + 1 bytes, and every event carries a 19-byte header plus a
/// 4-byte CRC32.
fn format_description_size() -> u32 {
    19 + 98 + 4
}

/// The 221-byte aliased-jsonb reproduction of the R48 amplification: 22
/// chained small-array containers, both entries of each pointing at the same
/// child, used to decode into 2^23 - 1 = 8,388,607 serde nodes. The decoded
/// node budgets turn the amplification into a clean error at the rows event
/// instead of an allocation runaway. For this event's wire size the shared
/// per-event budget (R48-refinement) is the tighter of the two and stops the
/// conversion first; the per-value budget's message is pinned by the
/// `row_decode` unit tests, which run it at the 4M per-event maximum.
#[test]
fn aliased_jsonb_bomb_is_rejected_by_the_node_budget() {
    let bomb = aliased_jsonb_bomb(22);
    assert_eq!(bomb.len(), 221);
    let mut value = (bomb.len() as u32).to_le_bytes().to_vec();
    value.extend_from_slice(&bomb);
    let tme = table_map(245, &[4]);
    let rows = row_event(&[value]);
    let bytes = binlog(&[tme.clone(), rows.clone()]);
    let rows_offset = 4 + format_description_size() + (19 + tme.body.len() + 4) as u32;
    let event_size = 19 + rows.body.len() + 4;
    let expected_budget = (16 * event_size).min(4_000_000);
    let context = "aliased-jsonb-bomb";
    let outcome = parse(&bytes, bytes.len(), context);
    assert_eq!(
        outcome.events.len(),
        2,
        "{context}: the format description and table map still decode: {outcome:?}"
    );
    let error = outcome
        .error
        .clone()
        .unwrap_or_else(|| panic!("{context}: the bomb must fail the rows event"));
    assert!(
        error.contains(&format!(
            "jsonb decoding in this event exceeds the per-event node budget of {expected_budget} nodes"
        )),
        "{error}"
    );
    assert!(
        error.contains(&format!("binlog error at offset {rows_offset}")),
        "{error}"
    );
    // The error is deterministic across chunked reads too.
    assert_eq!(parse(&bytes, 9, context), outcome, "{context}");
}

/// A hostile single-container jsonb whose declared element count is 0xffff_ffff
/// while the container declares only its 8-byte header: no element bytes exist
/// and no pre-allocation from the untrusted count may abort the process. The
/// library's structural check rejects the shape cleanly.
#[test]
fn hostile_container_element_count_is_rejected_cleanly() {
    // JSONB_TYPE_LARGE_ARRAY, element count 0xffff_ffff, size 8 (the header
    // alone) — the declared entries cannot exist in 9 wire bytes.
    let jsonb = [0x03, 0xff, 0xff, 0xff, 0xff, 0x08, 0x00, 0x00, 0x00];
    let mut value = (jsonb.len() as u32).to_le_bytes().to_vec();
    value.extend_from_slice(&jsonb);
    let bytes = binlog(&[table_map(245, &[4]), row_event(&[value])]);
    let context = "hostile-element-count";
    let outcome = parse(&bytes, bytes.len(), context);
    assert_eq!(
        outcome.events.len(),
        2,
        "{context}: the format description and table map still decode: {outcome:?}"
    );
    let error = outcome
        .error
        .clone()
        .unwrap_or_else(|| panic!("{context}: the hostile count must fail the rows event"));
    assert!(error.contains("Malformed jsonb"), "{error}");
    // The same bytes survive chunked reads with the identical outcome.
    assert_eq!(parse(&bytes, 5, context), outcome, "{context}");
}

/// The library-level `with_max_event_size` constructor (R21): a custom cap
/// smaller than a crafted event rejects exactly that event with the
/// oversized-event error while the earlier events still decode.
#[test]
fn with_max_event_size_rejects_events_above_the_custom_cap() {
    let tme = table_map(3, &[]);
    // A row event of 19 + body + CRC bytes with a padded value, so its frame
    // is larger than the format description and the table map.
    let big_value = vec![0x11; 200];
    let rows = row_event(&[big_value]);
    let bytes = binlog(&[tme.clone(), rows.clone()]);
    let rows_offset = 4 + format_description_size() + (19 + tme.body.len() + 4) as u32;
    // 121-byte format description and 56-byte table map fit; the row event
    // does not.
    let mut parser = BinlogParser::from_reader(Cursor::new(&bytes[..]))
        .unwrap()
        .with_max_event_size(130);
    let mut events = parser.events();
    assert!(events.next().unwrap().is_ok(), "format description");
    assert!(events.next().unwrap().is_ok(), "table map");
    let error = events.next().expect("the row event is framed").unwrap_err();
    assert!(
        matches!(
            error,
            ParserError::OversizedEvent { offset: rows_offset_event, size, limit: 130 }
                if rows_offset_event == u64::from(rows_offset)
                    && size == u32::try_from(19 + rows.body.len() + 4).unwrap()
        ),
        "{error}"
    );
    assert!(
        error.to_string().contains(&format!(
            "binlog error at offset {rows_offset}: invalid or oversized event"
        )),
        "{error}"
    );
    // The parser is fused after the error.
    assert!(events.next().is_none());
}

/// One-column table map for `db`.`t` (table id 5) carrying `metadata`, in the
/// byte layout of the round-3 R50 reproduction fixtures.
fn one_column_table_map(column_type: u8, metadata: &[u8]) -> WireEvent {
    let mut body = vec![5, 0, 0, 0, 0, 0, 0, 0]; // Table id 5 and flags.
    body.extend_from_slice(b"\x02db\0\x01t\0");
    body.push(1); // One column.
    body.push(column_type);
    body.push(metadata.len() as u8);
    body.extend_from_slice(metadata);
    body.push(1); // NULL bitmap.
    WireEvent { code: 19, body }
}

/// A write-rows event over the one-column table map, each slice one row's
/// value bytes (every row's NULL bitmap marks the column as not NULL).
fn one_column_write_rows(rows: &[&[u8]]) -> WireEvent {
    let mut body = vec![5, 0, 0, 0, 0, 0, 0, 0]; // Table id 5 and flags.
    body.extend([2, 0]); // Extra-data length (none).
    body.push(1); // One column.
    body.push(0x01); // The column is present.
    for row in rows {
        body.push(0x00); // This row's NULL bitmap: not NULL.
        body.extend_from_slice(row);
    }
    WireEvent { code: 30, body }
}

/// R50: a table map declaring NEWDECIMAL metadata with `scale > precision`
/// aborts the process inside the dependency's `decimal_bin_size` (a debug
/// panic through `precision - scale` underflow, a release allocator abort
/// from the wrapped size). The registration check rejects it with the
/// documented message before any row is decoded.
#[test]
fn decimal_scale_gt_precision_metadata_is_rejected_at_registration() {
    let bytes = binlog(&[
        one_column_table_map(0xf6, &[1, 200]), // precision 1, scale 200
        one_column_write_rows(&[&[0x01, 0x02, 0x03, 0x04]]),
    ]);
    let context = "decimal-scale-gt-precision";
    let outcome = parse(&bytes, bytes.len(), context);
    assert_eq!(
        outcome.events.len(),
        1,
        "{context}: only the format description decodes: {outcome:?}"
    );
    let error = outcome
        .error
        .clone()
        .unwrap_or_else(|| panic!("{context}: the table map must fail"));
    assert!(
        error.contains(
            "table map column metadata for column 0: NEWDECIMAL scale 200 exceeds precision 1"
        ),
        "{error}"
    );
    // The same outcome under chunked reads; parse() asserts the parser is
    // fused afterwards.
    assert_eq!(parse(&bytes, 7, context), outcome, "{context}");
}

/// R50: with valid metadata, hostile packed digit groups overflow the
/// dependency's scaling multiply (a debug panic; a release build wraps the
/// overflow into silently wrong output). The row-layout walk rejects the
/// span with the documented message before the library reads it, while the
/// legitimate decimal of the same shape still decodes byte-identically.
#[test]
fn hostile_decimal_digit_groups_are_rejected_before_the_library() {
    let context = "decimal-hostile-group";
    let bytes = binlog(&[
        one_column_table_map(0xf6, &[5, 5]), // precision 5, scale 5
        one_column_write_rows(&[&[0xff, 0xff, 0xff]]),
    ]);
    let outcome = parse(&bytes, bytes.len(), context);
    assert_eq!(
        outcome.events.len(),
        2,
        "{context}: the format description and table map still decode: {outcome:?}"
    );
    let error = outcome
        .error
        .clone()
        .unwrap_or_else(|| panic!("{context}: the rows event must fail"));
    assert!(
        error.contains("malformed NEWDECIMAL value in column 0: digit group exceeds 5 digits"),
        "{error}"
    );
    assert_eq!(parse(&bytes, 11, context), outcome, "{context}");

    // The legitimate control from the same reproduction set: precision 5,
    // scale 2, value 1.23, renders unchanged.
    let context = "decimal-legit";
    let legit = binlog(&[
        one_column_table_map(0xf6, &[5, 2]),
        one_column_write_rows(&[&[0x80, 0x01, 0x17]]),
    ]);
    let outcome = parse(&legit, legit.len(), context);
    assert!(
        outcome.error.is_none(),
        "{context}: the legitimate decimal must decode: {outcome:?}"
    );
    let mut cells = Vec::new();
    collect_cells(&outcome.events, &mut cells);
    assert_eq!(
        cells,
        vec![CellValue::Bytes("312e3233".into())],
        "{context}: the value renders as the hex of \"1.23\""
    );
}

/// R50: a fractional-second precision above six shifts every later column of
/// a row by bytes the dependency reads past its own declared widths; it is
/// rejected at registration with the documented message.
#[test]
fn fractional_second_precision_above_six_is_rejected_at_registration() {
    let bytes = binlog(&[
        one_column_table_map(0x11, &[7]), // TIMESTAMP2, fsp 7
        one_column_write_rows(&[&[0x00, 0x00, 0x04, 0x50]]),
    ]);
    let context = "timestamp2-fsp7";
    let outcome = parse(&bytes, bytes.len(), context);
    assert_eq!(
        outcome.events.len(),
        1,
        "{context}: only the format description decodes: {outcome:?}"
    );
    let error = outcome
        .error
        .clone()
        .unwrap_or_else(|| panic!("{context}: the table map must fail"));
    assert!(
        error.contains(
            "table map column metadata for column 0: fractional-second precision 7 outside 0..=6"
        ),
        "{error}"
    );
    assert_eq!(parse(&bytes, 13, context), outcome, "{context}");
}

/// R50: a TIMESTAMP2 fraction byte the server could not have written (0xff
/// for fsp 2) is recombined by the dependency through a signed integer and
/// renders a wrong negative time; the walk rejects it with the documented
/// message, and a legitimate fraction still decodes.
#[test]
fn overflowing_timestamp2_fraction_is_rejected() {
    let context = "timestamp2-frac-overflow";
    let bytes = binlog(&[
        one_column_table_map(0x11, &[2]), // TIMESTAMP2, fsp 2
        one_column_write_rows(&[&[0x00, 0x00, 0x04, 0x50, 0xff]]),
    ]);
    let outcome = parse(&bytes, bytes.len(), context);
    assert_eq!(
        outcome.events.len(),
        2,
        "{context}: the format description and table map still decode: {outcome:?}"
    );
    let error = outcome
        .error
        .clone()
        .unwrap_or_else(|| panic!("{context}: the rows event must fail"));
    assert!(
        error.contains("malformed TIMESTAMP2 fraction in column 0"),
        "{error}"
    );
    assert_eq!(parse(&bytes, 5, context), outcome, "{context}");

    // The same event with an in-range fraction byte decodes.
    let context = "timestamp2-frac-legit";
    let legit = binlog(&[
        one_column_table_map(0x11, &[2]),
        one_column_write_rows(&[&[0x00, 0x00, 0x04, 0x50, 0x63]]),
    ]);
    let outcome = parse(&legit, legit.len(), context);
    assert!(
        outcome.error.is_none(),
        "{context}: the legitimate fraction must decode: {outcome:?}"
    );
}

/// R50: row bytes left over after the last complete row are rejected with
/// the documented message — the library's row iterator would try to decode
/// them as a phantom row and fail with an opaque end-of-stream error. The
/// clean controls (a complete row, and a two-row event) still decode, so the
/// check rejects nothing the library accepts.
#[test]
fn trailing_bytes_after_row_data_are_rejected() {
    let context = "trailing-bytes";
    let bytes = binlog(&[
        one_column_table_map(0x03, &[]), // LONG
        // One complete 4-byte row plus a byte that cannot form a row: its
        // NULL bitmap marks the column as present, and no value follows.
        one_column_write_rows(&[&[1, 0, 0, 0], &[0x00]]),
    ]);
    let outcome = parse(&bytes, bytes.len(), context);
    assert_eq!(
        outcome.events.len(),
        2,
        "{context}: the format description and table map still decode: {outcome:?}"
    );
    let error = outcome
        .error
        .clone()
        .unwrap_or_else(|| panic!("{context}: the trailing bytes must fail the rows event"));
    assert!(
        error.contains("trailing bytes after row data in rows event"),
        "{error}"
    );
    assert_eq!(parse(&bytes, 3, context), outcome, "{context}");

    // A complete single row decodes.
    let context = "trailing-bytes-clean-single-row";
    let clean = binlog(&[
        one_column_table_map(0x03, &[]),
        one_column_write_rows(&[&[1, 0, 0, 0]]),
    ]);
    let outcome = parse(&clean, clean.len(), context);
    assert!(outcome.error.is_none(), "{context}: {outcome:?}");
    let mut cells = Vec::new();
    collect_cells(&outcome.events, &mut cells);
    assert_eq!(cells, vec![CellValue::Int(1)], "{context}");

    // A clean multi-row event decodes both rows: row boundaries are
    // self-delimiting, so the walk consumes exactly the rows present.
    let context = "trailing-bytes-clean-multi-row";
    let clean = binlog(&[
        one_column_table_map(0x03, &[]),
        one_column_write_rows(&[&[1, 0, 0, 0], &[2, 0, 0, 0]]),
    ]);
    let outcome = parse(&clean, clean.len(), context);
    assert!(outcome.error.is_none(), "{context}: {outcome:?}");
    let mut cells = Vec::new();
    collect_cells(&outcome.events, &mut cells);
    assert_eq!(
        cells,
        vec![CellValue::Int(1), CellValue::Int(2)],
        "{context}"
    );
}

/// R48-refinement acceptance: a legitimate rows event over 1200 JSON
/// columns of small documents still decodes — the shared per-event budget
/// (`min(16 × event_size, 4_000_000)` nodes) leaves a wide margin over the
/// ~0.25 nodes per wire byte that legitimate jsonb costs, so no legitimate
/// density is rejected.
#[test]
fn legitimate_multi_column_json_rows_decode_within_the_budget() {
    const COLUMNS: usize = 1200;
    // Binary jsonb for {"a": 1}: small object, one member; offsets count
    // from the element-count field.
    let doc = [
        0x00, 0x01, 0x00, 0x0c, 0x00, // small object, one member, 12 bytes
        0x0b, 0x00, 0x01, 0x00, // key entry: "a" at offset 11, length 1
        0x05, 0x01, 0x00, // value entry: int16 1 (inlined)
        b'a', // key bytes at offset 11
    ];
    let mut map_body = vec![5, 0, 0, 0, 0, 0, 0, 0]; // Table id 5 and flags.
    map_body.extend_from_slice(b"\x02db\0\x01t\0");
    map_body.push(0xfc); // 1200 columns, length-encoded
    map_body.extend((COLUMNS as u16).to_le_bytes());
    map_body.extend([0xf5; COLUMNS]); // JSON
    map_body.push(0xfc); // 1200 metadata bytes, length-encoded
    map_body.extend((COLUMNS as u16).to_le_bytes());
    map_body.extend([4; COLUMNS]); // JSON uses a four-byte length prefix
    map_body.extend([0; COLUMNS.div_ceil(8)]); // NULL bitmap
    let map = WireEvent {
        code: 19,
        body: map_body,
    };

    let mut rows_body = vec![5, 0, 0, 0, 0, 0, 0, 0]; // Table id 5 and flags.
    rows_body.extend([2, 0]); // Extra-data length (none).
    rows_body.push(0xfc); // 1200 columns, length-encoded
    rows_body.extend((COLUMNS as u16).to_le_bytes());
    rows_body.extend([0xff; COLUMNS / 8]); // All 1200 columns present
    rows_body.extend([0; COLUMNS.div_ceil(8)]); // None of them NULL
    for _ in 0..COLUMNS {
        rows_body.extend((doc.len() as u32).to_le_bytes());
        rows_body.extend_from_slice(&doc);
    }
    let rows = WireEvent {
        code: 30,
        body: rows_body,
    };
    let bytes = binlog_large(&[map, rows]);
    let context = "legit-1200-json-columns";
    let outcome = parse_with_cap(&bytes, bytes.len(), LARGE_EVENT_CAP, context);
    assert!(
        outcome.error.is_none(),
        "{context}: the legitimate event must decode: {outcome:?}"
    );
    // Every column of the single row is a JSON cell; collect them all.
    let mut cells = Vec::new();
    for event in &outcome.events {
        if let EventPayload::Rows { changes, .. } = &event.payload {
            for change in changes {
                let after = change.after.as_ref().unwrap();
                for column in &after.columns {
                    cells.push(column.value.clone());
                }
            }
        }
    }
    assert_eq!(cells.len(), COLUMNS, "{context}: every JSON column decodes");
    assert!(
        cells
            .iter()
            .all(|cell| cell == &CellValue::Json(serde_json::json!({"a": 1}))),
        "{context}: every column renders the same document"
    );
}

/// R48-refinement acceptance: 100 individually budget-clean hostile JSON
/// columns in one rows event (100 × 181 wire bytes, each bomb decoding to
/// 2^19 - 1 = 524,287 nodes within the per-value budget of one million) trip
/// the shared per-event budget instead of allocating linearly with the wire
/// size.
#[test]
fn one_hundred_json_bombs_trip_the_per_event_budget() {
    const BOMBS: usize = 100;
    let bomb = aliased_jsonb_bomb(18);
    assert_eq!(bomb.len(), 181);
    let mut body = vec![5, 0, 0, 0, 0, 0, 0, 0]; // Table id 5 and flags.
    body.extend([2, 0]); // Extra-data length (none).
    body.push(BOMBS as u8); // Column count.
    let mut bitmap = vec![0xffu8; BOMBS / 8];
    bitmap.push(0x0f); // 100 present bits over 13 bytes
    body.extend_from_slice(&bitmap);
    body.extend([0; BOMBS.div_ceil(8)]); // None of them NULL
    for _ in 0..BOMBS {
        body.extend((bomb.len() as u32).to_le_bytes());
        body.extend_from_slice(&bomb);
    }
    let rows = WireEvent { code: 30, body };
    // The table map declares the same 100 JSON columns; 100 is below the
    // length-encoded threshold for both counts.
    let mut map_body = vec![5, 0, 0, 0, 0, 0, 0, 0]; // Table id 5 and flags.
    map_body.extend_from_slice(b"\x02db\0\x01t\0");
    map_body.push(BOMBS as u8); // Column count.
    map_body.extend([0xf5; BOMBS]); // JSON
    map_body.push(BOMBS as u8); // Metadata length.
    map_body.extend([4; BOMBS]); // JSON uses a four-byte length prefix
    map_body.extend([0; BOMBS.div_ceil(8)]); // NULL bitmap
    let map = WireEvent {
        code: 19,
        body: map_body,
    };
    let bytes = binlog_large(&[map, rows]);
    let event_size = (19 + 37 + BOMBS * (4 + 181) + 4) as u32;
    let expected_budget = (16 * event_size as usize).min(4_000_000);
    let context = "100-json-bombs";
    let outcome = parse_with_cap(&bytes, bytes.len(), LARGE_EVENT_CAP, context);
    assert_eq!(
        outcome.events.len(),
        2,
        "{context}: the format description and table map still decode: {outcome:?}"
    );
    let error = outcome
        .error
        .clone()
        .unwrap_or_else(|| panic!("{context}: the rows event must fail"));
    assert!(
        error.contains(&format!(
            "jsonb decoding in this event exceeds the per-event node budget of {expected_budget} nodes"
        )),
        "{error}"
    );
    // The same outcome under chunked reads.
    assert_eq!(
        parse_with_cap(&bytes, 64, LARGE_EVENT_CAP, context),
        outcome,
        "{context}"
    );
}
