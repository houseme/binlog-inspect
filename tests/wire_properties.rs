// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Deterministic, bounded wire-format properties exercised through the public parser.
//!
//! The seed, family, case and mutation are printed on failure. These cases use
//! synthetic data and run on stable with either feature configuration. They
//! complement coverage-guided fuzzing: they do not generate arbitrary format
//! descriptions, compressed streams or deeply aliased JSONB containers, whose
//! resource amplification needs a separately limited process.

use binlog_inspect::{
    event::{CellValue, EventPayload, EventType, ParsedEvent},
    parser::BinlogParser,
};
use mysql_common::{
    binlog::{consts::TransactionPayloadCompressionType, events::TransactionPayloadEvent},
    proto::MySerialize,
};
use std::io::{self, Cursor, Read};

const SEED: u64 = 0x5247_3437_6269_6e6c;
const EVENT_CAP: u32 = 4096;
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
    let size = 19 + event.body.len() + usize::from(checksum) * 4;
    assert!(size <= EVENT_CAP as usize);
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
    let mut description = vec![0; 57];
    description[..2].copy_from_slice(&4u16.to_le_bytes());
    description[2..8].copy_from_slice(b"8.0.30");
    description[56] = 19;
    description.extend([0; 40]);
    description.push(1); // CRC32
    let mut bytes = b"\xfebin".to_vec();
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
    assert!((19..=EVENT_CAP).contains(&event.event_size));
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
    std::panic::catch_unwind(|| {
        let reader = ShortReader {
            input: Cursor::new(bytes),
            chunk,
        };
        let mut parser = match BinlogParser::from_reader(reader) {
            Ok(parser) => parser.with_max_event_size(EVENT_CAP),
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
                    check_event(&event);
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
