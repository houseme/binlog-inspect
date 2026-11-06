// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Row decoders must consume bytes before yielding another row.
//! Fixtures use the default V4 format description, whose V1 row headers
//! omit extra-data lengths and whose V2 headers include them.

use binlog_inspect::{
    event::{CellValue, EventPayload},
    parser::{BinlogParser, ParserError, VisitEvent},
};
use mysql_common::{
    binlog::{consts::TransactionPayloadCompressionType, events::TransactionPayloadEvent},
    proto::MySerialize,
};
use std::{
    io::{self, Cursor},
    ops::ControlFlow,
};

const ORDINARY_ROW_CODES: [u8; 6] = [23, 24, 25, 30, 31, 32];

fn event(code: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(1u32.to_le_bytes());
    bytes.push(code);
    bytes.extend(7u32.to_le_bytes());
    bytes.extend((19u32 + body.len() as u32).to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes.extend(body);
    bytes
}

fn table_map(columns: u8) -> Vec<u8> {
    assert!(columns <= 1);
    let mut body = vec![1, 0, 0, 0, 0, 0, 0, 0];
    body.extend_from_slice(b"\x02db\0\x01t\0");
    body.push(columns);
    body.extend(std::iter::repeat_n(0x03, usize::from(columns))); // LONG
    body.push(0); // column metadata length
    if columns > 0 {
        body.push(0); // nullable-column bitmap
    }
    event(19, &body)
}

fn row_event(code: u8, columns: u8, before: u8, after: u8, rows: &[u8]) -> Vec<u8> {
    let mut body = vec![1, 0, 0, 0, 0, 0, 0, 0];
    if code >= 30 {
        body.extend(2u16.to_le_bytes()); // V2 extra-data length
    }
    body.push(columns);
    if columns > 0 {
        match code {
            23 | 30 => body.push(after),
            25 | 32 => body.push(before),
            24 | 31 | 39 => body.extend([before, after]),
            _ => unreachable!("unsupported fixture event type"),
        }
    }
    body.extend(rows);
    event(code, &body)
}

fn parser(events: &[Vec<u8>]) -> BinlogParser<Cursor<Vec<u8>>> {
    let mut bytes = b"\xfebin".to_vec();
    for event in events {
        bytes.extend(event);
    }
    BinlogParser::from_reader(Cursor::new(bytes)).unwrap()
}

fn assert_invalid_data(error: ParserError, expected_offset: u64) {
    let ParserError::Io { offset, source } = error else {
        panic!("expected an I/O error");
    };
    assert_eq!(offset, expected_offset);
    assert_eq!(source.kind(), io::ErrorKind::InvalidData, "{source}");
}

fn assert_fused(parser: &mut BinlogParser<Cursor<Vec<u8>>>) {
    assert!(parser.events().next().is_none());
    assert_eq!(
        parser
            .visit_events(|_| panic!("a terminated parser invoked its visitor"))
            .unwrap(),
        ControlFlow::Continue(())
    );
}

#[test]
fn nonempty_rows_without_present_columns_are_rejected() {
    for code in ORDINARY_ROW_CODES {
        for (declared, schema_columns, bitmap) in [
            (1, 1, 0),    // all effective column bits are zero
            (1, 1, 0x80), // only a padding bit is set
            (0, 1, 0),    // row declares zero columns of a nonempty schema
            (0, 0, 0),    // table map and row both declare zero columns
        ] {
            let map = table_map(schema_columns);
            let offset = 4 + map.len() as u64;
            let row = row_event(code, declared, bitmap, bitmap, &[0]);
            let mut parser = parser(&[map, row, event(16, &77u64.to_le_bytes())]);
            assert!(parser.events().next().unwrap().is_ok());
            let error = parser.events().next().unwrap().unwrap_err();
            assert_invalid_data(error, offset);
            assert_fused(&mut parser);
        }
    }
}

#[test]
fn empty_row_data_with_empty_bitmaps_produces_no_changes() {
    for code in ORDINARY_ROW_CODES {
        for (declared, schema_columns, bitmap) in [(1, 1, 0), (1, 1, 0x80), (0, 1, 0), (0, 0, 0)] {
            let mut parser = parser(&[
                table_map(schema_columns),
                row_event(code, declared, bitmap, bitmap, &[]),
            ]);
            let events = parser.events().collect::<Result<Vec<_>, _>>().unwrap();
            let EventPayload::Rows { changes, .. } = &events[1].payload else {
                panic!("expected an ordinary row payload for code {code}");
            };
            assert!(changes.is_empty());
            assert_fused(&mut parser);
        }
    }
}

#[test]
fn updates_with_one_nonempty_image_still_make_progress() {
    let mut image = vec![0]; // SQL NULL bitmap, value is present
    image.extend(42i32.to_le_bytes());
    let rows = image.repeat(2);
    for code in [24, 31] {
        for (before, after) in [(1, 0), (0, 1)] {
            let mut parser = parser(&[table_map(1), row_event(code, 1, before, after, &rows)]);
            let events = parser.events().collect::<Result<Vec<_>, _>>().unwrap();
            let EventPayload::Rows { changes, .. } = &events[1].payload else {
                panic!("expected update rows");
            };
            assert_eq!(changes.len(), 2);
            for change in changes {
                for (image, present) in [(&change.before, before), (&change.after, after)] {
                    let columns = &image.as_ref().unwrap().columns;
                    assert_eq!(columns.len(), 1);
                    let expected = if present == 1 {
                        CellValue::Int(42)
                    } else {
                        CellValue::Absent
                    };
                    assert_eq!(columns[0].value, expected);
                }
            }
            assert_fused(&mut parser);
        }
    }
}

#[test]
fn partial_updates_with_empty_images_consume_value_options() {
    for (declared, schema_columns) in [(1, 1), (0, 1), (0, 0)] {
        // Each zero byte is an after image's value_options field. Even
        // without selected columns these encode two finite row pairs.
        let mut parser = parser(&[
            table_map(schema_columns),
            row_event(39, declared, 0, 0, &[0, 0]),
        ]);
        let events = parser.events().collect::<Result<Vec<_>, _>>().unwrap();
        let EventPayload::PartialUpdateRows { before, after, .. } = &events[1].payload else {
            panic!("expected partial update rows");
        };
        assert_eq!(before.len(), 2);
        assert_eq!(after.len(), 2);
        for image in before.iter().chain(after) {
            let columns = &image.as_ref().unwrap().columns;
            assert_eq!(columns.len(), usize::from(schema_columns));
            assert!(columns.iter().all(|cell| cell.value == CellValue::Absent));
        }
        assert_fused(&mut parser);
    }
}

#[test]
fn payload_row_progress_errors_stop_collectors_and_visitors() {
    let map = table_map(1);
    let xid = event(16, &77u64.to_le_bytes());
    let bad_offset = map.len() + xid.len();
    let content = [map, xid, row_event(30, 1, 0, 0x80, &[0])].concat();
    let payload = TransactionPayloadEvent::new(
        content.len() as u64,
        TransactionPayloadCompressionType::NONE,
        0,
        content,
    );
    let mut body = Vec::new();
    payload.serialize(&mut body);
    let events = [event(40, &body), event(16, &88u64.to_le_bytes())];

    let mut collector = parser(&events);
    let error = collector.events().next().unwrap().unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&format!("inner offset {bad_offset}")),
        "{error}"
    );
    assert_invalid_data(error, 4);
    assert_fused(&mut collector);

    let mut visitor = parser(&events);
    let mut notifications = Vec::new();
    let error = visitor
        .visit_events(|notification| {
            notifications.push(match notification {
                VisitEvent::TransactionPayloadStart { .. } => "start",
                VisitEvent::Event {
                    event,
                    parent_offset: Some(4),
                } => match event.payload {
                    EventPayload::TableMap { .. } => "map",
                    EventPayload::Xid { xid: 77 } => "xid",
                    _ => panic!("unexpected inner event"),
                },
                VisitEvent::TransactionPayloadEnd { .. } => "end",
                _ => panic!("unexpected visitor notification"),
            });
            Ok(ControlFlow::Continue(()))
        })
        .unwrap_err();
    assert_eq!(notifications, ["start", "map", "xid"]);
    assert_invalid_data(error, 4);
    assert_fused(&mut visitor);
}
