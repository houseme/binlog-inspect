// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Synthetic fixtures for bounded, callback-based transaction decoding.

use binlog_inspect::{
    event::EventPayload,
    parser::{BinlogParser, ParserError, VisitEvent},
};
use mysql_common::{
    binlog::{consts::TransactionPayloadCompressionType, events::TransactionPayloadEvent},
    proto::MySerialize,
};
use std::{
    io::{self, Cursor},
    ops::ControlFlow,
    panic::{AssertUnwindSafe, catch_unwind},
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

fn event(code: u8, body: &[u8], checksum: bool) -> Vec<u8> {
    let size = 19 + body.len() + if checksum { 4 } else { 0 };
    let mut bytes = Vec::new();
    bytes.extend(555u32.to_le_bytes());
    bytes.push(code);
    bytes.extend(99u32.to_le_bytes());
    bytes.extend((size as u32).to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes.extend(body);
    if checksum {
        bytes.extend(crc32(&bytes).to_le_bytes());
    }
    bytes
}

fn format_description() -> Vec<u8> {
    let mut body = vec![0; 57];
    body[..2].copy_from_slice(&4u16.to_le_bytes());
    body[2..8].copy_from_slice(b"8.0.30");
    body[56] = 19;
    body.extend([0; 40]);
    body.push(1);
    event(15, &body, true)
}

fn inner_event(code: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = event(code, body, false);
    // Inner headers deliberately disagree with the outer header. Both APIs
    // must report the enclosing timestamp and server ID.
    bytes[..4].copy_from_slice(&1234u32.to_le_bytes());
    bytes[5..9].copy_from_slice(&1u32.to_le_bytes());
    bytes
}

fn table_map() -> Vec<u8> {
    let mut body = vec![5, 0, 0, 0, 0, 0, 0, 0];
    body.extend_from_slice(b"\x02db\0\x01t\0\x01\x03\x00\x00");
    inner_event(19, &body)
}

fn rows_body() -> Vec<u8> {
    let mut body = vec![5, 0, 0, 0, 0, 0, 0, 0];
    body.extend_from_slice(&[2, 0, 1, 1, 0, 42, 0, 0, 0]);
    body
}

fn xid(value: u64) -> Vec<u8> {
    inner_event(16, &value.to_le_bytes())
}

/// A ZSTD frame with raw blocks, avoiding a test-only encoder dependency.
fn zstd_frame(content: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0xa0];
    frame.extend((content.len() as u32).to_le_bytes());
    if content.is_empty() {
        frame.extend([1, 0, 0]); // final, empty raw block
    }
    let blocks = content.len().div_ceil(64 * 1024);
    for (index, block) in content.chunks(64 * 1024).enumerate() {
        let header = ((block.len() as u32) << 3) | u32::from(index + 1 == blocks);
        frame.extend(&header.to_le_bytes()[..3]);
        frame.extend(block);
    }
    frame
}

fn payload(content: &[u8], compressed: bool) -> Vec<u8> {
    let (algorithm, size, data) = if compressed {
        (
            TransactionPayloadCompressionType::ZSTD,
            content.len() as u64,
            zstd_frame(content),
        )
    } else {
        (TransactionPayloadCompressionType::NONE, 0, content.to_vec())
    };
    let payload = TransactionPayloadEvent::new(data.len() as u64, algorithm, size, data);
    let mut body = Vec::new();
    payload.serialize(&mut body);
    event(40, &body, true)
}

fn binlog(payload: Vec<u8>) -> Vec<u8> {
    [
        b"\xfebin".to_vec(),
        format_description(),
        payload,
        event(30, &rows_body(), true),
        event(16, &88u64.to_le_bytes(), true),
    ]
    .concat()
}

fn sample(compressed: bool) -> Vec<u8> {
    let content = [table_map(), inner_event(30, &rows_body()), xid(77)].concat();
    binlog(payload(&content, compressed))
}

fn assert_fused(parser: &mut BinlogParser<Cursor<Vec<u8>>>) {
    assert!(parser.events().next().is_none());
    let flow = parser
        .visit_events(|_| panic!("a terminated parser invoked its visitor"))
        .unwrap();
    assert_eq!(flow, ControlFlow::Continue(()));
}

#[test]
fn visitor_reconstructs_the_collecting_api_for_none_and_zstd() {
    for compressed in [false, true] {
        let bytes = sample(compressed);
        let mut collector = BinlogParser::from_reader(Cursor::new(bytes.clone())).unwrap();
        let expected = collector.events().collect::<Result<Vec<_>, _>>().unwrap();
        let expected = serde_json::to_value(expected).unwrap();

        let mut parser = BinlogParser::from_reader(Cursor::new(bytes)).unwrap();
        // Switching from the existing iterator preserves FDE/checksum state.
        let first = parser.events().next().unwrap().unwrap();
        let mut actual = vec![serde_json::to_value(first).unwrap()];
        let mut pending: Option<serde_json::Value> = None;
        let mut rows_seen = 0;
        let flow = parser
            .visit_events(|notification| {
                match notification {
                    VisitEvent::Event {
                        event,
                        parent_offset,
                    } => {
                        if matches!(event.payload, EventPayload::Rows { .. }) {
                            rows_seen += 1;
                        }
                        let json = serde_json::to_value(event).unwrap();
                        match parent_offset {
                            Some(offset) => {
                                let outer = pending.as_mut().unwrap();
                                assert_eq!(outer["offset"], offset);
                                outer["payload"]["events"]
                                    .as_array_mut()
                                    .unwrap()
                                    .push(json);
                            }
                            None => {
                                assert!(pending.is_none());
                                actual.push(json);
                            }
                        }
                    }
                    VisitEvent::TransactionPayloadStart {
                        offset,
                        timestamp,
                        server_id,
                        event_size,
                        log_pos,
                        compression,
                        uncompressed_size,
                    } => {
                        assert!(pending.is_none());
                        pending = Some(serde_json::json!({
                            "offset": offset, "timestamp": timestamp, "server_id": server_id,
                            "event_type": "transaction_payload", "event_type_code": 40,
                            "event_size": event_size, "log_pos": log_pos,
                            "payload": {
                                "kind": "transaction_payload", "compression": compression,
                                "uncompressed_size": uncompressed_size, "events": [],
                            },
                        }));
                    }
                    VisitEvent::TransactionPayloadEnd { offset } => {
                        let outer = pending.take().unwrap();
                        assert_eq!(outer["offset"], offset);
                        actual.push(outer);
                    }
                    _ => unreachable!("unexpected visitor notification"),
                }
                Ok(ControlFlow::Continue(()))
            })
            .unwrap();
        assert_eq!(flow, ControlFlow::Continue(()));
        assert!(pending.is_none());
        assert_eq!(
            rows_seen, 2,
            "inner table maps must resolve later outer rows"
        );
        assert_eq!(serde_json::Value::Array(actual), expected);
        assert_fused(&mut parser);
    }
}

#[test]
fn empty_payloads_emit_a_complete_start_end_pair() {
    for compressed in [false, true] {
        let bytes = [
            b"\xfebin".to_vec(),
            format_description(),
            payload(&[], compressed),
        ]
        .concat();
        let mut parser = BinlogParser::from_reader(Cursor::new(bytes)).unwrap();
        let mut notifications = Vec::new();
        let flow = parser
            .visit_events(|notification| {
                notifications.push(match notification {
                    VisitEvent::Event { .. } => "event",
                    VisitEvent::TransactionPayloadStart { .. } => "start",
                    VisitEvent::TransactionPayloadEnd { .. } => "end",
                    _ => unreachable!(),
                });
                Ok(ControlFlow::Continue(()))
            })
            .unwrap();
        assert_eq!(flow, ControlFlow::Continue(()));
        assert_eq!(notifications, ["event", "start", "end"]);
    }
}

#[test]
fn checksum_failure_precedes_all_payload_callbacks() {
    let mut damaged = payload(&xid(77), true);
    *damaged.last_mut().unwrap() ^= 1;
    let mut parser = BinlogParser::from_reader(Cursor::new(binlog(damaged))).unwrap();
    let mut calls = 0;
    let error = parser
        .visit_events(|notification| {
            calls += 1;
            assert!(matches!(
                notification,
                VisitEvent::Event {
                    parent_offset: None,
                    ..
                }
            ));
            Ok(ControlFlow::Continue(()))
        })
        .unwrap_err();
    assert_eq!(calls, 1); // preceding FDE only
    assert!(error.to_string().contains("checksum mismatch"));
    assert_fused(&mut parser);
}

#[test]
fn late_inner_error_preserves_the_visited_prefix_and_omits_end() {
    let content = [xid(77), inner_event(16, &[0, 0])].concat();
    for compressed in [false, true] {
        let bytes = binlog(payload(&content, compressed));
        let mut parser = BinlogParser::from_reader(Cursor::new(bytes.clone())).unwrap();
        let mut notifications = Vec::new();
        let error = parser
            .visit_events(|notification| {
                notifications.push(match notification {
                    VisitEvent::Event {
                        parent_offset: None,
                        ..
                    } => "outer",
                    VisitEvent::Event {
                        event,
                        parent_offset: Some(_),
                    } => {
                        assert_eq!(event.payload, EventPayload::Xid { xid: 77 });
                        "inner"
                    }
                    VisitEvent::TransactionPayloadStart { .. } => "start",
                    VisitEvent::TransactionPayloadEnd { .. } => "end",
                    _ => unreachable!(),
                });
                Ok(ControlFlow::Continue(()))
            })
            .unwrap_err();
        assert_eq!(notifications, ["outer", "start", "inner"]);
        assert!(error.to_string().contains("inner offset 27"), "{error}");
        let ParserError::Io { offset, .. } = error else {
            panic!("expected I/O error");
        };
        assert_eq!(offset, 4 + format_description().len() as u64);
        assert_fused(&mut parser);

        // Cancelling after the valid inner event avoids decoding the damaged
        // suffix and permanently consumes the visitor session.
        let mut parser = BinlogParser::from_reader(Cursor::new(bytes)).unwrap();
        let flow = parser
            .visit_events(|notification| {
                Ok(
                    if matches!(
                        notification,
                        VisitEvent::Event {
                            parent_offset: Some(_),
                            ..
                        }
                    ) {
                        ControlFlow::Break(())
                    } else {
                        ControlFlow::Continue(())
                    },
                )
            })
            .unwrap();
        assert_eq!(flow, ControlFlow::Break(()));
        assert_fused(&mut parser);
    }
}

#[test]
fn callback_break_and_error_fuse_at_each_notification_kind() {
    // FDE, payload start, first inner event, payload end.
    for stop_at in [0, 1, 2, 5] {
        for fail in [false, true] {
            let mut parser = BinlogParser::from_reader(Cursor::new(sample(true))).unwrap();
            let mut calls = 0;
            let result = parser.visit_events(|_| {
                let index = calls;
                calls += 1;
                if index != stop_at {
                    return Ok(ControlFlow::Continue(()));
                }
                if fail {
                    Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "visitor writer closed",
                    ))
                } else {
                    Ok(ControlFlow::Break(()))
                }
            });
            assert_eq!(calls, stop_at + 1);
            if fail {
                let ParserError::Io { offset, source } = result.unwrap_err() else {
                    panic!("expected callback I/O error");
                };
                assert_eq!(source.kind(), io::ErrorKind::BrokenPipe);
                assert_eq!(source.to_string(), "visitor writer closed");
                assert_eq!(
                    offset,
                    if stop_at == 0 {
                        4
                    } else {
                        4 + format_description().len() as u64
                    }
                );
            } else {
                assert_eq!(result.unwrap(), ControlFlow::Break(()));
            }
            assert_fused(&mut parser);
        }
    }
}

#[test]
fn caught_callback_panics_leave_the_parser_fused() {
    for panic_at in [0, 1, 2, 5] {
        let mut parser = BinlogParser::from_reader(Cursor::new(sample(true))).unwrap();
        let mut calls = 0;
        let result = catch_unwind(AssertUnwindSafe(|| {
            parser.visit_events(|_| {
                let index = calls;
                calls += 1;
                assert_ne!(index, panic_at, "synthetic callback panic");
                Ok(ControlFlow::Continue(()))
            })
        }));
        assert!(result.is_err());
        assert_eq!(calls, panic_at + 1);
        assert_fused(&mut parser);
    }
}

#[test]
fn many_inner_events_are_consumed_by_a_counting_visitor() {
    let count = 100_000;
    let content = xid(77).repeat(count);
    let bytes = [
        b"\xfebin".to_vec(),
        format_description(),
        payload(&content, true),
    ]
    .concat();
    let mut parser = BinlogParser::from_reader(Cursor::new(bytes)).unwrap();
    let mut inner_count = 0;
    let mut ends = 0;
    let flow = parser
        .visit_events(|notification| {
            match notification {
                VisitEvent::Event {
                    event,
                    parent_offset: Some(_),
                } => {
                    assert_eq!(event.offset, inner_count * 27);
                    assert_eq!(event.payload, EventPayload::Xid { xid: 77 });
                    inner_count += 1;
                }
                VisitEvent::TransactionPayloadEnd { .. } => ends += 1,
                _ => {}
            }
            Ok(ControlFlow::Continue(()))
        })
        .unwrap();
    assert_eq!(flow, ControlFlow::Continue(()));
    assert_eq!(inner_count, count as u64);
    assert_eq!(ends, 1);
    assert_fused(&mut parser);
}
