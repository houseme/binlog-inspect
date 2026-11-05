// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

use binlog_inspect::{
    event::{
        CellValue, ColumnValue, EventPayload, EventType, JsonDiffRecord, ParsedEvent, RowChange,
        RowImage,
    },
    formatter::{CsvFormatter, Formatter, JsonLinesFormatter},
};
use std::io::Cursor;

fn sample_event() -> ParsedEvent {
    ParsedEvent {
        offset: 4,
        timestamp: 1,
        event_type: EventType::WriteRows,
        event_type_code: 30,
        server_id: 1,
        event_size: 19,
        log_pos: 23,
        payload: EventPayload::Rows {
            table_id: 1,
            database: "db".into(),
            table: "t".into(),
            changes: vec![RowChange {
                before: None,
                after: Some(RowImage {
                    columns: vec![
                        ColumnValue {
                            index: 0,
                            name: Some("a,\"b\"".into()),
                            mysql_type: Some("BLOB".into()),
                            signedness: None,
                            value: CellValue::Bytes("00ff".into()),
                        },
                        ColumnValue {
                            index: 1,
                            name: Some("n".into()),
                            mysql_type: Some("LONGLONG".into()),
                            signedness: Some(binlog_inspect::event::Signedness::Unsigned),
                            value: CellValue::UInt(42),
                        },
                    ],
                }),
            }],
        },
    }
}

#[test]
fn json_and_csv_represent_typed_rows() {
    let event = sample_event();
    let mut json_out = Vec::new();
    assert!(JsonLinesFormatter.format(&event, &mut json_out).unwrap());
    let json: serde_json::Value = serde_json::from_slice(&json_out).unwrap();
    assert_eq!(json["event_type"], "write_rows");
    assert_eq!(
        json["payload"]["changes"][0]["after"]["columns"][0]["value"]["value"],
        "00ff"
    );
    let mut csv_out = Vec::new();
    assert!(CsvFormatter.format(&event, &mut csv_out).unwrap());
    let csv = String::from_utf8(csv_out).unwrap();
    assert!(csv.contains("a,\\\"\"b\\\"\""), "{csv}");
    assert!(csv.contains("00ff"), "{csv}");
}

#[test]
fn rows_payload_round_trips_through_json() {
    let event = sample_event();
    let text = serde_json::to_string(&event).unwrap();
    let parsed: ParsedEvent = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed, event);
}

#[test]
fn cell_values_round_trip_through_json() {
    for value in [
        CellValue::Absent,
        CellValue::Null,
        CellValue::Bytes("00ff22".into()),
        CellValue::Int(-7),
        CellValue::UInt(u64::MAX),
        CellValue::Float("1.5".into()),
        CellValue::Double("inf".into()),
        CellValue::Date {
            year: 2026,
            month: 11,
            day: 5,
            hour: 12,
            minute: 34,
            second: 56,
            micros: 789000,
        },
        CellValue::Time {
            negative: true,
            days: 2,
            hours: 3,
            minutes: 4,
            seconds: 5,
            micros: 6,
        },
        CellValue::Json(serde_json::json!({"k": [1, null]})),
        CellValue::PartialJson {
            diffs: vec![
                JsonDiffRecord {
                    path: "$.b[1]".into(),
                    operation: "replace".into(),
                    value: Some(serde_json::json!(99)),
                },
                JsonDiffRecord {
                    path: "$.a".into(),
                    operation: "remove".into(),
                    value: None,
                },
            ],
            reason: "before value is not JSON".into(),
        },
    ] {
        let text = serde_json::to_string(&value).unwrap();
        let parsed: CellValue = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, value, "{text}");
    }
}

#[test]
fn partial_json_cell_serializes_with_stable_field_names() {
    let value = CellValue::PartialJson {
        diffs: vec![JsonDiffRecord {
            path: "$.c".into(),
            operation: "insert".into(),
            value: Some(serde_json::json!("x")),
        }],
        reason: "no before image to apply diffs against".into(),
    };
    let json = serde_json::to_value(&value).unwrap();
    assert_eq!(json["type"], "partial_json");
    assert_eq!(
        json["value"]["reason"],
        "no before image to apply diffs against"
    );
    assert_eq!(json["value"]["diffs"][0]["path"], "$.c");
    assert_eq!(json["value"]["diffs"][0]["operation"], "insert");
    assert_eq!(json["value"]["diffs"][0]["value"], "x");

    let event = sample_event();
    let event_with_loss = ParsedEvent {
        payload: EventPayload::Rows {
            table_id: 1,
            database: "db".into(),
            table: "t".into(),
            changes: vec![RowChange {
                before: None,
                after: Some(RowImage {
                    columns: vec![ColumnValue {
                        index: 0,
                        name: Some("doc".into()),
                        mysql_type: Some("JSON".into()),
                        signedness: None,
                        value,
                    }],
                }),
            }],
        },
        ..event
    };
    let text = serde_json::to_string(&event_with_loss).unwrap();
    let parsed: ParsedEvent = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed, event_with_loss);
}

#[test]
fn hex_encoding_still_uses_lowercase_pairs() {
    let event = ParsedEvent {
        offset: 4,
        timestamp: 1,
        event_type: EventType::WriteRows,
        event_type_code: 30,
        server_id: 1,
        event_size: 19,
        log_pos: 23,
        payload: EventPayload::Rows {
            table_id: 1,
            database: "db".into(),
            table: "t".into(),
            changes: vec![RowChange {
                before: None,
                after: Some(RowImage {
                    columns: vec![ColumnValue {
                        index: 0,
                        name: None,
                        mysql_type: None,
                        signedness: None,
                        value: CellValue::Bytes("0f80ff00".into()),
                    }],
                }),
            }],
        },
    };
    let text = serde_json::to_string(&event).unwrap();
    assert!(text.contains("\"0f80ff00\""), "{text}");
    let parsed: ParsedEvent = serde_json::from_str(&text).unwrap();
    assert_eq!(
        parsed.payload,
        EventPayload::Rows {
            table_id: 1,
            database: "db".into(),
            table: "t".into(),
            changes: vec![RowChange {
                before: None,
                after: Some(RowImage {
                    columns: vec![ColumnValue {
                        index: 0,
                        name: None,
                        mysql_type: None,
                        signedness: None,
                        value: CellValue::Bytes("0f80ff00".into()),
                    }],
                }),
            }],
        }
    );
}

#[test]
fn mysql_type_names_are_canonical() {
    let event = sample_event();
    let text = serde_json::to_string(&event).unwrap();
    assert!(text.contains("\"BLOB\""), "{text}");
    assert!(text.contains("\"LONGLONG\""), "{text}");
    assert!(!text.contains("MYSQL_TYPE_"), "{text}");
    // CSV still renders the event type as the snake_case name (quoted).
    let mut csv_out = Vec::new();
    assert!(CsvFormatter.format(&event, &mut csv_out).unwrap());
    let csv = String::from_utf8(csv_out).unwrap();
    assert!(csv.starts_with("1,\"write_rows\","), "{csv}");
    // The formatter's Write target is honored without buffering tricks.
    let mut probe = Cursor::new(Vec::new());
    assert!(JsonLinesFormatter.format(&event, &mut probe).unwrap());
}
