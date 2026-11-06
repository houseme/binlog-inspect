// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Table-map column metadata must be validated before exposing the schema or decoding rows.
//! All fixtures are synthetic and exercise the public parser without CLI features.

use binlog_inspect::{
    event::{CellValue, EventPayload},
    parser::{BinlogParser, ParserError},
};
use mysql_common::constants::ColumnType;
use std::io::{self, Cursor};

fn event(code: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(1u32.to_le_bytes());
    bytes.push(code);
    bytes.extend(1u32.to_le_bytes());
    bytes.extend((19u32 + body.len() as u32).to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn table_map(types: &[u8], metadata: &[u8]) -> Vec<u8> {
    assert!(types.len() < 251 && metadata.len() < 251);
    let mut body = vec![1, 0, 0, 0, 0, 0, 0, 0];
    body.extend_from_slice(b"\x01d\0\x01t\0");
    body.push(types.len() as u8);
    body.extend_from_slice(types);
    body.push(metadata.len() as u8);
    body.extend_from_slice(metadata);
    body.resize(body.len() + types.len().div_ceil(8), 0);
    event(19, &body)
}

fn binlog(map: &[u8]) -> Vec<u8> {
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend_from_slice(map);
    bytes
}

fn rejects_map(types: &[u8], metadata: &[u8], kind: io::ErrorKind) {
    let bytes = binlog(&table_map(types, metadata));
    let mut parser = BinlogParser::from_reader(Cursor::new(bytes)).unwrap();
    let error = parser.events().next().unwrap().unwrap_err();
    let ParserError::Io { offset, source } = error else {
        panic!("expected an I/O parser error for types={types:?}, metadata={metadata:?}");
    };
    assert_eq!(offset, 4);
    assert_eq!(
        source.kind(),
        kind,
        "types={types:?}, metadata={metadata:?}: {source}"
    );
    assert!(parser.events().next().is_none());
}

#[test]
fn missing_required_column_metadata_is_rejected_before_any_row() {
    use ColumnType::*;

    for column_type in [
        MYSQL_TYPE_FLOAT,
        MYSQL_TYPE_DOUBLE,
        MYSQL_TYPE_TIMESTAMP2,
        MYSQL_TYPE_DATETIME2,
        MYSQL_TYPE_TIME2,
        MYSQL_TYPE_TINY_BLOB,
        MYSQL_TYPE_MEDIUM_BLOB,
        MYSQL_TYPE_LONG_BLOB,
        MYSQL_TYPE_BLOB,
        MYSQL_TYPE_GEOMETRY,
        MYSQL_TYPE_JSON,
        MYSQL_TYPE_VECTOR,
    ] {
        rejects_map(&[column_type as u8], &[], io::ErrorKind::InvalidData);
    }
    for column_type in [
        MYSQL_TYPE_VARCHAR,
        MYSQL_TYPE_NEWDECIMAL,
        MYSQL_TYPE_SET,
        MYSQL_TYPE_ENUM,
        MYSQL_TYPE_STRING,
        MYSQL_TYPE_BIT,
    ] {
        for metadata in [&[][..], &[0][..]] {
            rejects_map(&[column_type as u8], metadata, io::ErrorKind::InvalidData);
        }
    }
}

#[test]
fn missing_metadata_in_an_earlier_column_is_also_rejected() {
    use ColumnType::*;

    rejects_map(
        &[MYSQL_TYPE_VARCHAR as u8, MYSQL_TYPE_LONG as u8],
        &[10],
        io::ErrorKind::InvalidData,
    );
    rejects_map(
        &[
            MYSQL_TYPE_LONG as u8,
            MYSQL_TYPE_NEWDECIMAL as u8,
            MYSQL_TYPE_LONG as u8,
        ],
        &[5],
        io::ErrorKind::InvalidData,
    );
    rejects_map(
        &[MYSQL_TYPE_JSON as u8, MYSQL_TYPE_LONG as u8],
        &[],
        io::ErrorKind::InvalidData,
    );
}

#[test]
fn unsupported_dependency_metadata_layouts_fail_before_row_decoding() {
    use ColumnType::*;

    // The dependency exposes zero metadata bytes for raw VAR_STRING while
    // its value decoder indexes two bytes. A guessed VARCHAR layout would
    // also shift later columns, so the unsupported raw type stays explicit.
    for metadata in [&[][..], &[10, 0][..]] {
        rejects_map(
            &[MYSQL_TYPE_VAR_STRING as u8],
            metadata,
            io::ErrorKind::Unsupported,
        );
    }
    // TYPED_ARRAY is a real MySQL binlog type. The dependency strips the
    // element-type byte from its metadata, then its value decoder expects
    // that byte again. Even structurally complete metadata cannot repair it.
    for metadata in [
        &[][..],
        &[MYSQL_TYPE_LONG as u8][..],
        &[MYSQL_TYPE_VARCHAR as u8, 255, 0, 0][..],
    ] {
        rejects_map(
            &[MYSQL_TYPE_TYPED_ARRAY as u8],
            metadata,
            io::ErrorKind::Unsupported,
        );
    }
}

#[test]
fn valid_metadata_preserves_supported_rows_and_schema_only_inputs() {
    use ColumnType::*;

    for (column_type, metadata, value, expected) in [
        (
            MYSQL_TYPE_LONG,
            vec![],
            42i32.to_le_bytes().to_vec(),
            CellValue::Int(42),
        ),
        (
            MYSQL_TYPE_VARCHAR,
            vec![10, 0],
            b"\x03abc".to_vec(),
            CellValue::Bytes("616263".into()),
        ),
        (
            MYSQL_TYPE_STRING,
            vec![254, 10],
            b"\x03abc".to_vec(),
            CellValue::Bytes("616263".into()),
        ),
    ] {
        let map = table_map(&[column_type as u8], &metadata);
        let mut parser = BinlogParser::from_reader(Cursor::new(binlog(&map))).unwrap();
        let schema = parser.events().next().unwrap().unwrap();
        assert!(matches!(
            schema.payload,
            EventPayload::TableMap {
                column_count: 1,
                ..
            }
        ));
        assert!(parser.events().next().is_none());

        let mut bytes = binlog(&map);
        let mut body = vec![1, 0, 0, 0, 0, 0, 0, 0];
        body.extend([2, 0, 1, 1, 0]); // Extra-data length, count, bitmap, NULL bitmap.
        body.extend(value);
        bytes.extend(event(30, &body));
        let mut parser = BinlogParser::from_reader(Cursor::new(bytes)).unwrap();
        let events = parser.events().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(events.len(), 2);
        let EventPayload::Rows { changes, .. } = &events[1].payload else {
            panic!("expected a decoded row for {column_type:?}");
        };
        assert_eq!(
            changes[0].after.as_ref().unwrap().columns[0].value,
            expected
        );
    }

    let map = table_map(
        &[
            MYSQL_TYPE_VARCHAR as u8,
            MYSQL_TYPE_LONG as u8,
            MYSQL_TYPE_STRING as u8,
        ],
        &[10, 0, 254, 4],
    );
    let mut parser = BinlogParser::from_reader(Cursor::new(binlog(&map))).unwrap();
    assert!(matches!(
        parser.events().next().unwrap().unwrap().payload,
        EventPayload::TableMap {
            column_count: 3,
            ..
        }
    ));
    assert!(parser.events().next().is_none());
}
