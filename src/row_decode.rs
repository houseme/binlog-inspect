// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Convert mysql_common row values without exposing its types in the public event model.
//!
//! This module also pre-validates hostile table map optional metadata before it
//! reaches the underlying library: the library allocates variant vectors from
//! declared counts without bounding them, which aborts the process on crafted
//! input. The manual TLV walk in [`validate_table_map_metadata`] mirrors the
//! library's wire format exactly so no valid table map is rejected.
use crate::event::{CellValue, ColumnValue, RowImage, Signedness};
use mysql_common::{
    binlog::{
        events::{OptionalMetaExtractor, TableMapEvent},
        row::BinlogRow,
        value::BinlogValue,
    },
    constants::ColumnType,
    value::Value,
};
use std::io;

/// Optional metadata field types (TLV type codes) understood by the library.
///
/// Anything else is rejected by the library itself; mirroring the set keeps
/// this pre-validation from rejecting files the library would accept.
const KNOWN_TLV_TYPES: [u8; 13] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
/// `SET_STR_VALUE`: variant names of SET columns.
const TLV_SET_STR_VALUE: u8 = 5;
/// `ENUM_STR_VALUE`: variant names of ENUM columns.
const TLV_ENUM_STR_VALUE: u8 = 6;

/// Lowercase hex digits used for byte rendering.
const HEX: [u8; 16] = *b"0123456789abcdef";

pub(crate) fn decode_row(
    row: &BinlogRow,
    present: &[bool],
    signedness: &[Option<bool>],
) -> io::Result<RowImage> {
    let mut offset = 0;
    let mut columns = Vec::with_capacity(present.len());
    for (index, &included) in present.iter().enumerate() {
        if !included {
            columns.push(ColumnValue {
                index,
                name: None,
                mysql_type: None,
                signedness: None,
                value: CellValue::Absent,
            });
            continue;
        }
        let column = row.columns_ref().get(offset).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "row bitmap and column count differ",
            )
        })?;
        let value = row
            .as_ref(offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "row value missing"))?;
        let value = match value {
            BinlogValue::Value(value) => match value {
                Value::NULL => CellValue::Null,
                Value::Bytes(bytes) => {
                    let mut encoded = String::with_capacity(bytes.len() * 2);
                    for byte in bytes {
                        encoded.push(HEX[usize::from(byte >> 4)] as char);
                        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
                    }
                    CellValue::Bytes(encoded)
                }
                Value::Int(n) => CellValue::Int(*n),
                Value::UInt(n) => CellValue::UInt(*n),
                Value::Float(n) => CellValue::Float(n.to_string()),
                Value::Double(n) => CellValue::Double(n.to_string()),
                Value::Date(year, month, day, hour, minute, second, micros) => CellValue::Date {
                    year: *year,
                    month: *month,
                    day: *day,
                    hour: *hour,
                    minute: *minute,
                    second: *second,
                    micros: *micros,
                },
                Value::Time(negative, days, hours, minutes, seconds, micros) => CellValue::Time {
                    negative: *negative,
                    days: *days,
                    hours: *hours,
                    minutes: *minutes,
                    seconds: *seconds,
                    micros: *micros,
                },
            },
            BinlogValue::Jsonb(value) => CellValue::Json(
                serde_json::Value::try_from(value.clone())
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
            ),
            BinlogValue::JsonDiff(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "partial JSON updates are not supported",
                ));
            }
        };
        let mysql_type = column.column_type();
        let signedness = if mysql_type.is_numeric_type() {
            Some(match signedness.get(index).copied().flatten() {
                Some(true) => Signedness::Unsigned,
                Some(false) => Signedness::Signed,
                None => Signedness::Unknown,
            })
        } else {
            None
        };
        columns.push(ColumnValue {
            index,
            name: Some(column.name_str().into_owned()),
            mysql_type: Some(column_type_name(mysql_type).to_owned()),
            signedness,
            value,
        });
        offset += 1;
    }
    if offset != row.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "row bitmap and value count differ",
        ));
    }
    Ok(RowImage { columns })
}

/// Collects the present-column bitmap, validating that it covers all `n` columns.
///
/// Bits beyond `n` are legitimate padding; fewer than `n` bits means a
/// truncated bitmap, which must not be silently accepted.
pub(crate) fn present_bits(bits: impl Iterator<Item = bool>, n: usize) -> io::Result<Vec<bool>> {
    let collected: Vec<bool> = bits.take(n).collect();
    if collected.len() != n {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "row bitmap length does not match column count",
        ));
    }
    Ok(collected)
}

/// Canonical stable name for a MySQL column type.
///
/// The library's `Debug` output must not leak into the output model, so every
/// [`ColumnType`] variant maps to its short constant name.
pub(crate) fn column_type_name(column_type: ColumnType) -> &'static str {
    match column_type {
        ColumnType::MYSQL_TYPE_DECIMAL => "DECIMAL",
        ColumnType::MYSQL_TYPE_TINY => "TINY",
        ColumnType::MYSQL_TYPE_SHORT => "SHORT",
        ColumnType::MYSQL_TYPE_LONG => "LONG",
        ColumnType::MYSQL_TYPE_FLOAT => "FLOAT",
        ColumnType::MYSQL_TYPE_DOUBLE => "DOUBLE",
        ColumnType::MYSQL_TYPE_NULL => "NULL",
        ColumnType::MYSQL_TYPE_TIMESTAMP => "TIMESTAMP",
        ColumnType::MYSQL_TYPE_LONGLONG => "LONGLONG",
        ColumnType::MYSQL_TYPE_INT24 => "INT24",
        ColumnType::MYSQL_TYPE_DATE => "DATE",
        ColumnType::MYSQL_TYPE_TIME => "TIME",
        ColumnType::MYSQL_TYPE_DATETIME => "DATETIME",
        ColumnType::MYSQL_TYPE_YEAR => "YEAR",
        ColumnType::MYSQL_TYPE_NEWDATE => "NEWDATE",
        ColumnType::MYSQL_TYPE_VARCHAR => "VARCHAR",
        ColumnType::MYSQL_TYPE_BIT => "BIT",
        ColumnType::MYSQL_TYPE_TIMESTAMP2 => "TIMESTAMP2",
        ColumnType::MYSQL_TYPE_DATETIME2 => "DATETIME2",
        ColumnType::MYSQL_TYPE_TIME2 => "TIME2",
        ColumnType::MYSQL_TYPE_TYPED_ARRAY => "TYPED_ARRAY",
        ColumnType::MYSQL_TYPE_VECTOR => "VECTOR",
        ColumnType::MYSQL_TYPE_UNKNOWN => "UNKNOWN",
        ColumnType::MYSQL_TYPE_JSON => "JSON",
        ColumnType::MYSQL_TYPE_NEWDECIMAL => "NEWDECIMAL",
        ColumnType::MYSQL_TYPE_ENUM => "ENUM",
        ColumnType::MYSQL_TYPE_SET => "SET",
        ColumnType::MYSQL_TYPE_TINY_BLOB => "TINY_BLOB",
        ColumnType::MYSQL_TYPE_MEDIUM_BLOB => "MEDIUM_BLOB",
        ColumnType::MYSQL_TYPE_LONG_BLOB => "LONG_BLOB",
        ColumnType::MYSQL_TYPE_BLOB => "BLOB",
        ColumnType::MYSQL_TYPE_VAR_STRING => "VAR_STRING",
        ColumnType::MYSQL_TYPE_STRING => "STRING",
        ColumnType::MYSQL_TYPE_GEOMETRY => "GEOMETRY",
    }
}

/// Extract signedness in table-column order; None means metadata is unavailable.
pub(crate) fn signedness(map: &TableMapEvent<'_>) -> io::Result<Vec<Option<bool>>> {
    let metadata = OptionalMetaExtractor::new(map.iter_optional_meta())?;
    let mut values = metadata.iter_signedness();
    let mut result = Vec::new();
    for index in 0..map.columns_count() as usize {
        let ty = map
            .get_column_type(index)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing column type"))?;
        result.push(if ty.is_numeric_type() {
            values.next()
        } else {
            None
        });
    }
    Ok(result)
}

/// Validates table map optional metadata against the raw event bytes before
/// the library parses it.
///
/// Walks the same structure the library's `TableMapEvent` deserializer walks
/// (identical field order and encodings), then checks every optional metadata
/// TLV: declared lengths must fit the remaining bytes, only field types known
/// to the library are accepted, and ENUM/SET variant counts must fit the TLV
/// value (the library allocates from the declared count without bounding it).
///
/// Structural shortfalls deliberately return `Ok`: the library rejects those
/// deterministically with an end-of-stream error, so there is nothing to
/// prevent. Only cases that could abort the process are rejected here.
pub(crate) fn validate_table_map_metadata(body: &[u8], tme_header_length: u8) -> io::Result<()> {
    let pos = match walk_table_map_header(body, tme_header_length) {
        Some(pos) => pos,
        // The structure does not fit; the library will reject this event.
        None => return Ok(()),
    };
    let meta = &body[pos..];
    let mut pos = 0;
    while pos < meta.len() {
        let field_type = meta[pos];
        pos += 1;
        let len = match read_lenenc(meta, &mut pos)? {
            Some(len) => len as usize,
            // Invalid length-encoded integer; the library rejects it as well.
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid optional metadata length",
                ));
            }
        };
        let Some(value) = pos.checked_add(len).and_then(|end| meta.get(pos..end)) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "optional metadata TLV exceeds table map bounds",
            ));
        };
        pos += len;
        if !KNOWN_TLV_TYPES.contains(&field_type) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown optional metadata field type",
            ));
        }
        if field_type == TLV_SET_STR_VALUE || field_type == TLV_ENUM_STR_VALUE {
            validate_enum_set_variants(value)?;
        }
    }
    Ok(())
}

/// Walks the fixed part of a table map event and returns the offset of the
/// optional metadata block, or `None` if the event is too short.
fn walk_table_map_header(body: &[u8], tme_header_length: u8) -> Option<usize> {
    let mut pos = 0;
    // Old servers declare a 6-byte post-header and carry a 4-byte table id.
    pos += if tme_header_length == 6 { 4 } else { 6 };
    pos += 2; // flags
    for _ in 0..2 {
        let name_len = *body.get(pos)?;
        pos += 1 + usize::from(name_len) + 1; // length byte, name, NUL
    }
    // The library reads both counts through ParseBuf, whose lenenc decoding
    // maps the non-canonical 0xfb/0xff prefixes to zero instead of failing;
    // mirroring that keeps the walk running for events the library accepts.
    let columns_count = read_lenenc_lenient(body, &mut pos).ok()? as usize;
    let types_end = pos.checked_add(columns_count)?;
    if types_end > body.len() {
        return None;
    }
    pos = types_end;
    let meta_len = read_lenenc_lenient(body, &mut pos).ok()? as usize;
    let meta_end = pos.checked_add(meta_len)?;
    if meta_end > body.len() {
        return None;
    }
    pos = meta_end;
    let null_bytes = columns_count.div_ceil(8);
    let null_end = pos.checked_add(null_bytes)?;
    if null_end > body.len() {
        return None;
    }
    Some(null_end)
}

/// Validates the variant list of a SET/ENUM optional metadata TLV.
///
/// The library allocates a vector with the declared variant count before
/// reading anything, so an inflated count must be rejected here. The count is
/// decoded through the library's `ParseBuf` lenenc semantics (`0xfb`/`0xff`
/// mean zero), mirroring `RawInt<LenEnc>`.
fn validate_enum_set_variants(value: &[u8]) -> io::Result<()> {
    let mut pos = 0;
    let num_variants = read_lenenc_lenient(value, &mut pos)? as usize;
    // Every variant needs at least one length byte, so a count larger than the
    // remaining bytes can never be satisfied.
    if num_variants > value.len() - pos {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "enum/set variant count exceeds TLV bounds",
        ));
    }
    for _ in 0..num_variants {
        let len = match read_lenenc(value, &mut pos)? {
            Some(len) => len as usize,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid variant length",
                ));
            }
        };
        let Some(end) = pos.checked_add(len) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "variant length exceeds TLV bounds",
            ));
        };
        if end > value.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "variant name exceeds TLV bounds",
            ));
        }
        pos = end;
    }
    Ok(())
}

/// Reads a MySQL length-encoded integer the way the library's `ReadMysqlExt`
/// does for optional metadata TLV lengths: the non-canonical `0xfb`/`0xff`
/// prefixes are errors. Returns `None` for them.
fn read_lenenc(buf: &[u8], pos: &mut usize) -> io::Result<Option<u64>> {
    let Some(&first) = buf.get(*pos) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected end of length-encoded integer",
        ));
    };
    let extra = match first {
        x if x <= 0xfa => {
            *pos += 1;
            return Ok(Some(u64::from(x)));
        }
        0xfc => 2,
        0xfd => 3,
        0xfe => 8,
        0xfb | 0xff => return Ok(None),
        _ => unreachable!(),
    };
    let end = pos
        .checked_add(1 + extra)
        .filter(|end| *end <= buf.len())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected end of length-encoded integer",
            )
        })?;
    let mut raw = [0u8; 8];
    raw[..extra].copy_from_slice(&buf[*pos + 1..end]);
    *pos = end;
    Ok(Some(u64::from_le_bytes(raw)))
}

/// Reads a length-encoded integer through the library's `ParseBuf` semantics,
/// where the `0xfb`/`0xff` prefix byte is consumed and decodes to zero
/// instead of failing.
fn read_lenenc_lenient(buf: &[u8], pos: &mut usize) -> io::Result<u64> {
    match read_lenenc(buf, pos)? {
        Some(value) => Ok(value),
        None => {
            *pos += 1; // consume the prefix the way the library does
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mysql_common::{constants::ColumnType, packets::Column};

    #[test]
    fn distinguishes_absent_null_and_arbitrary_bytes() {
        let columns = vec![
            Column::new(ColumnType::MYSQL_TYPE_LONG).with_name(b"nil"),
            Column::new(ColumnType::MYSQL_TYPE_BLOB).with_name(b"payload"),
        ];
        let row = BinlogRow::new(
            vec![
                Some(BinlogValue::Value(Value::NULL)),
                Some(BinlogValue::Value(Value::Bytes(vec![0, 255, 34]))),
            ],
            columns.into(),
        );
        let image = decode_row(&row, &[false, true, true], &[None, None, None]).unwrap();
        let json = serde_json::to_value(image).unwrap();
        assert_eq!(json["columns"][0]["value"]["type"], "absent");
        assert_eq!(json["columns"][1]["value"]["type"], "null");
        assert_eq!(json["columns"][1]["signedness"], "unknown");
        assert_eq!(json["columns"][2]["value"]["value"], "00ff22");
        assert_eq!(json["columns"][2]["index"], 2);
        assert_eq!(json["columns"][1]["mysql_type"], "LONG");
        assert_eq!(json["columns"][2]["mysql_type"], "BLOB");
    }
    #[test]
    fn rejects_inconsistent_bitmap() {
        let row = BinlogRow::new(
            vec![Some(BinlogValue::Value(Value::Int(4)))],
            vec![Column::new(ColumnType::MYSQL_TYPE_LONG)].into(),
        );
        assert!(decode_row(&row, &[false], &[None]).is_err());
    }
    #[test]
    fn present_bits_must_cover_all_columns() {
        assert!(present_bits([true, false].into_iter(), 2).is_ok());
        let err = present_bits([true].into_iter(), 2).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // Padding bits beyond n are ignored, not an error.
        assert!(present_bits([true, false, true, false].into_iter(), 2).is_ok());
    }
    #[test]
    fn column_type_names_are_canonical() {
        assert_eq!(
            column_type_name(ColumnType::MYSQL_TYPE_LONGLONG),
            "LONGLONG"
        );
        assert_eq!(column_type_name(ColumnType::MYSQL_TYPE_JSON), "JSON");
        assert_eq!(column_type_name(ColumnType::MYSQL_TYPE_VECTOR), "VECTOR");
    }
    #[test]
    fn enum_tlv_with_bogus_variant_count_is_rejected() {
        // ENUM_STR_VALUE TLV declaring an absurd variant count.
        let mut tlv = vec![6u8];
        tlv.push(4); // TLV length
        tlv.push(0xfe); // variant count: 8-byte length-encoded integer follows
        tlv.extend_from_slice(&u64::MAX.to_le_bytes()[..3]);
        let mut body = vec![0u8; 6 + 2]; // table id + flags
        body.push(1); // database name length
        body.extend_from_slice(b"d\0");
        body.push(1); // table name length
        body.extend_from_slice(b"t\0");
        body.push(1); // one column
        body.push(0x03); // LONG
        body.push(0); // no column metadata
        body.push(1); // one null-bitmap byte
        body.extend_from_slice(&tlv);
        let err = validate_table_map_metadata(&body, 8).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
    #[test]
    fn well_formed_tlv_block_is_accepted() {
        // SIGNEDNESS for two numeric columns, plus ENUM_STR_VALUE with a
        // single variant "a".
        let mut tlv = vec![1u8, 1, 0];
        tlv.extend_from_slice(&[6, 3, 1, 1, b'a']);
        let mut body = vec![0u8; 6 + 2]; // table id + flags
        body.push(1);
        body.extend_from_slice(b"d\0");
        body.push(1);
        body.extend_from_slice(b"t\0");
        body.push(2); // two columns
        body.extend_from_slice(&[0x03, 0x03]); // two LONG columns
        body.push(0); // no column metadata
        body.push(1); // one null-bitmap byte
        body.extend_from_slice(&tlv);
        validate_table_map_metadata(&body, 8).unwrap();
    }
    #[test]
    fn unknown_tlv_type_is_rejected() {
        let tlv = vec![99u8, 1, 0];
        let mut body = vec![0u8; 6 + 2];
        body.push(1);
        body.extend_from_slice(b"d\0");
        body.push(1);
        body.extend_from_slice(b"t\0");
        body.push(1);
        body.push(0x03);
        body.push(0);
        body.push(1);
        body.extend_from_slice(&tlv);
        let err = validate_table_map_metadata(&body, 8).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Builds a table map body whose optional metadata block is `tlv`, with a
    /// zero-prefix column count like the library's `ParseBuf` decoding yields.
    fn body_with_lenient_header(tlv: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; 6 + 2]; // table id + flags
        body.push(1);
        body.extend_from_slice(b"d\0");
        body.push(1);
        body.extend_from_slice(b"t\0");
        body.push(0xfb); // non-canonical zero column count
        body.push(0); // no column metadata
        body.extend_from_slice(tlv);
        body
    }

    #[test]
    fn noncanonical_lenenc_prefixes_mirror_the_library() {
        // The library decodes a 0xfb column count as zero and keeps parsing,
        // so the pre-walk must continue too: the unknown TLV type after the
        // header is what gets rejected, not the prefix.
        let tlv = vec![99u8, 1, 0];
        let err = validate_table_map_metadata(&body_with_lenient_header(&tlv), 8).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("optional metadata field type"));
    }

    #[test]
    fn enum_variant_count_lenient_prefix_is_accepted() {
        // A 0xff variant count decodes to zero variants in the library.
        let tlv = vec![6u8, 1, 0xff];
        let mut body = vec![0u8; 6 + 2];
        body.push(1);
        body.extend_from_slice(b"d\0");
        body.push(1);
        body.extend_from_slice(b"t\0");
        body.push(1);
        body.push(0x03);
        body.push(0);
        body.push(1);
        body.extend_from_slice(&tlv);
        validate_table_map_metadata(&body, 8).unwrap();
    }

    #[test]
    fn tlv_length_strict_prefix_is_rejected() {
        // TLV lengths go through the library's strict reader, so 0xff there
        // is an error, not a zero.
        let tlv = vec![1u8, 0xff, 0];
        let mut body = vec![0u8; 6 + 2];
        body.push(1);
        body.extend_from_slice(b"d\0");
        body.push(1);
        body.extend_from_slice(b"t\0");
        body.push(1);
        body.push(0x03);
        body.push(0);
        body.push(1);
        body.extend_from_slice(&tlv);
        let err = validate_table_map_metadata(&body, 8).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
