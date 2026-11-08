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
    binlog::{events::TableMapEvent, jsonb, row::BinlogRow, value::BinlogValue},
    constants::ColumnType,
    proto::MySerialize,
    value::Value,
};
use std::io;

/// Optional metadata field types (TLV type codes) accepted by the
/// pre-validation walk.
///
/// The underlying library only knows the types 1..=13; the partial-JSON types
/// 14 and 15 (WL#2955) are accepted here and stripped from the event body
/// before the library parses the table map, because its metadata iterator
/// rejects unknown types. Anything else is rejected.
const KNOWN_TLV_TYPES: [u8; 15] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
/// `SIGNEDNESS`: unsigned flags of numeric columns (MSB-first bitmap).
const TLV_SIGNEDNESS: u8 = 1;
/// `SET_STR_VALUE`: variant names of SET columns.
const TLV_SET_STR_VALUE: u8 = 5;
/// `ENUM_STR_VALUE`: variant names of ENUM columns.
const TLV_ENUM_STR_VALUE: u8 = 6;
/// `PARTIAL_JSON_UPDATE`: bitmap of columns logged as partial JSON updates.
const TLV_PARTIAL_JSON_UPDATE: u8 = 14;
/// `UPDATED_COLUMN_TYPES`: actual data types of updated columns.
const TLV_UPDATED_COLUMN_TYPES: u8 = 15;

/// Lowercase hex digits used for byte rendering.
const HEX: [u8; 16] = *b"0123456789abcdef";

/// Maximum jsonb nesting depth accepted by the conversion.
///
/// MySQL's JSON implementation rejects documents nested deeper than 100
/// levels, so values written by a real server never exceed this; anything
/// deeper is hostile input. The cap also bounds the recursion of
/// [`jsonb_to_serde`], so over-deep input returns a clean `InvalidData`
/// error instead of overflowing the stack.
const MAX_JSONB_DEPTH: usize = 100;

/// Default budget on the serde nodes a single jsonb conversion may produce.
///
/// The jsonb format stores a child offset per container entry, so crafted
/// containers can point every entry at the same child subtree and amplify a
/// linear-size wire value into an exponentially larger decoded tree: the
/// reproduction that motivated this budget decodes 221 wire bytes (22 aliased
/// small-array containers) into 8,388,607 serde nodes, and a ~331-byte chain
/// demands ~275 GB before the [`MAX_JSONB_DEPTH`] cap can fire. Every node
/// the conversion produces — scalar or container, containers counting
/// themselves plus, through the recursion, their children — is charged one
/// against the counter threaded through [`jsonb_to_serde`]; the counter is
/// monotone across the whole conversion, so aliasing cannot reset it.
/// Exceeding the budget returns a clean `InvalidData` error instead of
/// allocating towards an allocator abort (R48).
const DEFAULT_JSONB_NODE_BUDGET: usize = 1_000_000;

/// Converts a library jsonb value into the serde_json model.
///
/// Containers are converted here so the conversion recursion is capped at
/// [`MAX_JSONB_DEPTH`]; deeper (hostile) input returns `InvalidData` instead
/// of overflowing the stack. Every scalar — including the opaque values
/// MySQL writes for decimal literals and DECIMAL column values, and for
/// DATE/TIME/DATETIME values inside JSON — is converted through the
/// library's own [`jsonb::Value::parse`] rendering, whose documented rules
/// turn `NEWDECIMAL` opaques into their decimal text form,
/// DATE/TIME/DATETIME opaques into their text form, and every other opaque
/// into a `base64:type<id>:<data>` string. Legitimate data therefore never
/// fails the event.
///
/// `nodes` is the decoded-node counter shared by the whole conversion: every
/// converted node charges one against it, and exceeding
/// [`DEFAULT_JSONB_NODE_BUDGET`] returns `InvalidData`. Each value
/// conversion entry point (the row-value path and the diff-value path) owns
/// one counter and must never reset it mid-conversion.
fn jsonb_to_serde(
    value: &jsonb::Value<'_>,
    depth: usize,
    nodes: &mut usize,
) -> io::Result<serde_json::Value> {
    *nodes += 1;
    if *nodes > DEFAULT_JSONB_NODE_BUDGET {
        return Err(jsonb_over_node_budget());
    }
    match value {
        jsonb::Value::SmallArray(container) => {
            if depth > MAX_JSONB_DEPTH {
                return Err(jsonb_too_deep());
            }
            // Untrusted count; the vector grows on demand.
            let mut items = Vec::with_capacity(container.element_count().min(4096) as usize);
            for item in container.iter() {
                items.push(jsonb_to_serde(&item?, depth + 1, nodes)?);
            }
            Ok(serde_json::Value::Array(items))
        }
        jsonb::Value::LargeArray(container) => {
            if depth > MAX_JSONB_DEPTH {
                return Err(jsonb_too_deep());
            }
            // Untrusted count; the vector grows on demand.
            let mut items = Vec::with_capacity(container.element_count().min(4096) as usize);
            for item in container.iter() {
                items.push(jsonb_to_serde(&item?, depth + 1, nodes)?);
            }
            Ok(serde_json::Value::Array(items))
        }
        jsonb::Value::SmallObject(container) => {
            if depth > MAX_JSONB_DEPTH {
                return Err(jsonb_too_deep());
            }
            let mut members = serde_json::Map::new();
            for entry in container.iter() {
                let (key, value) = entry?;
                members.insert(
                    key.value().into_owned(),
                    jsonb_to_serde(&value, depth + 1, nodes)?,
                );
            }
            Ok(serde_json::Value::Object(members))
        }
        jsonb::Value::LargeObject(container) => {
            if depth > MAX_JSONB_DEPTH {
                return Err(jsonb_too_deep());
            }
            let mut members = serde_json::Map::new();
            for entry in container.iter() {
                let (key, value) = entry?;
                members.insert(
                    key.value().into_owned(),
                    jsonb_to_serde(&value, depth + 1, nodes)?,
                );
            }
            Ok(serde_json::Value::Object(members))
        }
        // Scalars carry no recursion, so they are converted through the
        // library's own JsonDom rendering (including its opaque string rules).
        other => Ok(serde_json::Value::from(other.clone().parse()?)),
    }
}

/// The rejection error for jsonb input nested deeper than [`MAX_JSONB_DEPTH`].
fn jsonb_too_deep() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("jsonb nesting depth exceeds the MySQL limit of {MAX_JSONB_DEPTH} levels"),
    )
}

/// The rejection error for jsonb input decoding beyond
/// [`DEFAULT_JSONB_NODE_BUDGET`].
fn jsonb_over_node_budget() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("jsonb decoding exceeds the node budget of {DEFAULT_JSONB_NODE_BUDGET} nodes"),
    )
}

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
            BinlogValue::Jsonb(value) => {
                // One node budget per value conversion entry point; a failure
                // here aborts the row, so the counter never spans cells.
                let mut nodes = 0usize;
                CellValue::Json(jsonb_to_serde(value, 1, &mut nodes)?)
            }
            BinlogValue::JsonDiff(diffs) => {
                // Without a paired before image (see [`decode_rows_pair`])
                // there is nothing to apply the diffs to; they are preserved
                // as a recorded loss instead of failing the whole image.
                let (diffs, problem) = json_diff::parse_diffs(diffs);
                CellValue::PartialJson {
                    diffs,
                    reason: problem
                        .unwrap_or_else(|| "no before image to apply diffs against".to_owned()),
                }
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

/// Decodes the before and after images of an updated row as a pair.
///
/// Partial-JSON after images (WL#2955) carry a sequence of binlog JSON diffs
/// per JSON column instead of a full document. Each such sequence is applied
/// to the before image's decoded value at the same column index: on success
/// the after cell becomes [`CellValue::Json`] with the full new document, on
/// any failure it becomes [`CellValue::PartialJson`] with the preserved diffs
/// and the reason. Images without diffs decode exactly like [`decode_row`].
pub(crate) fn decode_rows_pair(
    before_row: Option<&BinlogRow>,
    after_row: Option<&BinlogRow>,
    before_present: Option<&[bool]>,
    after_present: Option<&[bool]>,
    signedness: &[Option<bool>],
) -> io::Result<(Option<RowImage>, Option<RowImage>)> {
    let before = before_row
        .map(|row| {
            decode_row(
                row,
                before_present.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing before bitmap")
                })?,
                signedness,
            )
        })
        .transpose()?;
    let mut after = after_row
        .map(|row| {
            decode_row(
                row,
                after_present.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing after bitmap")
                })?,
                signedness,
            )
        })
        .transpose()?;
    if let (Some(before), Some(after)) = (&before, after.as_mut()) {
        apply_pair(before, after);
    }
    Ok((before, after))
}

/// Replaces the provisional [`CellValue::PartialJson`] cells of the after
/// image by applying their diffs against the before image's values.
///
/// Cells whose diffs were already resolved (or whose before counterpart
/// offers no JSON value to apply against) keep their state.
///
/// Both images are in table-column order, so the before cursor advances
/// monotonically — a linear merge instead of a per-cell search (R42).
fn apply_pair(before: &RowImage, after: &mut RowImage) {
    let mut cursor = before.columns.iter();
    let mut candidate = cursor.next();
    for after_cell in after.columns.iter_mut() {
        // Advance the before cursor to this column's index; both images are
        // sorted by column index, so the cursor never moves backwards.
        while candidate.is_some_and(|cell| cell.index < after_cell.index) {
            candidate = cursor.next();
        }
        if !matches!(after_cell.value, CellValue::PartialJson { .. }) {
            continue;
        }
        let CellValue::PartialJson { diffs, .. } = &after_cell.value else {
            continue;
        };
        let diffs = diffs.clone();
        // A gap (no before cell at this index) keeps the loss-marked value,
        // matching the previous search-based behavior.
        let Some(before_cell) = candidate.filter(|cell| cell.index == after_cell.index) else {
            continue;
        };
        let replacement = match &before_cell.value {
            CellValue::Json(before_value) => {
                match json_diff::apply_json_diffs(before_value.clone(), &diffs) {
                    Ok(applied) => CellValue::Json(applied),
                    Err(error) => CellValue::PartialJson {
                        diffs,
                        reason: error.0,
                    },
                }
            }
            CellValue::Absent => CellValue::PartialJson {
                diffs,
                reason: "before column is absent".to_owned(),
            },
            _ => CellValue::PartialJson {
                diffs,
                reason: "before value is not JSON".to_owned(),
            },
        };
        after_cell.value = replacement;
    }
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
///
/// The SIGNEDNESS TLV is located with a direct walk of the re-serialized
/// table map body instead of the library's metadata extractor: the library's
/// iterator hard-errors on the partial-JSON metadata types (14, 15) that
/// partial-JSON binlogs carry, which would defeat their handling.
pub(crate) fn signedness(map: &TableMapEvent<'_>) -> io::Result<Vec<Option<bool>>> {
    validate_column_metadata(map)?;
    let bits = signedness_bits(map)?;
    let mut numeric = 0usize;
    let mut result = Vec::new();
    for index in 0..map.columns_count() as usize {
        let ty = map
            .get_column_type(index)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing column type"))?;
        result.push(if ty.is_numeric_type() {
            let bit = bitmap_bit(bits.as_deref(), numeric);
            numeric += 1;
            bit
        } else {
            None
        });
    }
    Ok(result)
}

/// Validate metadata before the dependency substitutes an empty slice for
/// missing metadata and indexes it during row decoding.
fn validate_column_metadata(map: &TableMapEvent<'_>) -> io::Result<()> {
    let count = usize::try_from(map.columns_count())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "column count overflow"))?;
    for index in 0..count {
        let column_type = map
            .get_raw_column_type(index)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing column type"))?;
        // mysql_common gives VAR_STRING zero metadata bytes but its value
        // decoder requires two. TYPED_ARRAY strips the element type before
        // its value decoder tries to read it again. Reject both explicitly.
        if matches!(
            column_type,
            ColumnType::MYSQL_TYPE_VAR_STRING | ColumnType::MYSQL_TYPE_TYPED_ARRAY
        ) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "unsupported binlog column type {}",
                    column_type_name(column_type)
                ),
            ));
        }
    }
    // The getter walks every preceding column, so checking the last column
    // once validates the complete metadata span in linear time.
    if let Some(last) = count.checked_sub(1)
        && map.get_column_metadata(last).is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "table map column metadata is truncated",
        ));
    }
    Ok(())
}

/// Reads the SIGNEDNESS (type 1) TLV value of a table map event, if any.
///
/// The event is serialized back into its wire body (always the current
/// 6-byte-table-id form) and the optional metadata block is located with the
/// same structural walk the pre-validation uses, so the raw TLV bytes can be
/// scanned without going through the library's metadata iterator. The last
/// SIGNEDNESS entry wins, mirroring the library's extraction.
fn signedness_bits(map: &TableMapEvent<'_>) -> io::Result<Option<Vec<u8>>> {
    let mut body = Vec::new();
    map.serialize(&mut body);
    let pos = walk_table_map_header(&body, 8)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "table map does not fit"))?;
    let mut signedness = None;
    for entry in collect_tlvs(&body[pos..])? {
        if entry.field_type == TLV_SIGNEDNESS {
            signedness = Some(body[pos + entry.value.start..pos + entry.value.end].to_vec());
        }
    }
    Ok(signedness)
}

/// Reads one bit of an MSB-first bitmap (`0x80 >> (index % 8)` of byte
/// `index / 8`, one bit per column of the covered kind in table order).
///
/// Bits beyond the available bytes mean the metadata was absent or shorter
/// than the column count; the library reports unknown signedness then, too.
fn bitmap_bit(bytes: Option<&[u8]>, index: usize) -> Option<bool> {
    let byte = *bytes?.get(index / 8)?;
    Some(byte & (0x80 >> (index % 8)) != 0)
}

/// One scanned optional metadata TLV entry: its field type, the byte range of
/// the whole entry (type byte, length prefix, and value), and the byte range
/// of the value alone — both relative to the metadata block.
struct TlvEntry {
    field_type: u8,
    entry: std::ops::Range<usize>,
    value: std::ops::Range<usize>,
}

/// Scans the optional metadata block into its TLV entries.
///
/// Length prefixes are decoded with the library's strict reader, so a
/// non-canonical `0xfb`/`0xff` prefix or a truncated prefix is an error, and a
/// declared length that exceeds the metadata block is an error — mirroring the
/// previous inline walk exactly.
fn collect_tlvs(meta: &[u8]) -> io::Result<Vec<TlvEntry>> {
    let mut pos = 0;
    let mut entries = Vec::new();
    while pos < meta.len() {
        let start = pos;
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
        let value_start = pos;
        let Some(value_end) = pos.checked_add(len).filter(|end| *end <= meta.len()) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "optional metadata TLV exceeds table map bounds",
            ));
        };
        entries.push(TlvEntry {
            field_type,
            entry: start..value_end,
            value: value_start..value_end,
        });
        pos = value_end;
    }
    Ok(entries)
}

/// Validates table map optional metadata against the raw event bytes before
/// the library parses it.
///
/// Walks the same structure the library's `TableMapEvent` deserializer walks
/// (identical field order and encodings), then checks every optional metadata
/// TLV: declared lengths must fit the remaining bytes, only field types known
/// to the library or belonging to the partial-JSON extension are accepted, and
/// ENUM/SET variant counts must fit the TLV value (the library allocates from
/// the declared count without bounding it).
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
    for entry in collect_tlvs(&body[pos..])? {
        if !KNOWN_TLV_TYPES.contains(&entry.field_type) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown optional metadata field type",
            ));
        }
        if entry.field_type == TLV_SET_STR_VALUE || entry.field_type == TLV_ENUM_STR_VALUE {
            validate_enum_set_variants(&body[pos + entry.value.start..pos + entry.value.end])?;
        }
    }
    Ok(())
}

/// Byte ranges (relative to the table map event body) of the optional
/// metadata entries the underlying library cannot iterate.
///
/// The library stores a table map's optional metadata raw and iterates it
/// lazily when decoding rows; its iterator rejects the partial-JSON types 14
/// (`PARTIAL_JSON_UPDATE`) and 15 (`UPDATED_COLUMN_TYPES`) with a hard error,
/// so those entries must be removed from the event body before the library
/// parses the table map. Returns `None` when the event structure does not fit
/// the expected layout — the library rejects such events deterministically,
/// so there is nothing to strip.
pub(crate) fn unsupported_tlv_ranges(
    body: &[u8],
    tme_header_length: u8,
) -> io::Result<Option<Vec<std::ops::Range<usize>>>> {
    let Some(pos) = walk_table_map_header(body, tme_header_length) else {
        return Ok(None);
    };
    let mut ranges = Vec::new();
    for entry in collect_tlvs(&body[pos..])? {
        if entry.field_type == TLV_PARTIAL_JSON_UPDATE
            || entry.field_type == TLV_UPDATED_COLUMN_TYPES
        {
            ranges.push((pos + entry.entry.start)..(pos + entry.entry.end));
        }
    }
    Ok(Some(ranges))
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

/// Validates every column variant list in a SET/ENUM optional metadata TLV.
///
/// The library allocates a vector with the declared variant count before
/// reading anything, so an inflated count must be rejected here. The count is
/// decoded through the library's `ParseBuf` lenenc semantics (`0xfb`/`0xff`
/// mean zero), mirroring `RawInt<LenEnc>`.
fn validate_enum_set_variants(value: &[u8]) -> io::Result<()> {
    let mut pos = 0;
    loop {
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
        if pos == value.len() {
            break;
        }
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

/// Application of WL#2955 binlog JSON diffs to a before value.
///
/// A partial JSON after image stores, per JSON column, a sequence of logical
/// changes (`replace`/`insert`/`remove`) that the MySQL applier replays
/// against the before image's full document. This module parses the MySQL
/// JSON path text form of each diff and applies the operations to a
/// [`serde_json::Value`], matching the server's behavior of failing the whole
/// application when a path cannot be traversed or a precondition (existing
/// member, array bounds) does not hold.
mod json_diff {
    use crate::event::JsonDiffRecord;
    use mysql_common::binlog::jsondiff::{JsonDiff, JsonDiffOperation};

    /// Why a sequence of binlog JSON diffs could not be applied.
    ///
    /// The message is user-facing (it becomes the `reason` of
    /// [`CellValue::PartialJson`]), so it always names the offending path.
    #[derive(Debug, Clone, PartialEq)]
    pub(super) struct ApplyError(pub(super) String);

    /// The operation kind of a binlog JSON diff.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Operation {
        /// Set the value at the path.
        Replace,
        /// Add a new member or array element at the path.
        Insert,
        /// Delete the member or array element at the path.
        Remove,
    }

    impl Operation {
        fn name(self) -> &'static str {
            match self {
                Self::Replace => "replace",
                Self::Insert => "insert",
                Self::Remove => "remove",
            }
        }

        fn parse(name: &str) -> Result<Self, ApplyError> {
            match name {
                "replace" => Ok(Self::Replace),
                "insert" => Ok(Self::Insert),
                "remove" => Ok(Self::Remove),
                other => Err(ApplyError(format!("unknown diff operation `{other}`"))),
            }
        }
    }

    /// One segment of a concrete MySQL JSON path.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Segment {
        /// An object member, resolved by name.
        Member(String),
        /// An array element, resolved by zero-based index.
        Index(usize),
    }

    /// Converts the library's parsed diffs of one column into model records.
    ///
    /// A diff whose binary JSON value cannot be converted at all (invalid
    /// UTF-8 in a string member, or nesting beyond the jsonb depth cap or the
    /// node budget) yields `None` for its value and is reported in the
    /// returned problem
    /// note instead of failing the whole column; opaque values convert like
    /// any other scalar (see [`super::jsonb_to_serde`]).
    pub(super) fn parse_diffs(diffs: &[JsonDiff<'_>]) -> (Vec<JsonDiffRecord>, Option<String>) {
        let mut parsed = Vec::with_capacity(diffs.len());
        let mut problem = None;
        // The whole diff sequence shares one monotone node budget (R48): an
        // unrepresentable value does not abort the loop, so a fresh budget
        // per diff would let hostile values each re-amplify to the limit.
        let mut nodes = 0usize;
        for diff in diffs {
            let operation = match diff.operation() {
                JsonDiffOperation::REPLACE => Operation::Replace,
                JsonDiffOperation::INSERT => Operation::Insert,
                JsonDiffOperation::REMOVE => Operation::Remove,
            };
            let value = match diff.value() {
                Some(jsonb) => match super::jsonb_to_serde(jsonb, 1, &mut nodes) {
                    Ok(value) => Some(value),
                    Err(error) => {
                        problem.get_or_insert_with(|| {
                            format!("diff value is not representable as JSON ({error})")
                        });
                        None
                    }
                },
                None => None,
            };
            parsed.push(JsonDiffRecord {
                path: diff.path_str().into_owned(),
                operation: operation.name().to_owned(),
                value,
            });
        }
        (parsed, problem)
    }

    /// Applies a sequence of diffs to a before value, in order.
    ///
    /// Mirrors the MySQL applier: the first failure aborts the whole
    /// application, leaving no partial result behind.
    pub(super) fn apply_json_diffs(
        before: serde_json::Value,
        diffs: &[JsonDiffRecord],
    ) -> Result<serde_json::Value, ApplyError> {
        let mut value = before;
        for diff in diffs {
            apply_one(&mut value, diff)?;
        }
        // Applying a ≤100-deep diff value at a deep path composes documents
        // whose depth no input cap bounds: a REPLACE can re-insert a
        // 100-level chain at a leaf, adding ~99 levels per diff. The output
        // serializer recurses, so an unbounded composite would abort the
        // process; a composed document beyond MySQL's limit is a loss record
        // instead (real server diffs never compose beyond it).
        if json_depth(&value) > super::MAX_JSONB_DEPTH {
            return Err(ApplyError(
                "the composed document exceeds the nesting limit of 100 levels".to_owned(),
            ));
        }
        Ok(value)
    }

    /// Maximum container depth of a JSON value, matching jsonb_to_serde.
    /// Scalars add no container level. The explicit stack bounds recursion
    /// while inspecting a potentially hostile composed document.
    fn json_depth(value: &serde_json::Value) -> usize {
        let mut max = 0;
        let mut stack = vec![(value, 1usize)];
        while let Some((current, depth)) = stack.pop() {
            match current {
                serde_json::Value::Array(items) => {
                    max = max.max(depth);
                    stack.extend(items.iter().map(|item| (item, depth + 1)));
                }
                serde_json::Value::Object(members) => {
                    max = max.max(depth);
                    stack.extend(members.values().map(|member| (member, depth + 1)));
                }
                _ => {}
            }
        }
        max
    }

    /// Applies a single diff to a value in place.
    ///
    /// Edge-case semantics, pinned to the server's applier (MySQL
    /// `sql-common/json_diff.cc`): an object REPLACE behaves as an upsert (it also
    /// adds the member when it is absent), and an array INSERT accepts
    /// index == length (append) but not beyond. Real server diffs always
    /// target existing paths, so these edges only decide how malformed or
    /// hostile diff sequences render; the tests in this module and in
    /// `tests/partial_json.rs` pin them.
    fn apply_one(value: &mut serde_json::Value, diff: &JsonDiffRecord) -> Result<(), ApplyError> {
        let at = |what: &'static str| ApplyError(format!("path `{}`: {what}", diff.path));
        let operation = Operation::parse(&diff.operation)?;
        let segments = parse_path(&diff.path)?;
        // Depth bound enforced BEFORE any mutation: an inserted value of
        // depth `json_depth(value)` at a path `segments.len()` levels down
        // composes a document that deep. The composite is dropped
        // recursively and serialized recursively, so it must never be built
        // past the limit — rejecting the diff early keeps every reachable
        // state within it (R44 verification finding D1).
        if let Some(new_value) = &diff.value
            && segments.len() + json_depth(new_value) > super::MAX_JSONB_DEPTH
        {
            return Err(at(
                "the composed document would exceed the nesting limit of 100 levels",
            ));
        }
        let Some((last, parents)) = segments.split_last() else {
            // The bare `$` path targets the whole document.
            return match operation {
                Operation::Replace => {
                    let Some(new_value) = &diff.value else {
                        return Err(at("the operation carries no value"));
                    };
                    *value = new_value.clone();
                    Ok(())
                }
                Operation::Insert | Operation::Remove => {
                    Err(at("cannot insert or remove the document root"))
                }
            };
        };
        let mut current = value;
        for segment in parents {
            current = match segment {
                Segment::Member(key) => match current {
                    serde_json::Value::Object(map) => map
                        .get_mut(key)
                        .ok_or_else(|| at("parent path element does not exist"))?,
                    _ => return Err(at("parent path element is not an object")),
                },
                Segment::Index(index) => match current {
                    serde_json::Value::Array(items) => items
                        .get_mut(*index)
                        .ok_or_else(|| at("parent path element does not exist"))?,
                    _ => return Err(at("parent path element is not an array")),
                },
            };
        }
        let new_value = || {
            diff.value
                .clone()
                .ok_or_else(|| at("the operation carries no value"))
        };
        match operation {
            Operation::Replace => match (last, current) {
                (Segment::Member(key), serde_json::Value::Object(map)) => {
                    map.insert(key.clone(), new_value()?);
                    Ok(())
                }
                (Segment::Index(index), serde_json::Value::Array(items))
                    if *index < items.len() =>
                {
                    items[*index] = new_value()?;
                    Ok(())
                }
                _ => Err(at("replace target does not exist")),
            },
            Operation::Insert => match (last, current) {
                (Segment::Member(key), serde_json::Value::Object(map)) => {
                    if map.contains_key(key) {
                        return Err(at("insert on an existing member"));
                    }
                    map.insert(key.clone(), new_value()?);
                    Ok(())
                }
                (Segment::Index(index), serde_json::Value::Array(items))
                    if *index <= items.len() =>
                {
                    items.insert(*index, new_value()?);
                    Ok(())
                }
                _ => Err(at("insert target is not applicable")),
            },
            Operation::Remove => match (last, current) {
                (Segment::Member(key), serde_json::Value::Object(map)) => map
                    .remove(key)
                    .map(|_| ())
                    .ok_or_else(|| at("remove target does not exist")),
                (Segment::Index(index), serde_json::Value::Array(items))
                    if *index < items.len() =>
                {
                    items.remove(*index);
                    Ok(())
                }
                _ => Err(at("remove target does not exist")),
            },
        }
    }

    /// Parses the MySQL JSON path text form of a diff.
    ///
    /// Accepted accessors after the required `$`: bare member names
    /// (`[A-Za-z0-9_$]+`, the MySQL bare-key set), quoted member names
    /// (`."name"` and `["name"]`, double or single quotes, with backslash
    /// escapes), and array indices (`[0]`). Wildcards (`$.*`, `$**`) are
    /// rejected: binlog diffs always carry concrete paths.
    fn parse_path(path: &str) -> Result<Vec<Segment>, ApplyError> {
        let invalid =
            |what: &'static str| ApplyError(format!("invalid JSON path `{path}`: {what}"));
        let rest = path
            .strip_prefix('$')
            .ok_or_else(|| invalid("must start with `$`"))?;
        let bytes = rest.as_bytes();
        let mut pos = 0usize;
        let mut segments = Vec::new();
        while pos < bytes.len() {
            match bytes[pos] {
                b'.' => {
                    pos += 1;
                    if matches!(bytes.get(pos), Some(b'"') | Some(b'\'')) {
                        let quote = bytes[pos];
                        let key = read_quoted_member(rest, &mut pos, quote)?;
                        segments.push(Segment::Member(key));
                    } else {
                        let start = pos;
                        while bytes.get(pos).is_some_and(|byte| {
                            byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'$'
                        }) {
                            pos += 1;
                        }
                        if pos == start {
                            return Err(invalid("empty member name"));
                        }
                        // Only ASCII was consumed, so slicing is valid UTF-8.
                        segments.push(Segment::Member(rest[start..pos].to_owned()));
                    }
                }
                b'[' => {
                    pos += 1;
                    if matches!(bytes.get(pos), Some(b'"') | Some(b'\'')) {
                        let quote = bytes[pos];
                        let key = read_quoted_member(rest, &mut pos, quote)?;
                        if bytes.get(pos) != Some(&b']') {
                            return Err(invalid("unterminated bracketed member"));
                        }
                        pos += 1;
                        segments.push(Segment::Member(key));
                    } else if bytes.get(pos).is_some_and(|byte| byte.is_ascii_digit()) {
                        let start = pos;
                        while bytes.get(pos).is_some_and(|byte| byte.is_ascii_digit()) {
                            pos += 1;
                        }
                        let index: usize = rest[start..pos]
                            .parse()
                            .map_err(|_| invalid("array index overflow"))?;
                        if bytes.get(pos) != Some(&b']') {
                            return Err(invalid("unterminated array index"));
                        }
                        pos += 1;
                        segments.push(Segment::Index(index));
                    } else {
                        return Err(invalid("expected a quoted member name or an array index"));
                    }
                }
                _ => return Err(invalid("unsupported path syntax")),
            }
        }
        Ok(segments)
    }

    /// Reads a quoted member name starting at the opening quote byte, which
    /// may be `"` or `'`, advancing `pos` past the closing quote.
    ///
    /// Double-quoted members use JSON string decoding, including UTF-16
    /// surrogate pairs and validation of escape sequences, as in MySQL's
    /// `sql-common/json_path.cc`. The single-quoted extension retains its
    /// historical escape handling.
    fn read_quoted_member(rest: &str, pos: &mut usize, quote: u8) -> Result<String, ApplyError> {
        if quote == b'"' {
            // Decode just the string token so subsequent path segments stay
            // available to parse_path. Reuse serde's escape validation.
            let mut strings =
                serde_json::Deserializer::from_str(&rest[*pos..]).into_iter::<String>();
            let key = strings
                .next()
                .ok_or_else(|| {
                    ApplyError(format!(
                        "invalid JSON path `${rest}`: missing quoted member"
                    ))
                })?
                .map_err(|error| ApplyError(format!("invalid JSON path `${rest}`: {error}")))?;
            *pos += strings.byte_offset();
            return Ok(key);
        }
        let bytes = rest.as_bytes();
        *pos += 1; // opening quote
        let mut key = Vec::new();
        loop {
            let Some(&byte) = bytes.get(*pos) else {
                return Err(ApplyError(format!(
                    "invalid JSON path `${rest}`: unterminated quoted member name"
                )));
            };
            *pos += 1;
            match byte {
                byte if byte == quote => break,
                b'\\' => {
                    let Some(&escape) = bytes.get(*pos) else {
                        return Err(ApplyError(format!(
                            "invalid JSON path `${rest}`: unterminated escape sequence"
                        )));
                    };
                    *pos += 1;
                    match escape {
                        b'n' => key.push(b'\n'),
                        b'r' => key.push(b'\r'),
                        b't' => key.push(b'\t'),
                        b'b' => key.push(b'\x08'),
                        b'0' => key.push(0),
                        b'u' => {
                            let code = bytes
                                .get(*pos..*pos + 4)
                                .and_then(|raw| std::str::from_utf8(raw).ok())
                                .and_then(|raw| u32::from_str_radix(raw, 16).ok());
                            let Some(code) = code else {
                                return Err(ApplyError(format!(
                                    "invalid JSON path `${rest}`: invalid \\u escape"
                                )));
                            };
                            *pos += 4;
                            let Some(character) = char::from_u32(code) else {
                                return Err(ApplyError(format!(
                                    "invalid JSON path `${rest}`: invalid \\u escape"
                                )));
                            };
                            let mut encoded = [0; 4];
                            key.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                        }
                        other => key.push(other),
                    }
                }
                other => key.push(other),
            }
        }
        String::from_utf8(key).map_err(|_| {
            ApplyError(format!(
                "invalid JSON path `${rest}`: member name is not valid UTF-8"
            ))
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::event::JsonDiffRecord;

        /// Builds a diff record the way the model stores them.
        fn rec(path: &str, operation: &str, value: Option<serde_json::Value>) -> JsonDiffRecord {
            JsonDiffRecord {
                path: path.to_owned(),
                operation: operation.to_owned(),
                value,
            }
        }

        #[test]
        fn replaces_inserts_and_removes_members_and_elements() {
            let doc = serde_json::json!({"a": 1, "b": [1, 2]});
            let diffs = vec![
                rec("$.b[1]", "replace", Some(serde_json::json!(99))),
                rec("$.c", "insert", Some(serde_json::json!("x"))),
                rec("$.a", "remove", None),
            ];
            let applied = apply_json_diffs(doc, &diffs).unwrap();
            assert_eq!(applied, serde_json::json!({"b": [1, 99], "c": "x"}));
        }

        #[test]
        fn array_insert_shifts_and_accepts_end_position() {
            let doc = serde_json::json!([1, 2, 3]);
            let insert = |index: usize| {
                let diffs = [rec(
                    &format!("$[{index}]"),
                    "insert",
                    Some(serde_json::json!(9)),
                )];
                apply_json_diffs(doc.clone(), &diffs)
            };
            assert_eq!(insert(1).unwrap(), serde_json::json!([1, 9, 2, 3]));
            // Inserting at the length appends.
            assert_eq!(insert(3).unwrap(), serde_json::json!([1, 2, 3, 9]));
            assert!(insert(4).is_err());
        }

        #[test]
        fn root_replace_swaps_the_document() {
            let doc = serde_json::json!({"a": 1});
            let diffs = [rec("$", "replace", Some(serde_json::json!([true])))];
            assert_eq!(
                apply_json_diffs(doc, &diffs).unwrap(),
                serde_json::json!([true])
            );
            let remove_root = [rec("$", "remove", None)];
            assert!(apply_json_diffs(serde_json::json!({}), &remove_root).is_err());
        }

        #[test]
        fn diff_depth_limit_counts_containers_consistently_with_jsonb() {
            let depth = super::super::MAX_JSONB_DEPTH;
            let nested =
                |leaf| (0..depth).fold(leaf, |child, _| serde_json::Value::Array(vec![child]));
            let before = nested(serde_json::json!(1));
            assert_eq!(apply_json_diffs(before.clone(), &[]).unwrap(), before);
            let path = format!("${}", "[0]".repeat(depth));
            assert_eq!(
                apply_json_diffs(
                    before.clone(),
                    &[rec(&path, "replace", Some(serde_json::json!(2)))]
                )
                .unwrap(),
                nested(serde_json::json!(2))
            );
            let error = apply_json_diffs(
                before,
                &[rec(&path, "replace", Some(serde_json::json!([])))],
            )
            .unwrap_err();
            assert!(error.0.contains("nesting limit"), "{}", error.0);
            assert_eq!(
                apply_json_diffs(
                    serde_json::json!(null),
                    &[rec("$", "replace", Some(nested(serde_json::json!(3))))]
                )
                .unwrap(),
                nested(serde_json::json!(3))
            );
        }

        #[test]
        fn failures_name_the_offending_path() {
            let doc = serde_json::json!({"a": {"b": 1}});
            let remove = [rec("$.a.zz", "remove", None)];
            let error = apply_json_diffs(doc.clone(), &remove).unwrap_err();
            assert_eq!(error.0, "path `$.a.zz`: remove target does not exist");
            // A missing intermediate element is a failure, not a creation.
            let insert = [rec("$.zz.c", "insert", Some(serde_json::json!(1)))];
            let error = apply_json_diffs(doc, &insert).unwrap_err();
            assert!(
                error.0.contains("parent path element does not exist"),
                "{}",
                error.0
            );
        }

        #[test]
        fn insert_rejects_existing_members_and_replace_missing_ones() {
            let doc = serde_json::json!({"a": 1});
            let insert = [rec("$.a", "insert", Some(serde_json::json!(2)))];
            assert!(
                apply_json_diffs(doc.clone(), &insert)
                    .unwrap_err()
                    .0
                    .contains("insert on an existing member")
            );
            // Object replace is an upsert, like the task's applier contract.
            let replace = [rec("$.a", "replace", Some(serde_json::json!(2)))];
            assert_eq!(
                apply_json_diffs(doc, &replace).unwrap(),
                serde_json::json!({"a": 2})
            );
            // Array replace past the end is a failure.
            let doc = serde_json::json!([1]);
            let replace = [rec("$[3]", "replace", Some(serde_json::json!(2)))];
            assert!(
                apply_json_diffs(doc, &replace)
                    .unwrap_err()
                    .0
                    .contains("replace target does not exist")
            );
        }

        #[test]
        fn quoted_and_indexed_member_forms_are_accepted() {
            let doc = serde_json::json!({"a b": {"c.d": 1}});
            let diffs = [rec(
                r#"$."a b"["c.d"]"#,
                "replace",
                Some(serde_json::json!(2)),
            )];
            let applied = apply_json_diffs(doc, &diffs).unwrap();
            assert_eq!(applied, serde_json::json!({"a b": {"c.d": 2}}));
        }

        #[test]
        fn escapes_are_decoded_in_quoted_members() {
            let doc = serde_json::json!({"q\"k": 1});
            let diffs = [rec(r#"$."q\"k""#, "replace", Some(serde_json::json!(2)))];
            assert_eq!(
                apply_json_diffs(doc, &diffs).unwrap(),
                serde_json::json!({"q\"k": 2})
            );
        }

        #[test]
        fn json_quoted_paths_preserve_member_identity() {
            for (path, key) in [
                (r#"$."\f""#, "\u{000c}"),
                (r#"$["\uD83D\uDE00"]"#, "😀"),
                (r#"$."\u0000""#, "\0"),
                (r#"$."\"\\\/\b\n\r\t""#, "\"\\/\u{0008}\n\r\t"),
                (r#"$."中文""#, "中文"),
                (r"$.'legacy\'key'", "legacy'key"),
            ] {
                let mut doc = serde_json::json!({"f": 10});
                doc[key] = serde_json::json!({"child": 1});
                let diffs = [rec(
                    &format!("{path}.child"),
                    "replace",
                    Some(serde_json::json!(2)),
                )];
                let applied = apply_json_diffs(doc.clone(), &diffs).unwrap();
                doc[key]["child"] = serde_json::json!(2);
                assert_eq!(applied, doc, "{path}");
            }
        }

        #[test]
        fn invalid_json_quoted_paths_are_rejected() {
            for path in [
                r#"$."\uD800""#,
                r#"$."\uDC00""#,
                r#"$."\uD800\u0041""#,
                r#"$."\u12""#,
                r#"$."\u+123""#,
                r#"$."\x41""#,
                "$.\"line\nfeed\"",
            ] {
                let diffs = [rec(path, "replace", Some(serde_json::json!(2)))];
                let error = apply_json_diffs(serde_json::json!({}), &diffs).unwrap_err();
                assert!(error.0.contains("invalid JSON path"), "{path}: {}", error.0);
            }
        }

        #[test]
        fn unsupported_paths_are_rejected() {
            for path in [
                "a.b",                     // missing `$`
                "$.a-b",                   // `-` needs the quoted form
                "$..a",                    // ellipsis wildcard
                "$.a*",                    // wildcard
                "$[x]",                    // not an index
                "$.a[",                    // truncated
                "$.'a",                    // unterminated quote
                "$[99999999999999999999]", // index overflow
                "$.",                      // empty member
                "$.a.",                    // trailing accessor
            ] {
                let diffs = [rec(path, "replace", Some(serde_json::json!(1)))];
                let error = apply_json_diffs(serde_json::json!({}), &diffs).unwrap_err();
                assert!(
                    error.0.starts_with("invalid JSON path"),
                    "{path}: {}",
                    error.0
                );
            }
        }

        #[test]
        fn unknown_operation_names_are_rejected() {
            let diffs = [rec("$.a", "set", Some(serde_json::json!(1)))];
            let error = apply_json_diffs(serde_json::json!({}), &diffs).unwrap_err();
            assert!(error.0.contains("unknown diff operation"), "{}", error.0);
        }

        #[test]
        fn records_match_the_model_shape() {
            let records = [rec("$.a", "insert", Some(serde_json::json!(1)))];
            let serialized = serde_json::to_value(&records).unwrap();
            assert_eq!(serialized[0]["path"], "$.a");
            assert_eq!(serialized[0]["operation"], "insert");
            assert_eq!(serialized[0]["value"], 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mysql_common::{
        binlog::{jsonb::Value as JsonbValue, jsondiff::JsonDiff},
        io::ParseBuf,
        proto::MyDeserialize,
    };
    use mysql_common::{constants::ColumnType, packets::Column};

    /// Parses binary jsonb bytes with the library, as a row value would be.
    fn jsonb(bytes: &[u8]) -> JsonbValue<'static> {
        let mut buf = ParseBuf(bytes);
        JsonbValue::deserialize((), &mut buf).unwrap().into_owned()
    }

    /// Parses one binary JSON diff (operation byte, path, optional value).
    fn diff(bytes: &[u8]) -> JsonDiff<'static> {
        let mut buf = ParseBuf(bytes);
        JsonDiff::deserialize((), &mut buf).unwrap().into_owned()
    }

    fn json_column() -> Column {
        Column::new(ColumnType::MYSQL_TYPE_JSON).with_name(b"doc")
    }

    /// Binary jsonb for `{"a": 1, "b": [1, 2]}` (small object form).
    ///
    /// jsonb offsets are relative to the container start (its element-count
    /// field), and the size field counts the container from that point.
    const JSONB_DOC: &[u8] = &[
        0x00, // small object
        0x02, 0x00, // two members
        0x1e, 0x00, // 30 bytes from the element-count field on
        0x12, 0x00, 0x01, 0x00, // key entry: "a" at offset 18, length 1
        0x13, 0x00, 0x01, 0x00, // key entry: "b" at offset 19, length 1
        0x05, 0x01, 0x00, // value entry at offset 12: int16 1 (inlined)
        0x02, 0x14, 0x00, // value entry at offset 15: small array at offset 20
        b'a', b'b', // key bytes at offsets 18, 19
        0x02, 0x00, 0x0a, 0x00, // small array: two elements, 10 bytes
        0x05, 0x01, 0x00, // int16 1 (inlined)
        0x05, 0x02, 0x00, // int16 2 (inlined)
    ];

    #[test]
    fn jsonb_fixture_parses_as_expected() {
        let value = serde_json::Value::try_from(jsonb(JSONB_DOC)).unwrap();
        assert_eq!(value, serde_json::json!({"a": 1, "b": [1, 2]}));
    }

    /// Binary jsonb for a top-level opaque `NEWDECIMAL` value (what MySQL
    /// writes for a decimal literal or a DECIMAL column value inside JSON):
    /// type byte 0x0f, the column type (NEWDECIMAL = 246), a variable-length
    /// data length, and the packed binlog decimal (precision, scale, packed
    /// digits).
    fn opaque_decimal_jsonb() -> Vec<u8> {
        let dec = mysql_common::binlog::decimal::Decimal::parse_str_bytes(b"12.5").unwrap();
        let mut out = vec![0x0f, 0xf6, 4]; // OPAQUE, NEWDECIMAL, data length
        out.extend_from_slice(&[3, 1]); // precision 3, scale 1
        dec.write_bin(&mut out).unwrap();
        out
    }

    #[test]
    fn opaque_decimal_jsonb_renders_as_a_string_not_a_failure() {
        let mut nodes = 0usize;
        let value = jsonb_to_serde(&jsonb(&opaque_decimal_jsonb()), 1, &mut nodes).unwrap();
        assert_eq!(value, serde_json::json!("12.5"));
    }

    /// A nested large jsonb array holding three elements: element 0 is the
    /// child container (or, at the bottom of a chain, another inlined
    /// int16), elements 1 and 2 are inlined int16s. Nested values carry no
    /// type byte of their own — the value entry names the type and points
    /// at the payload, so the payload starts with the element count field.
    fn nested_large_array(child: Option<&[u8]>) -> Vec<u8> {
        let mut out = vec![0x03, 0x00, 0x00, 0x00]; // payload: element count = 3
        let size_pos = out.len();
        out.extend(0u32.to_le_bytes()); // size counts from the element-count field
        if child.is_some() {
            out.push(0x03); // element 0: the child container
            out.extend(23u32.to_le_bytes()); // offset from the element-count field
        } else {
            out.push(0x05); // element 0: inlined int16
            out.extend(1i16.to_le_bytes());
            out.extend([0, 0]);
        }
        out.push(0x05); // elements 1 and 2: inlined int16s
        out.extend(1i16.to_le_bytes());
        out.extend([0, 0]);
        out.push(0x05);
        out.extend(1i16.to_le_bytes());
        out.extend([0, 0]);
        if let Some(child) = child {
            out.extend(child);
        }
        let total = out.len() as u32;
        out[size_pos..size_pos + 4].copy_from_slice(&total.to_le_bytes());
        out
    }

    /// A top-level large array wrapping a chain of `depth - 1` nested
    /// containers, so `depth` counts the containers in total. Large arrays
    /// carry 4-byte offsets and sizes, so deep chains cannot be built from
    /// the small format.
    fn deep_jsonb(depth: usize) -> Vec<u8> {
        let mut chain = nested_large_array(None);
        for _ in 1..depth - 1 {
            chain = nested_large_array(Some(&chain));
        }
        let mut out = vec![0x03];
        out.extend(3u32.to_le_bytes()); // real element count
        let size_pos = out.len();
        out.extend(0u32.to_le_bytes()); // size counts from the count field
        out.push(0x03); // element 0: the nested chain
        out.extend(23u32.to_le_bytes()); // offset from the count field
        out.push(0x05); // elements 1 and 2: inlined int16s
        out.extend(1i16.to_le_bytes());
        out.extend([0, 0]);
        out.push(0x05);
        out.extend(1i16.to_le_bytes());
        out.extend([0, 0]);
        out.extend(chain);
        let total = (out.len() - 1) as u32;
        out[size_pos..size_pos + 4].copy_from_slice(&total.to_le_bytes());
        out
    }

    #[test]
    fn jsonb_at_the_depth_cap_converts_and_beyond_is_rejected() {
        // MySQL's own limit is 100 nesting levels: 100 containers convert.
        // Every container holds its child plus two int16 scalars.
        let at_cap = jsonb(&deep_jsonb(MAX_JSONB_DEPTH));
        let mut expected = serde_json::json!([1, 1, 1]);
        for _ in 1..MAX_JSONB_DEPTH {
            expected = serde_json::Value::Array(vec![
                expected,
                serde_json::json!(1),
                serde_json::json!(1),
            ]);
        }
        let mut nodes = 0usize;
        assert_eq!(jsonb_to_serde(&at_cap, 1, &mut nodes).unwrap(), expected);
        // One level deeper is hostile input: a clean InvalidData error, not
        // a stack overflow.
        let over = jsonb(&deep_jsonb(MAX_JSONB_DEPTH + 1));
        let mut nodes = 0usize;
        let err = jsonb_to_serde(&over, 1, &mut nodes).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("nesting depth"), "{}", err);
    }

    /// The R48 aliased-jsonb bomb: `depth` chained small-array containers
    /// whose two entries both point at the same next container; the last
    /// container holds two inlined int16 leaves. Ten wire bytes per container
    /// plus the top-level type byte decode into `2^(depth+1) - 1` serde nodes.
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

    #[test]
    fn node_budget_counts_containers_and_their_children() {
        let mut nodes = 0usize;
        jsonb_to_serde(&jsonb(JSONB_DOC), 1, &mut nodes).unwrap();
        // The root object, its two member values, and the array's two
        // elements.
        assert_eq!(nodes, 5);
    }

    #[test]
    fn aliased_containers_amplify_until_the_node_budget_stops_them() {
        // 221 wire bytes used to decode into 2^23 - 1 = 8,388,607 serde
        // nodes (the R48 reproduction); the conversion now stops at the
        // budget with a clean InvalidData error.
        let bomb = aliased_jsonb_bomb(22);
        assert_eq!(bomb.len(), 221);
        let mut nodes = 0usize;
        let err = jsonb_to_serde(&jsonb(&bomb), 1, &mut nodes).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("node budget of 1000000 nodes"),
            "{}",
            err
        );
        // An aliased document within the budget still converts, and the
        // counter reports the decoded node count exactly.
        let mut nodes = 0usize;
        jsonb_to_serde(&jsonb(&aliased_jsonb_bomb(18)), 1, &mut nodes).unwrap();
        assert_eq!(nodes, (1 << 19) - 1);
    }

    #[test]
    fn parse_diffs_shares_one_node_budget_across_the_sequence() {
        // The first diff's aliased value exhausts the shared budget; the
        // later legitimate value is dropped with it, so a sequence of
        // hostile diffs cannot each re-amplify to the limit. The losses are
        // reported through the problem note instead of failing.
        let mut bomb_diff = vec![0x00, 3, b'$', b'.', b'b']; // REPLACE $.b
        let bomb = aliased_jsonb_bomb(22);
        bomb_diff.push(bomb.len() as u8);
        bomb_diff.extend_from_slice(&bomb);
        let leaf_diff = [0x01, 3, b'$', b'.', b'c', 3, 0x0c, 1, b'x']; // INSERT $.c = "x"
        let diffs = [diff(&bomb_diff), diff(&leaf_diff)];
        let (parsed, problem) = json_diff::parse_diffs(&diffs);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].path, "$.b");
        assert_eq!(parsed[0].value, None);
        assert_eq!(parsed[1].value, None);
        let problem = problem.expect("the budget breach must be reported");
        assert!(
            problem.contains("node budget of 1000000 nodes"),
            "{problem}"
        );
    }

    /// REPLACE `$.b[1]` with 99, as written into a partial JSON after image.
    fn replace_b1_with_99() -> JsonDiff<'static> {
        diff(&[
            0x00, // REPLACE
            6, b'$', b'.', b'b', b'[', b'1', b']', // path
            3, 0x05, 99, 0x00, // int16 99
        ])
    }

    #[test]
    fn pair_applies_a_replace_diff_to_the_before_value() {
        let before = BinlogRow::new(
            vec![Some(BinlogValue::Jsonb(jsonb(JSONB_DOC)))],
            vec![json_column()].into(),
        );
        let after = BinlogRow::new(
            vec![Some(BinlogValue::JsonDiff(vec![replace_b1_with_99()]))],
            vec![json_column()].into(),
        );
        let (before, after) = decode_rows_pair(
            Some(&before),
            Some(&after),
            Some(&[true]),
            Some(&[true]),
            &[],
        )
        .unwrap();
        assert_eq!(
            before.unwrap().columns[0].value,
            CellValue::Json(serde_json::json!({"a": 1, "b": [1, 2]}))
        );
        assert_eq!(
            after.unwrap().columns[0].value,
            CellValue::Json(serde_json::json!({"a": 1, "b": [1, 99]}))
        );
    }

    #[test]
    fn pair_applies_a_multi_diff_sequence_in_order() {
        let before = BinlogRow::new(
            vec![Some(BinlogValue::Jsonb(jsonb(JSONB_DOC)))],
            vec![json_column()].into(),
        );
        let after = BinlogRow::new(
            vec![Some(BinlogValue::JsonDiff(vec![
                replace_b1_with_99(),
                // INSERT `$.c` = "x": string jsonb (type 0x0c, varlen "x").
                diff(&[0x01, 3, b'$', b'.', b'c', 3, 0x0c, 1, b'x']),
                // REMOVE `$.a`.
                diff(&[0x02, 3, b'$', b'.', b'a']),
            ]))],
            vec![json_column()].into(),
        );
        let (_, after) = decode_rows_pair(
            Some(&before),
            Some(&after),
            Some(&[true]),
            Some(&[true]),
            &[],
        )
        .unwrap();
        assert_eq!(
            after.unwrap().columns[0].value,
            CellValue::Json(serde_json::json!({"b": [1, 99], "c": "x"}))
        );
    }

    #[test]
    fn pair_records_a_loss_when_the_diff_cannot_apply() {
        let before = BinlogRow::new(
            vec![Some(BinlogValue::Jsonb(jsonb(JSONB_DOC)))],
            vec![json_column()].into(),
        );
        let after = BinlogRow::new(
            vec![Some(BinlogValue::JsonDiff(vec![
                // REMOVE `$.zz`: the member does not exist in the before value.
                diff(&[0x02, 4, b'$', b'.', b'z', b'z']),
            ]))],
            vec![json_column()].into(),
        );
        let (_, after) = decode_rows_pair(
            Some(&before),
            Some(&after),
            Some(&[true]),
            Some(&[true]),
            &[],
        )
        .unwrap();
        let CellValue::PartialJson { diffs, reason } = after.unwrap().columns[0].value.clone()
        else {
            panic!("expected a partial JSON record");
        };
        assert_eq!(reason, "path `$.zz`: remove target does not exist");
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "$.zz");
        assert_eq!(diffs[0].operation, "remove");
        assert_eq!(diffs[0].value, None);
    }

    #[test]
    fn pair_records_a_loss_for_a_missing_or_non_json_before_value() {
        let diffs = || vec![replace_b1_with_99()];
        // The before image lacks the column entirely.
        let before = BinlogRow::new(vec![], vec![json_column()].into());
        let after = BinlogRow::new(
            vec![Some(BinlogValue::JsonDiff(diffs()))],
            vec![json_column()].into(),
        );
        let (_, after) = decode_rows_pair(
            Some(&before),
            Some(&after),
            Some(&[false]),
            Some(&[true]),
            &[],
        )
        .unwrap();
        let CellValue::PartialJson { reason, .. } = after.unwrap().columns[0].value.clone() else {
            panic!("expected a partial JSON record");
        };
        assert_eq!(reason, "before column is absent");

        // The before image has no row at all.
        let after = BinlogRow::new(
            vec![Some(BinlogValue::JsonDiff(diffs()))],
            vec![json_column()].into(),
        );
        let (_, after) = decode_rows_pair(None, Some(&after), None, Some(&[true]), &[]).unwrap();
        let CellValue::PartialJson { reason, .. } = after.unwrap().columns[0].value.clone() else {
            panic!("expected a partial JSON record");
        };
        assert_eq!(reason, "no before image to apply diffs against");

        // The before value is an integer, not JSON.
        let before = BinlogRow::new(
            vec![Some(BinlogValue::Value(Value::Int(7)))],
            vec![json_column()].into(),
        );
        let after = BinlogRow::new(
            vec![Some(BinlogValue::JsonDiff(diffs()))],
            vec![json_column()].into(),
        );
        let (_, after) = decode_rows_pair(
            Some(&before),
            Some(&after),
            Some(&[true]),
            Some(&[true]),
            &[],
        )
        .unwrap();
        let CellValue::PartialJson { reason, .. } = after.unwrap().columns[0].value.clone() else {
            panic!("expected a partial JSON record");
        };
        assert_eq!(reason, "before value is not JSON");
    }

    #[test]
    fn without_a_pair_context_diffs_are_recorded_not_fatal() {
        let row = BinlogRow::new(
            vec![Some(BinlogValue::JsonDiff(vec![replace_b1_with_99()]))],
            vec![json_column()].into(),
        );
        let image = decode_row(&row, &[true], &[]).unwrap();
        let CellValue::PartialJson { diffs, reason } = image.columns[0].value.clone() else {
            panic!("expected a partial JSON record");
        };
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].operation, "replace");
        assert_eq!(diffs[0].value, Some(serde_json::json!(99)));
        assert_eq!(reason, "no before image to apply diffs against");
    }

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
    fn enum_set_metadata_validates_every_column_list() {
        for field_type in [TLV_SET_STR_VALUE, TLV_ENUM_STR_VALUE] {
            // Two column lists, including empty names and a zero-variant
            // list, follow the same length-encoded representation.
            let valid = [1, 1, b'a', 2, 0, 1, b'b', 0];
            let mut tlv = vec![field_type, valid.len() as u8];
            tlv.extend(valid);
            validate_table_map_metadata(&body_with_lenient_header(&tlv), 8).unwrap();

            for suffix in [vec![0xfe], vec![2, 0], vec![1, 3, b'b']] {
                let mut value = vec![1, 1, b'a']; // valid first column
                value.extend(suffix);
                let mut tlv = vec![field_type, value.len() as u8];
                tlv.extend(value);
                let error =
                    validate_table_map_metadata(&body_with_lenient_header(&tlv), 8).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
        }
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
        let mut body = vec![0u8; 6 + 2]; // table id + flags
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

    /// Builds a table map body with one LONG and one JSON column whose
    /// optional metadata block is `tlv`.
    fn body_with_long_and_json(tlv: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; 6 + 2]; // table id + flags
        body.push(1);
        body.extend_from_slice(b"d\0");
        body.push(1);
        body.extend_from_slice(b"t\0");
        body.push(2); // two columns
        body.extend_from_slice(&[0x03, 0xf5]); // LONG, JSON
        body.extend_from_slice(&[1, 4]); // JSON uses a four-byte length prefix
        body.push(1); // one null-bitmap byte
        body.extend_from_slice(tlv);
        body
    }

    #[test]
    fn partial_json_tlv_types_are_accepted() {
        // SIGNEDNESS (one numeric column, unsigned), PARTIAL_JSON_UPDATE
        // (one bit per column: only the JSON column is partial), and
        // UPDATED_COLUMN_TYPES (an opaque per-column type list).
        let mut tlv = vec![1u8, 1, 0x80];
        tlv.extend_from_slice(&[14, 1, 0x40]);
        tlv.extend_from_slice(&[15, 2, 0xf9, 0x00]);
        let body = body_with_long_and_json(&tlv);
        validate_table_map_metadata(&body, 8).unwrap();
        let ranges = unsupported_tlv_ranges(&body, 8).unwrap().unwrap();
        assert_eq!(ranges.len(), 2);
        // First range: the PARTIAL_JSON_UPDATE entry (type, length, value).
        let tlv_offset = body.len() - tlv.len();
        assert_eq!(ranges[0].start, tlv_offset + 3);
        assert_eq!(ranges[0].end, tlv_offset + 6);
        // Second range: the UPDATED_COLUMN_TYPES entry.
        assert_eq!(ranges[1].start, tlv_offset + 6);
        assert_eq!(ranges[1].end, tlv_offset + 6 + 4);
    }

    #[test]
    fn hostile_partial_json_tlv_lengths_are_rejected() {
        // PARTIAL_JSON_UPDATE declaring an 8-byte length-encoded size that
        // exceeds the body; the value length prefix must never overflow.
        let mut tlv = vec![14u8, 0xfe];
        tlv.extend_from_slice(&u64::MAX.to_le_bytes());
        let err = validate_table_map_metadata(&body_with_long_and_json(&tlv), 8).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds table map bounds"));
        // Same abuse for UPDATED_COLUMN_TYPES.
        let mut tlv = vec![15u8, 0xfe];
        tlv.extend_from_slice(&u64::MAX.to_le_bytes());
        let err = validate_table_map_metadata(&body_with_long_and_json(&tlv), 8).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn signedness_is_read_from_the_walk_not_the_library() {
        // Serialize a parsed table map whose metadata block carries
        // SIGNEDNESS plus the partial-JSON types the library rejects, then
        // check that signedness() still extracts the unsigned flag.
        let mut tlv = vec![1u8, 1, 0x80];
        tlv.extend_from_slice(&[14, 1, 0x40]);
        tlv.extend_from_slice(&[15, 2, 0xf9, 0x00]);
        let body = body_with_long_and_json(&tlv);
        let mut reader = mysql_common::binlog::EventStreamReader::new(
            mysql_common::binlog::consts::BinlogVersion::Version4,
        );
        let mut event = Vec::new();
        event.extend_from_slice(&0u32.to_le_bytes());
        event.push(19); // TABLE_MAP_EVENT
        event.extend_from_slice(&1u32.to_le_bytes()); // server id
        event.extend_from_slice(&(19 + body.len() as u32).to_le_bytes());
        event.extend_from_slice(&0u32.to_le_bytes()); // log pos
        event.extend_from_slice(&0u16.to_le_bytes()); // flags
        event.extend_from_slice(&body);
        reader
            .read(&mut std::io::Cursor::new(event))
            .unwrap()
            .unwrap();
        let map = reader.get_tme(0).unwrap();
        let signedness = signedness(map).unwrap();
        assert_eq!(signedness, vec![Some(true), None]);
    }
}
