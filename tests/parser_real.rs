// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Synthetic-binlog parser tests: framing, hostile input, and typed events.
//!
//! All fixtures are crafted bytes; no real binlog data is used.
use binlog_inspect::{event::EventPayload, parser::BinlogParser, parser::MAX_EVENT_SIZE};
use mysql_common::{
    binlog::events::{GtidEvent, PreviousGtidsEvent, PreviousGtidsSid},
    packets::{GnoInterval, Tag},
    proto::MySerialize,
};
use std::io::Write;

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
fn raw_event(code: u8, body: &[u8], checksum: bool) -> Vec<u8> {
    let size = 19 + body.len() + if checksum { 4 } else { 0 };
    let mut data = Vec::new();
    data.extend_from_slice(&0u32.to_le_bytes());
    data.push(code);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&(size as u32).to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(body);
    if checksum {
        data.extend_from_slice(&crc32(&data).to_le_bytes());
    }
    data
}
fn format_description(algorithm: u8) -> Vec<u8> {
    let mut body = vec![0; 57];
    body[0..2].copy_from_slice(&4u16.to_le_bytes());
    body[2..8].copy_from_slice(b"8.0.30");
    body[56] = 19;
    body.extend([0; 40]);
    body.push(algorithm);
    raw_event(15, &body, true)
}
fn file(data: &[u8]) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f
}

/// The UUID used by the library's own tagged-GTID test vector.
const SID: [u8; 16] = [
    0x55, 0x77, 0x89, 0x04, 0x02, 0x99, 0x11, 0xf1, 0xb1, 0xb8, 0x4e, 0xf0, 0xc4, 0x95, 0x6f, 0xeb,
];
const SID_TEXT: &str = "55778904-0299-11f1-b1b8-4ef0c4956feb";

#[test]
fn rejects_corrupted_checksum_after_valid_format_description() {
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(format_description(1));
    let mut xid = raw_event(16, &42u64.to_le_bytes(), true);
    xid[19] ^= 1;
    bytes.extend(xid);
    let f = file(&bytes);
    let mut parser = BinlogParser::open(f.path()).unwrap();
    let mut events = parser.events();
    assert!(events.next().unwrap().is_ok());
    assert!(
        events
            .next()
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("checksum mismatch")
    );
    assert!(events.next().is_none());
}
#[test]
fn rejects_unknown_checksum_algorithm() {
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(format_description(7));
    let f = file(&bytes);
    let mut parser = BinlogParser::open(f.path()).unwrap();
    assert!(parser.events().next().unwrap().is_err());
}

#[test]
fn short_event_bodies_fail_without_panicking() {
    // Every event type code the library knows plus MariaDB-only codes.
    let kinds: Vec<u8> = (0..=42).chain([100, 160, 255]).collect();
    for kind in &kinds {
        for len in 0..65 {
            let mut bytes = b"\xfebin".to_vec();
            bytes.extend(raw_event(*kind, &vec![0; len], false));
            let f = file(&bytes);
            let outcome = std::panic::catch_unwind(|| {
                let mut parser = BinlogParser::open(f.path()).unwrap();
                let _ = parser.events().next();
            });
            assert!(
                outcome.is_ok(),
                "event kind {kind}, body length {len} caused a panic"
            );
        }
    }
}

/// Same corpus as [`short_event_bodies_fail_without_panicking`] but with a
/// valid checksummed format description in front, so every event is treated
/// as checksummed.
#[test]
fn short_checksummed_event_bodies_fail_without_panicking() {
    let kinds: Vec<u8> = (0..=42).collect();
    for kind in &kinds {
        for len in 0..65 {
            let mut bytes = b"\xfebin".to_vec();
            bytes.extend(format_description(1));
            bytes.extend(raw_event(*kind, &vec![0; len], true));
            let f = file(&bytes);
            let outcome = std::panic::catch_unwind(|| {
                let mut parser = BinlogParser::open(f.path()).unwrap();
                for event in parser.events() {
                    let _ = event;
                }
            });
            assert!(
                outcome.is_ok(),
                "checksummed event kind {kind}, body length {len} caused a panic"
            );
        }
    }
}

#[test]
fn hostile_previous_gtids_rejects_cleanly() {
    for body in [
        // Untagged header claiming 2^40 SIDs in an 8-byte payload.
        (1u64 << 40).to_le_bytes().to_vec(),
        // Tagged header (format bit set) claiming 2^40 SIDs.
        ((1u64 << 56) | (1 << 40) | 1).to_le_bytes().to_vec(),
        // One SID whose declared interval count exceeds the payload.
        {
            let mut body = 1u64.to_le_bytes().to_vec();
            body.extend_from_slice(&SID);
            body.extend_from_slice(&1_000_000u64.to_le_bytes());
            body
        },
    ] {
        let mut bytes = b"\xfebin".to_vec();
        bytes.extend(raw_event(35, &body, false));
        let f = file(&bytes);
        let outcome = std::panic::catch_unwind(move || {
            let mut parser = BinlogParser::open(f.path()).unwrap();
            let err = parser.events().next().unwrap().unwrap_err();
            assert!(
                err.to_string().contains("previous gtids"),
                "unexpected error: {err}"
            );
        });
        assert!(outcome.is_ok(), "hostile previous gtids caused a panic");
    }
}

#[test]
fn previous_gtids_decode_to_mysqlbinlog_style_set() {
    // Untagged: one SID, interval [1, 3) rendered as "1-2".
    let mut body = 1u64.to_le_bytes().to_vec();
    body.extend_from_slice(&SID);
    body.extend_from_slice(&1u64.to_le_bytes()); // one interval
    body.extend_from_slice(&1u64.to_le_bytes()); // start
    body.extend_from_slice(&3u64.to_le_bytes()); // end (exclusive)
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(raw_event(35, &body, false));
    // Tagged: one SID with tag "mytag", interval [1, 3).
    let tagged = PreviousGtidsEvent::new(vec![PreviousGtidsSid::new(
        SID,
        Some(Tag::new("mytag").unwrap()),
        vec![GnoInterval::new(1, 3)],
    )]);
    let mut tagged_body = Vec::new();
    tagged.serialize(&mut tagged_body);
    bytes.extend(raw_event(35, &tagged_body, false));
    let f = file(&bytes);
    let mut parser = BinlogParser::open(f.path()).unwrap();
    let mut events = parser.events();
    let first = events.next().unwrap().unwrap();
    assert_eq!(first.event_type_code, 35);
    assert_eq!(
        first.payload,
        EventPayload::PreviousGtids {
            gtid_set: format!("{SID_TEXT}:1-2")
        }
    );
    let second = events.next().unwrap().unwrap();
    assert_eq!(
        second.payload,
        EventPayload::PreviousGtids {
            gtid_set: format!("{SID_TEXT}:mytag:1-2")
        }
    );
    assert!(events.next().is_none());
}

#[test]
fn typed_events_decode() {
    let mut bytes = b"\xfebin".to_vec();
    // Stop: no body at all.
    bytes.extend(raw_event(3, &[], false));
    // Intvar: LAST_INSERT_ID_EVENT = 1, value 99.
    let mut intvar = vec![1u8];
    intvar.extend_from_slice(&99u64.to_le_bytes());
    bytes.extend(raw_event(5, &intvar, false));
    // Incident: INCIDENT_LOST_EVENTS = 1, message "lost!".
    let mut incident = 1u16.to_le_bytes().to_vec();
    incident.push(5);
    incident.extend_from_slice(b"lost!");
    bytes.extend(raw_event(26, &incident, false));
    // Rows query: length-prefixed SQL.
    let mut rows_query = vec![8u8];
    rows_query.extend_from_slice(b"SELECT 1");
    bytes.extend(raw_event(29, &rows_query, false));
    // Anonymous GTID: flags(0) + SID + GNO, same wire format as a GTID event.
    let mut anonymous = vec![0u8];
    anonymous.extend_from_slice(&SID);
    anonymous.extend_from_slice(&1u64.to_le_bytes());
    bytes.extend(raw_event(34, &anonymous, false));
    // Untagged GTID: uuid:gno.
    let mut gtid = vec![0u8];
    gtid.extend_from_slice(&SID);
    gtid.extend_from_slice(&7u64.to_le_bytes());
    bytes.extend(raw_event(33, &gtid, false));
    // Tagged GTID (MySQL 8.4+): uuid:tag:gno, serialized by the library.
    let tagged = GtidEvent::new_tagged(SID, Tag::new("mytag").unwrap(), 3);
    let mut tagged_body = Vec::new();
    tagged.serialize(&mut tagged_body);
    bytes.extend(raw_event(42, &tagged_body, false));
    let f = file(&bytes);
    let mut parser = BinlogParser::open(f.path()).unwrap();
    let mut events = parser.events();
    let stop = events.next().unwrap().unwrap();
    assert_eq!(stop.event_type_code, 3);
    assert_eq!(stop.payload, EventPayload::Stop);
    let intvar = events.next().unwrap().unwrap();
    assert_eq!(
        intvar.payload,
        EventPayload::Intvar {
            var_type: "LAST_INSERT_ID_EVENT".into(),
            value: 99
        }
    );
    let incident = events.next().unwrap().unwrap();
    assert_eq!(
        incident.payload,
        EventPayload::Incident {
            incident_type: "INCIDENT_LOST_EVENTS".into(),
            message: "lost!".into()
        }
    );
    let rows_query = events.next().unwrap().unwrap();
    assert_eq!(
        rows_query.payload,
        EventPayload::RowsQuery {
            sql: "SELECT 1".into()
        }
    );
    let anonymous = events.next().unwrap().unwrap();
    assert_eq!(anonymous.event_type_code, 34);
    assert_eq!(
        anonymous.payload,
        EventPayload::Gtid {
            gtid: "ANONYMOUS".into(),
            tag: None
        }
    );
    let gtid = events.next().unwrap().unwrap();
    assert_eq!(gtid.event_type_code, 33);
    assert_eq!(
        gtid.payload,
        EventPayload::Gtid {
            gtid: format!("{SID_TEXT}:7"),
            tag: None
        }
    );
    let tagged = events.next().unwrap().unwrap();
    assert_eq!(tagged.event_type_code, 42);
    assert_eq!(
        tagged.payload,
        EventPayload::Gtid {
            gtid: format!("{SID_TEXT}:mytag:3"),
            tag: Some("mytag".into())
        }
    );
    assert!(events.next().is_none());
}

#[test]
fn server_version_stops_at_first_nul() {
    let mut bytes = b"\xfebin".to_vec();
    // Like format_description(1), but with garbage injected after the NUL
    // padding of the 50-byte server version field before checksumming.
    let mut body = vec![0; 57];
    body[0..2].copy_from_slice(&4u16.to_le_bytes());
    body[2..8].copy_from_slice(b"8.0.30");
    body[20..24].copy_from_slice(&[0xaa; 4]);
    body[56] = 19;
    body.extend([0; 40]);
    body.push(1); // checksum algorithm: CRC32
    bytes.extend(raw_event(15, &body, true));
    let f = file(&bytes);
    let mut parser = BinlogParser::open(f.path()).unwrap();
    let event = parser.events().next().unwrap().unwrap();
    assert_eq!(
        event.payload,
        EventPayload::FormatDescription {
            server_version: "8.0.30".into()
        }
    );
}

#[test]
fn hostile_table_map_metadata_rejects_cleanly() {
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(format_description(1));
    let mut body = vec![1, 0, 0, 0, 0, 0]; // table id
    body.extend([0, 0]); // flags
    body.extend([1, b'd', 0]); // database name
    body.extend([1, b't', 0]); // table name
    body.push(1); // one column
    body.push(0x03); // LONG
    body.push(0); // empty column metadata
    body.push(1); // null bitmap
    // ENUM_STR_VALUE TLV declaring u64::MAX variants: 0xfe marks an 8-byte
    // length-encoded integer.
    let mut tlv = vec![6u8, 9, 0xfe];
    tlv.extend_from_slice(&u64::MAX.to_le_bytes());
    body.extend_from_slice(&tlv);
    // The checksummed format description is in front, so the event itself
    // must carry a valid checksum suffix.
    bytes.extend(raw_event(19, &body, true));
    let f = file(&bytes);
    let outcome = std::panic::catch_unwind(move || {
        let mut parser = BinlogParser::open(f.path()).unwrap();
        let mut events = parser.events();
        assert!(events.next().unwrap().is_ok()); // format description
        let err = events.next().unwrap().unwrap_err();
        assert!(
            err.to_string().contains("variant count"),
            "unexpected error: {err}"
        );
    });
    assert!(outcome.is_ok(), "hostile table map metadata caused a panic");
}

/// Hostile partial-JSON optional metadata (types 14 and 15) in the
/// panic-corpus style: inflated declared lengths must return a clean
/// `InvalidData` error and never abort the process, while well-formed
/// entries of the same types pass the pre-validation walk.
#[test]
fn partial_json_table_map_metadata_follows_the_tolerance_policy() {
    let table_map_body = |tlv: &[u8]| {
        let mut body = vec![1, 0, 0, 0, 0, 0]; // table id
        body.extend([0, 0]); // flags
        body.extend([1, b'd', 0]); // database name
        body.extend([1, b't', 0]); // table name
        body.push(1); // one column
        body.push(0x03); // LONG
        body.push(0); // empty column metadata
        body.push(1); // null bitmap
        body.extend_from_slice(tlv);
        body
    };
    for (name, tlv) in [
        ("hostile partial json update length", {
            let mut tlv = vec![14u8, 0xfe];
            tlv.extend_from_slice(&u64::MAX.to_le_bytes());
            tlv
        }),
        ("hostile updated column types length", {
            let mut tlv = vec![15u8, 0xfd];
            tlv.extend_from_slice(&[0xff; 3]);
            tlv
        }),
    ] {
        let mut bytes = b"\xfebin".to_vec();
        bytes.extend(format_description(1));
        bytes.extend(raw_event(19, &table_map_body(&tlv), true));
        let f = file(&bytes);
        let outcome = std::panic::catch_unwind(move || {
            let mut parser = BinlogParser::open(f.path()).unwrap();
            let mut events = parser.events();
            assert!(events.next().unwrap().is_ok()); // format description
            let err = events.next().unwrap().unwrap_err();
            assert!(
                err.to_string().contains("exceeds table map bounds"),
                "unexpected error for {name}: {err}"
            );
        });
        assert!(outcome.is_ok(), "{name} caused a panic");
    }

    // Well-formed partial-JSON entries are accepted by the walk (they are
    // stripped from the library's view later).
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(format_description(1));
    bytes.extend(raw_event(
        19,
        &table_map_body(&[14, 1, 0x80, 15, 2, 0x03, 0x00]),
        true,
    ));
    let f = file(&bytes);
    let mut parser = BinlogParser::open(f.path()).unwrap();
    let event = parser.events().next().unwrap().unwrap();
    assert!(matches!(
        event.payload,
        EventPayload::FormatDescription { .. }
    ));
    let event = parser.events().next().unwrap().unwrap();
    assert!(matches!(event.payload, EventPayload::TableMap { .. }));
}

#[test]
fn oversized_event_is_rejected() {
    let mut bytes = b"\xfebin".to_vec();
    // Declared size above the default cap.
    let mut header = [0u8; 19];
    header[4] = 16;
    header[9..13].copy_from_slice(&(MAX_EVENT_SIZE + 1).to_le_bytes());
    bytes.extend_from_slice(&header);
    bytes.extend(raw_event(16, &7u64.to_le_bytes(), false));
    let f = file(&bytes);
    let mut parser = BinlogParser::open(f.path()).unwrap();
    let err = parser.events().next().unwrap().unwrap_err();
    assert!(err.to_string().contains("oversized"), "{err}");
}

#[test]
fn from_reader_accepts_stream_without_seek() {
    // The magic is validated from the stream itself; stdin-like inputs need
    // no file descriptor.
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(raw_event(16, &5u64.to_le_bytes(), false));
    let mut parser = BinlogParser::from_reader(std::io::Cursor::new(bytes)).unwrap();
    let event = parser.events().next().unwrap().unwrap();
    assert_eq!(event.payload, EventPayload::Xid { xid: 5 });
    assert!(BinlogParser::from_reader(std::io::Cursor::new(b"\xfdbin".to_vec())).is_err());
    assert!(BinlogParser::from_reader(std::io::Cursor::new(b"garbage!".to_vec())).is_err());
    // Truncated magic is a header error, not an I/O failure.
    assert!(matches!(
        BinlogParser::from_reader(std::io::Cursor::new(b"\xfeb".to_vec())),
        Err(binlog_inspect::parser::ParserError::InvalidHeader)
    ));
}
