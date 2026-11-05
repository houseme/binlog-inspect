use binlog_inspect::{
    event::{EventPayload, EventType, ParsedEvent},
    filter::EventFilter,
    formatter::{CsvFormatter, Formatter, TextFormatter},
    parser::{BinlogParser, MAX_EVENT_SIZE, ParserError},
};
use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

fn event_at(kind: u8, body: &[u8], timestamp: u32) -> Vec<u8> {
    let size = 19 + body.len() as u32;
    let mut result = Vec::new();
    result.extend(timestamp.to_le_bytes());
    result.push(kind);
    result.extend(7u32.to_le_bytes());
    result.extend(size.to_le_bytes());
    result.extend((4 + size).to_le_bytes());
    result.extend(0u16.to_le_bytes());
    result.extend(body);
    result
}
fn event(kind: u8, body: &[u8]) -> Vec<u8> {
    event_at(kind, body, 1)
}
fn file(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(bytes).unwrap();
    f
}
/// A bare 19-byte header whose declared event size (0) is outside the valid
/// range; the framing layer rejects it before allocating anything.
fn corrupt_event() -> Vec<u8> {
    let mut header = vec![0u8; 19];
    header[4] = 16;
    header
}
/// MySQL serialization-library varlen uint for small values (fixtures only).
fn varlen(value: u64) -> Vec<u8> {
    assert!(value < 128, "fixture helper supports one-byte varlen only");
    vec![(value << 1) as u8]
}
fn run_cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_binlog-inspect"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn detects_headers() {
    assert!(matches!(
        BinlogParser::open(file(b"\xfdbin").path()),
        Err(ParserError::EncryptedBinlog)
    ));
    assert!(matches!(
        BinlogParser::open(file(b"\xfe bi").path()),
        Err(ParserError::InvalidHeader)
    ));
}
#[test]
fn xid_unknown_and_truncated_body() {
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event(16, &123u64.to_le_bytes()));
    bytes.extend(event(250, &[1, 2, 3]));
    let f = file(&bytes);
    let mut p = BinlogParser::open(f.path()).unwrap();
    let mut events = p.events();
    assert!(matches!(
        events.next().unwrap().unwrap().payload,
        EventPayload::Xid { xid: 123 }
    ));
    assert!(matches!(
        events.next().unwrap().unwrap().payload,
        EventPayload::Unknown { raw_len: 3 }
    ));
    assert!(events.next().is_none());
    bytes.pop();
    let f = file(&bytes);
    let mut p = BinlogParser::open(f.path()).unwrap();
    let mut events = p.events();
    assert!(events.next().unwrap().is_ok());
    assert!(events.next().unwrap().is_err());
    assert!(events.next().is_none());
}
#[test]
fn cli_json_and_filter() {
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event(16, &123u64.to_le_bytes()));
    let f = file(&bytes);
    let out = run_cli(&[f.path().to_str().unwrap(), "--events", "xid"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["payload"]["xid"], 123);
    let out = run_cli(&[f.path().to_str().unwrap(), "--events", "query"]);
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
}
#[test]
fn cli_events_flag_validation() {
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event(16, &123u64.to_le_bytes()));
    let f = file(&bytes);
    let path = f.path().to_str().unwrap();

    // Unknown values are rejected at parse time with exit code 2 and list all
    // valid values.
    let out = run_cli(&[path, "--events", "bogus"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("bogus"), "{stderr}");
    assert!(stderr.contains("valid values"), "{stderr}");

    // transaction_payload is selectable; the XID-only file simply has none.
    let out = run_cli(&[path, "--events", "transaction_payload"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());

    // A valid comma-separated list still parses.
    let out = run_cli(&[path, "--events", "xid,query"]);
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["payload"]["xid"], 123);

    // Filtering to types that do not occur yields no output but exits 0.
    let out = run_cli(&[path, "--events", "query,rotate"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
}
#[test]
fn text_formatter_layout_is_stable() {
    let item = ParsedEvent {
        offset: 4,
        timestamp: 1_700_000_000,
        event_type: EventType::Xid,
        event_type_code: 16,
        server_id: 7,
        event_size: 27,
        log_pos: 31,
        payload: EventPayload::Xid { xid: 123 },
    };
    let mut out = Vec::new();
    assert!(TextFormatter.format(&item, &mut out).unwrap());
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "1700000000 xid server=7 pos=31 {\"kind\":\"xid\",\"xid\":123}\n"
    );
}
#[test]
fn cli_text_format_matches_layout() {
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event(16, &123u64.to_le_bytes()));
    let f = file(&bytes);
    let out = run_cli(&[f.path().to_str().unwrap(), "--format", "text"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "1 xid server=7 pos=31 {\"kind\":\"xid\",\"xid\":123}\n"
    );
}
#[test]
fn strict_mode_aborts_while_lenient_mode_continues() {
    let dir = tempfile::tempdir().unwrap();
    let mut a_bytes = b"\xfebin".to_vec();
    a_bytes.extend(event(16, &123u64.to_le_bytes()));
    a_bytes.extend(corrupt_event());
    let a = dir.path().join("a.binlog");
    std::fs::write(&a, &a_bytes).unwrap();
    let mut b_bytes = b"\xfebin".to_vec();
    b_bytes.extend(event(16, &456u64.to_le_bytes()));
    let b = dir.path().join("b.binlog");
    std::fs::write(&b, &b_bytes).unwrap();

    // Strict: the first error aborts everything; B is never processed.
    let out = Command::new(env!("CARGO_BIN_EXE_binlog-inspect"))
        .arg(&a)
        .arg(&b)
        .arg("--strict")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("123"),
        "A's event before the error: {stdout}"
    );
    assert!(
        !stdout.contains("456"),
        "B must not be processed in strict mode"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("a.binlog"), "{stderr}");
    assert!(stderr.contains("offset"), "{stderr}");

    // Without strict: A stops early and is reported, B is still parsed, exit 3.
    let out = Command::new(env!("CARGO_BIN_EXE_binlog-inspect"))
        .arg(&a)
        .arg(&b)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("123") && stdout.contains("456"), "{stdout}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("a.binlog"), "{stderr}");
    assert!(stderr.contains("offset"), "{stderr}");
    assert!(!stderr.contains("b.binlog"), "B parsed fully: {stderr}");
}
#[test]
fn framing_rejects_invalid_event_sizes() {
    // Declared size below the 19-byte header minimum.
    let mut bytes = b"\xfebin".to_vec();
    let mut header = vec![0u8; 19];
    header[4] = 16;
    header[9..13].copy_from_slice(&18u32.to_le_bytes());
    header[13..17].copy_from_slice(&37u32.to_le_bytes());
    bytes.extend(header);
    let f = file(&bytes);
    let mut p = BinlogParser::open(f.path()).unwrap();
    let err = p.events().next().unwrap().unwrap_err();
    assert!(err.to_string().contains("offset"), "{err}");

    // Declared size above the 64 MiB cap: only the header is written and the
    // parser rejects it before allocating.
    let mut bytes = b"\xfebin".to_vec();
    let mut header = vec![0u8; 19];
    header[4] = 16;
    header[9..13].copy_from_slice(&(MAX_EVENT_SIZE + 1).to_le_bytes());
    bytes.extend(header);
    let f = file(&bytes);
    let mut p = BinlogParser::open(f.path()).unwrap();
    let err = p.events().next().unwrap().unwrap_err();
    assert!(err.to_string().contains("offset"), "{err}");
}
#[test]
fn table_filter_excludes_unresolved_rows() {
    // A rows event without a preceding table map stays unresolved...
    let mut row = vec![1, 0, 0, 0, 0, 0, 0, 0];
    row.extend_from_slice(&[2, 0, 1, 1, 0, 42, 0, 0, 0]);
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event(30, &row));
    let f = file(&bytes);
    let path = f.path().to_str().unwrap();

    // ...and is emitted under its row-event type without a table filter.
    let out = run_cli(&[path, "--events", "write_rows"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"event_type\":\"write_rows\""), "{stdout}");
    assert!(stdout.contains("\"kind\":\"unresolved\""), "{stdout}");

    // A table filter must never match an unresolved payload.
    let out = run_cli(&[path, "--table", "db.t"]);
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
}
#[test]
fn stdin_dash_is_parsed() {
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event(16, &99u64.to_le_bytes()));
    let mut child = Command::new(env!("CARGO_BIN_EXE_binlog-inspect"))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(&bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["payload"]["xid"], 99);
}
#[test]
fn gtid_events_expose_kind_gtid_value_and_tag() {
    // Regular GTID (code 33): flags, sid, gno.
    let mut regular = vec![0u8]; // flags
    regular.extend([0x11u8; 16]); // sid
    regular.extend(1u64.to_le_bytes()); // gno

    // Tagged GTID (code 42, MySQL 8.4+): serialization-library v2 envelope.
    let mut tagged = vec![2u8]; // serialization version
    tagged.extend(varlen(28)); // self-inclusive payload size
    tagged.extend(varlen(3)); // last non-ignorable field id (TAG)
    tagged.extend(varlen(0)); // field id GTID_FLAGS
    tagged.push(0); // flags value
    tagged.extend(varlen(1)); // field id SID
    for byte in 1u8..=16 {
        tagged.push(byte << 1); // varlen-encoded UUID byte
    }
    tagged.extend(varlen(2)); // field id GNO
    tagged.extend(varlen(84)); // zig-zag(42) = 84, varlen-encoded
    tagged.extend(varlen(3)); // field id TAG
    tagged.push(4); // tag length
    tagged.extend_from_slice(b"t1");

    // Anonymous GTID (code 34): all-zero sid and gno.
    let mut anonymous = vec![0u8]; // flags
    anonymous.extend([0u8; 16]); // sid
    anonymous.extend(0u64.to_le_bytes()); // gno

    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event(33, &regular));
    bytes.extend(event(42, &tagged));
    bytes.extend(event(34, &anonymous));
    let f = file(&bytes);
    let out = run_cli(&[f.path().to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 3, "{stdout}");
    assert_eq!(lines[0]["event_type"], "gtid");
    assert_eq!(lines[0]["payload"]["kind"], "gtid");
    assert_eq!(
        lines[0]["payload"]["gtid"],
        "11111111-1111-1111-1111-111111111111:1"
    );
    assert_eq!(lines[0]["payload"]["tag"], serde_json::Value::Null);
    assert_eq!(lines[1]["event_type"], "gtid");
    assert_eq!(lines[1]["payload"]["kind"], "gtid");
    assert_eq!(
        lines[1]["payload"]["gtid"],
        "01020304-0506-0708-090a-0b0c0d0e0f10:t1:42"
    );
    assert_eq!(lines[1]["payload"]["tag"], "t1");
    assert_eq!(lines[2]["event_type"], "anonymous_gtid");
    assert_eq!(lines[2]["payload"]["kind"], "gtid");
    assert_eq!(lines[2]["payload"]["gtid"], "ANONYMOUS");
    assert_eq!(lines[2]["payload"]["tag"], serde_json::Value::Null);
}
#[test]
fn output_is_atomic_mode_0600_and_never_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event(16, &123u64.to_le_bytes()));
    let input = dir.path().join("in.binlog");
    std::fs::write(&input, &bytes).unwrap();
    let output = dir.path().join("out.jsonl");

    let status = Command::new(env!("CARGO_BIN_EXE_binlog-inspect"))
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(0));
    let content = std::fs::read(&output).unwrap();
    let content = String::from_utf8(content).unwrap();
    assert!(content.contains("\"xid\":123"), "{content}");
    assert!(content.ends_with('\n'));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&output).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // An existing target is never overwritten (exit 1), content unchanged.
    let status = Command::new(env!("CARGO_BIN_EXE_binlog-inspect"))
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
    assert_eq!(std::fs::read(&output).unwrap(), content.as_bytes());

    // A partial parse failure still publishes the output and exits 3.
    let mut corrupt = b"\xfebin".to_vec();
    corrupt.extend(corrupt_event());
    let corrupt_input = dir.path().join("corrupt.binlog");
    std::fs::write(&corrupt_input, &corrupt).unwrap();
    let partial_target = dir.path().join("partial.jsonl");
    let status = Command::new(env!("CARGO_BIN_EXE_binlog-inspect"))
        .arg(&corrupt_input)
        .arg("--output")
        .arg(&partial_target)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(3));
    assert!(partial_target.exists());

    // A hard error mid-run leaves neither the target nor temporary files.
    let missing = dir.path().join("missing.binlog");
    let target = dir.path().join("never.jsonl");
    let status = Command::new(env!("CARGO_BIN_EXE_binlog-inspect"))
        .arg(&missing)
        .arg("--output")
        .arg(&target)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
    assert!(!target.exists());

    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
        .map(|entry| entry.file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "leftover temporary files: {leftovers:?}"
    );
}
#[cfg(feature = "remote")]
#[test]
fn remote_download_and_encrypted_rejection() {
    use std::{io::Read, net::TcpListener, thread};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut req = [0; 2048];
        let _ = stream.read(&mut req);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n\xfdbin")
            .unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_binlog-inspect"))
        .args(["--url", &format!("http://{addr}/file")])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("encrypted binlog"));
}

#[test]
fn query_is_decoded() {
    let mut body = vec![0u8; 13];
    body[8] = 3;
    body.extend_from_slice(b"app\0SELECT 1");
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event(2, &body));
    let f = file(&bytes);
    let mut p = BinlogParser::open(f.path()).unwrap();
    let item = p.events().next().unwrap().unwrap();
    assert!(
        matches!(item.payload, EventPayload::Query { database, sql } if database == "app" && sql == "SELECT 1")
    );
}

#[test]
fn csv_quotes_row_values_and_table_filter() {
    use binlog_inspect::event::{CellValue, ColumnValue, RowChange, RowImage};
    let item = ParsedEvent {
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
                        name: Some("a,\"b\"".into()),
                        value: CellValue::Null,
                        mysql_type: None,
                        signedness: None,
                    }],
                }),
            }],
        },
    };
    let mut formatter = CsvFormatter;
    assert_eq!(
        formatter.header(),
        Some("timestamp,event_type,database,table,before,after")
    );
    let mut out = Vec::new();
    assert!(formatter.format(&item, &mut out).unwrap());
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("a,\\\"\"b\\\"\""), "{text}");
    assert!(text.ends_with('\n') && text.lines().count() == 1);

    let filter = EventFilter {
        tables: [("db".to_string(), "t".to_string())].into_iter().collect(),
        ..Default::default()
    };
    assert!(filter.keep(&item));
    let kinds = EventFilter {
        kinds: [EventType::UpdateRows].into_iter().collect(),
        ..Default::default()
    };
    assert!(!kinds.keep(&item));
    let unresolved = ParsedEvent {
        offset: 4,
        timestamp: 1,
        event_type: EventType::WriteRows,
        event_type_code: 30,
        server_id: 1,
        event_size: 19,
        log_pos: 23,
        payload: EventPayload::Unresolved { table_id: 1 },
    };
    assert!(!filter.keep(&unresolved));
}

#[cfg(feature = "remote")]
#[test]
fn remote_plaintext_is_parsed() {
    use std::{io::Read, net::TcpListener, thread};
    let mut body = b"\xfebin".to_vec();
    body.extend(event(16, &55u64.to_le_bytes()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut req = [0; 2048];
        let _ = stream.read(&mut req);
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(&body).unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_binlog-inspect"))
        .args(["--url", &format!("http://{addr}/file")])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["payload"]["xid"], 55);
}

#[test]
fn table_map_and_write_rows_are_decoded() {
    let mut map = vec![1, 0, 0, 0, 0, 0, 0, 0];
    map.extend_from_slice(b"\x03app\0\x01t\0\x01\x03\x00\x00");
    let mut row = vec![1, 0, 0, 0, 0, 0, 0, 0];
    row.extend_from_slice(&[2, 0, 1, 1, 0, 42, 0, 0, 0]);
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event(19, &map));
    bytes.extend(event(30, &row));
    let f = file(&bytes);
    let mut p = BinlogParser::open(f.path()).unwrap();
    let mut events = p.events();
    assert!(matches!(
        events.next().unwrap().unwrap().payload,
        EventPayload::TableMap { table_id: 1, .. }
    ));
    let decoded = events.next().unwrap().unwrap();
    assert!(
        matches!(decoded.payload, EventPayload::Rows { database, table, changes, .. } if database == "app" && table == "t" && changes.len() == 1 && serde_json::to_string(changes[0].after.as_ref().unwrap()).unwrap().contains("42"))
    );
}

#[test]
fn row_column_count_must_match_table_map() {
    let mut map = vec![1, 0, 0, 0, 0, 0, 0, 0];
    map.extend_from_slice(b"\x03app\0\x01t\0\x01\x03\x00\x00");
    let mut row = vec![1, 0, 0, 0, 0, 0, 0, 0];
    row.extend_from_slice(&[2, 0, 2, 1, 0, 42, 0, 0, 0]);
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event(19, &map));
    bytes.extend(event(30, &row));
    let f = file(&bytes);
    let mut p = BinlogParser::open(f.path()).unwrap();
    let mut events = p.events();
    assert!(events.next().unwrap().is_ok());
    assert!(
        events
            .next()
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("column count")
    );
}

#[test]
fn update_minimal_row_images_preserve_column_positions() {
    let mut map = vec![1, 0, 0, 0, 0, 0, 0, 0];
    map.extend_from_slice(b"\x03app\0\x01t\0\x03\x03\x03\x03\x00\x00");
    let mut row = vec![1, 0, 0, 0, 0, 0, 0, 0];
    row.extend_from_slice(&[2, 0, 3, 1, 4, 0, 42, 0, 0, 0, 0, 84, 0, 0, 0]);
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event(19, &map));
    bytes.extend(event(31, &row));
    let f = file(&bytes);
    let mut p = BinlogParser::open(f.path()).unwrap();
    let mut events = p.events();
    assert!(events.next().unwrap().is_ok());
    let decoded = events.next().unwrap().unwrap();
    let value = serde_json::to_value(decoded).unwrap();
    let change = &value["payload"]["changes"][0];
    assert_eq!(change["before"]["columns"][0]["value"]["value"], 42);
    assert_eq!(change["before"]["columns"][2]["value"]["type"], "absent");
    assert_eq!(change["after"]["columns"][0]["value"]["type"], "absent");
    assert_eq!(change["after"]["columns"][2]["value"]["value"], 84);
}

/// Extracts the XID payload values from one JSONL run of the CLI.
fn xids_of(output: &Output) -> Vec<u64> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            value["payload"]["xid"].as_u64().unwrap()
        })
        .collect()
}

/// A regular (code 33) GTID body: flags, sid, gno.
fn gtid_body(sid: [u8; 16], gno: u64) -> Vec<u8> {
    let mut body = vec![0u8]; // flags
    body.extend(sid);
    body.extend(gno.to_le_bytes());
    body
}

/// A tagged (code 42, MySQL 8.4+) GTID body using the serialization-library
/// v2 envelope; renders as `01020304-0506-0708-090a-0b0c0d0e0f10:t1:42`.
fn tagged_gtid_body() -> Vec<u8> {
    let mut tagged = vec![2u8]; // serialization version
    tagged.extend(varlen(28)); // self-inclusive payload size
    tagged.extend(varlen(3)); // last non-ignorable field id (TAG)
    tagged.extend(varlen(0)); // field id GTID_FLAGS
    tagged.push(0); // flags value
    tagged.extend(varlen(1)); // field id SID
    for byte in 1u8..=16 {
        tagged.push(byte << 1); // varlen-encoded UUID byte
    }
    tagged.extend(varlen(2)); // field id GNO
    tagged.extend(varlen(84)); // zig-zag(42) = 84, varlen-encoded
    tagged.extend(varlen(3)); // field id TAG
    tagged.push(4); // tag length
    tagged.extend_from_slice(b"t1");
    tagged
}

#[test]
fn cli_position_filters_are_start_inclusive_and_stop_exclusive() {
    // Two XID events: the first starts at byte offset 4, the second at 31.
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event(16, &1u64.to_le_bytes()));
    bytes.extend(event(16, &2u64.to_le_bytes()));
    let f = file(&bytes);
    let path = f.path().to_str().unwrap();
    let run = |args: &[&str]| {
        let out = run_cli(args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        xids_of(&out)
    };
    // --start-position is inclusive: offset 4 satisfies start=4.
    assert_eq!(run(&[path, "--start-position", "4"]), [1, 2]);
    assert_eq!(run(&[path, "--start-position", "5"]), [2]);
    assert_eq!(run(&[path, "--start-position", "31"]), [2]);
    // --stop-position is exclusive (mysqlbinlog convention).
    assert_eq!(run(&[path, "--stop-position", "31"]), [1]);
    assert_eq!(run(&[path, "--stop-position", "30"]), [1]);
    assert_eq!(run(&[path, "--stop-position", "4"]), [0u64; 0]);
    // Both bounds combine into a window that keeps only the second event.
    assert_eq!(
        run(&[path, "--start-position", "31", "--stop-position", "58"]),
        [2]
    );
}

#[test]
fn cli_datetime_filters_are_inclusive_on_both_ends() {
    // 1700000000 = 2023-11-14T22:13:20Z; 1700086400 is exactly one day later.
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event_at(16, &1u64.to_le_bytes(), 1_700_000_000));
    bytes.extend(event_at(16, &2u64.to_le_bytes(), 1_700_086_400));
    let f = file(&bytes);
    let path = f.path().to_str().unwrap();
    let run = |args: &[&str]| {
        let out = run_cli(args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        xids_of(&out)
    };
    // RFC3339 with Z; start bound inclusive.
    assert_eq!(
        run(&[path, "--start-datetime", "2023-11-14T22:13:20Z"]),
        [1, 2]
    );
    assert_eq!(
        run(&[path, "--start-datetime", "2023-11-15T22:13:20Z"]),
        [2]
    );
    // RFC3339 with an offset is accepted too.
    assert_eq!(
        run(&[path, "--start-datetime", "2023-11-15T23:13:20+01:00"]),
        [2]
    );
    // Stop bound inclusive: an event exactly at the bound is kept.
    assert_eq!(run(&[path, "--stop-datetime", "2023-11-14T22:13:20Z"]), [1]);
    assert_eq!(
        run(&[path, "--stop-datetime", "2023-11-15T22:13:20Z"]),
        [1, 2]
    );
    // Local wall-clock form, pinned to UTC for determinism.
    let out = Command::new(env!("CARGO_BIN_EXE_binlog-inspect"))
        .args([
            path,
            "--start-datetime",
            "2023-11-14 22:13:20",
            "--stop-datetime",
            "2023-11-15 22:13:20",
        ])
        .env("TZ", "UTC")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(xids_of(&out), [1, 2]);
    // Invalid formats are usage errors (exit 2).
    for value in ["not-a-date", "2023-13-01T00:00:00Z", "2023-11-14"] {
        let out = run_cli(&[path, "--start-datetime", value]);
        assert_eq!(out.status.code(), Some(2), "{value}");
    }
}

#[test]
fn cli_include_gtid_filters_exact_matches_and_validates() {
    let sid = [
        0x55, 0x77, 0x89, 0x04, 0x02, 0x99, 0x11, 0xf1, 0xb1, 0xb8, 0x4e, 0xf0, 0xc4, 0x95, 0x6f,
        0xeb,
    ];
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event(33, &gtid_body([0x11; 16], 1)));
    bytes.extend(event(42, &tagged_gtid_body()));
    bytes.extend(event(33, &gtid_body(sid, 7)));
    bytes.extend(event(34, &gtid_body([0u8; 16], 0)));
    let f = file(&bytes);
    let path = f.path().to_str().unwrap();
    let gtids = |args: &[&str]| {
        let out = run_cli(args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|line| {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                value["payload"]["gtid"].as_str().unwrap().to_owned()
            })
            .collect::<Vec<_>>()
    };
    // Untagged exact match.
    assert_eq!(
        gtids(&[
            path,
            "--include-gtid",
            "11111111-1111-1111-1111-111111111111:1"
        ]),
        ["11111111-1111-1111-1111-111111111111:1"]
    );
    // Tagged exact match.
    assert_eq!(
        gtids(&[
            path,
            "--include-gtid",
            "01020304-0506-0708-090a-0b0c0d0e0f10:t1:42"
        ]),
        ["01020304-0506-0708-090a-0b0c0d0e0f10:t1:42"]
    );
    // Non-matching allow lists filter everything, including anonymous events.
    assert!(
        gtids(&[
            path,
            "--include-gtid",
            "55778904-0299-11f1-b1b8-4ef0c4956feb:8"
        ])
        .is_empty()
    );
    // Repeated values form an allow list; UUIDs normalize to lowercase.
    assert_eq!(
        gtids(&[
            path,
            "--include-gtid",
            "11111111-1111-1111-1111-111111111111:1",
            "--include-gtid",
            "55778904-0299-11F1-B1B8-4EF0C4956FEB:7",
        ]),
        [
            "11111111-1111-1111-1111-111111111111:1",
            "55778904-0299-11f1-b1b8-4ef0c4956feb:7"
        ]
    );
    // Shape validation failures are usage errors (exit 2).
    for value in [
        "nonsense",
        "55778904-0299-11f1-b1b8-4ef0c4956feb",
        "55778904-0299-11f1-b1b8-4ef0c4956feb:t1",
        "55778904-0299-11f1-b1b8-4ef0c4956feb:t-1:2",
        "ZZZZZZZZ-0299-11f1-b1b8-4ef0c4956feb:1",
        "55778904-0299-11f1-b1b8-4ef0c4956feb:t1:x",
        "55778904-0299-11f1-b1b8-4ef0c4956feb:1:2:3",
    ] {
        let out = run_cli(&[path, "--include-gtid", value]);
        assert_eq!(out.status.code(), Some(2), "{value}");
    }
}

#[test]
fn cli_stats_emits_json_over_kept_events() {
    let mut map = vec![1, 0, 0, 0, 0, 0, 0, 0];
    map.extend_from_slice(b"\x03app\0\x01t\0\x01\x03\x00\x00");
    let mut row = vec![1, 0, 0, 0, 0, 0, 0, 0];
    row.extend_from_slice(&[2, 0, 1, 1, 0, 42, 0, 0, 0]);
    let bodies = [
        map.len(),
        row.len(),
        // Regular GTID: flags + sid + gno.
        1 + 16 + 8,
        // XID: 8 bytes.
        8,
    ];
    let expected_bytes: u64 = bodies.iter().map(|len| (19 + len) as u64).sum();
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event(19, &map));
    bytes.extend(event(30, &row));
    bytes.extend(event(33, &gtid_body([0x11; 16], 1)));
    bytes.extend(event(16, &123u64.to_le_bytes()));
    let f = file(&bytes);
    let path = f.path().to_str().unwrap();
    let stats_of = |args: &[&str], expected_code: i32| {
        let out = run_cli(args);
        assert_eq!(
            out.status.code(),
            Some(expected_code),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    };

    let stdout = stats_of(&[path, "--stats"], 0);
    assert_eq!(stdout.lines().count(), 1, "one JSON line: {stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["files"], 1);
    assert_eq!(value["events_total"], 4);
    assert_eq!(value["bytes_total"], expected_bytes);
    assert_eq!(value["transactions"], 1);
    assert_eq!(value["errors"], 0);
    let by_type = value["by_type"].as_object().unwrap();
    assert_eq!(by_type.len(), 4, "{stdout}");
    assert_eq!(by_type["table_map"], 1);
    assert_eq!(by_type["write_rows"], 1);
    assert_eq!(by_type["gtid"], 1);
    assert_eq!(by_type["xid"], 1);
    let by_table = value["by_table"].as_object().unwrap();
    assert_eq!(by_table.len(), 1, "{stdout}");
    assert_eq!(by_table["app.t"], 1);

    // --format is accepted but ignored: the output is still stats JSON.
    let stdout = stats_of(&[path, "--stats", "--format", "csv"], 0);
    assert!(stdout.starts_with("{\"files\":1"), "{stdout}");

    // Stats respect the other filters: only kept events are counted.
    let stdout = stats_of(&[path, "--stats", "--events", "xid"], 0);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["events_total"], 1);
    assert_eq!(value["transactions"], 0);
    assert_eq!(value["bytes_total"], 19 + 8);
    let by_type = value["by_type"].as_object().unwrap();
    assert_eq!(by_type.len(), 1);
    assert_eq!(by_type["xid"], 1);
    assert_eq!(value["by_table"].as_object().unwrap().len(), 0);

    // A partial failure is still counted: corrupt tail, exit 3, errors = 1.
    let mut corrupt = bytes.clone();
    corrupt.extend(corrupt_event());
    let corrupt_file = file(&corrupt);
    let stdout = stats_of(&[corrupt_file.path().to_str().unwrap(), "--stats"], 3);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["errors"], 1);
    assert_eq!(value["files"], 1);

    // --output semantics are kept: the JSON lands in the output file.
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("stats.json");
    let status = Command::new(env!("CARGO_BIN_EXE_binlog-inspect"))
        .arg(path)
        .arg("--stats")
        .arg("--output")
        .arg(&output)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(0));
    let content = std::fs::read_to_string(&output).unwrap();
    let value: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(value["events_total"], 4);
}

#[test]
fn cli_completions_print_and_exit_before_reading_input() {
    // zsh completions start with the #compdef marker.
    let out = run_cli(&["--completions", "zsh"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("#compdef binlog-inspect"), "{stdout}");
    // Other shells produce non-empty output too.
    for shell in ["bash", "fish", "powershell", "elvish"] {
        let out = run_cli(&["--completions", shell]);
        assert_eq!(out.status.code(), Some(0), "{shell}");
        assert!(!out.stdout.is_empty(), "{shell} produced no completions");
    }
    // Every other option is ignored and no file is opened.
    let out = run_cli(&["--completions", "zsh", "/nonexistent/input.binlog"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("#compdef"));
    // Unknown shells are usage errors (exit 2).
    let out = run_cli(&["--completions", "tcsh"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn cli_max_event_size_caps_and_validates() {
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(event(16, &123u64.to_le_bytes()));
    let f = file(&bytes);
    let path = f.path().to_str().unwrap();

    // A cap below the real event size rejects it as invalid or oversized
    // (lenient mode: exit 3 with a partial-failure report).
    let out = run_cli(&[path, "--max-event-size", "20"]);
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid or oversized"), "{stderr}");

    // The explicit default keeps parsing.
    let out = run_cli(&[path, "--max-event-size", "67108864"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("\"xid\":123"));

    // Values above the 1 GiB inspection limit are usage errors (exit 2).
    let out = run_cli(&[path, "--max-event-size", "1073741825"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("exceeds the 1 GiB inspection limit"),
        "{stderr}"
    );
}
