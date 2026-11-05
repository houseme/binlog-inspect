# Usage guide

[中文](USAGE.zh-CN.md) | [Project README](../README.md)

## Install and build

The project is not published on crates.io yet; build or install from source. The current Rust stable toolchain is required (the project uses the Rust 2024 edition; its minimum supported version has not been verified):

```sh
cargo install --path .        # installs into ~/.cargo/bin
# or build inside the project only
cargo build --locked --release
./target/release/binlog-inspect --help
```

Remote download support is disabled by default and requires the `remote` feature:

```sh
cargo build --locked --release --features remote
```

Alternatively, use `cargo run --locked -- [arguments]`; add `--features remote` before `--` when using URLs. At least one local file or URL is required. Local files are processed in the supplied order, followed by URLs in their supplied order, with independent parser state for each input. A Rotate event does not automatically open the next file; list it explicitly.

## Command-line options

The table matches `binlog-inspect --help`:

| Option | Description |
| --- | --- |
| `[FILES]...` | Local binlog file paths; `-` reads from standard input. |
| `-f, --format <FORMAT>` | Output format: `jsonl` (default), `text`, or `csv`. |
| `-o, --output <FILE>` | Write to a new file instead of stdout; existing files are not overwritten. |
| `--events <EVENTS>` | Comma-separated event types; repeatable. Omit to include all types. |
| `--table <database.table>` | Filter to `database.table`; repeatable. Omit to include all tables and non-table events. |
| `--strict` | Abort on the first error in any input (exit code 1); without it an error stops the current file, remaining files are still processed, and the exit code is 3. |
| `--url <URL>` | HTTP(S) file URL; repeatable and available only when built with `remote`. |
| `-h, --help` / `-V, --version` | Show help / version. |

### All --events values

The values map one-to-one to the library `EventType` enum, which is also the set of values the JSON `event_type` field takes:

| Value | Meaning |
| --- | --- |
| `format_description` | Layout description for the rest of the binlog file (includes the server version). |
| `table_map` | Table identifier and its schema (database, table, column count). |
| `write_rows` | Inserted row images. |
| `update_rows` | Updated before/after row image pairs. |
| `delete_rows` | Deleted row images. |
| `partial_update_rows` | Partial JSON updates (WL#2955); only the before image is decoded, the after diff is not. |
| `query` | SQL statement event. |
| `xid` | Transaction commit identifier. |
| `gtid` | Global transaction identifier, including MySQL 8.4+ tagged GTIDs (`uuid:tag:gno`). |
| `anonymous_gtid` | GTID event of an anonymous transaction (`gtid` is `ANONYMOUS`). |
| `previous_gtids` | GTID set committed before the current binlog file. |
| `rotate` | Log rotation (reported only; the next file is not opened automatically). |
| `stop` | Server shutdown marker. |
| `rows_query` | Original statement for a row event. |
| `incident` | Replication incident report. |
| `intvar` | Statement-time integer variable assignment (AUTO_INCREMENT / LAST_INSERT_ID). |
| `rand` | Random seed for statement-based replication (undecoded: type and length only). |
| `user_var` | User-defined variable assignment (undecoded). |
| `begin_load_query` | Bulk load data carried outside the statement stream (undecoded). |
| `execute_load_query` | Bulk load execution marker (undecoded). |
| `heartbeat` | Replication heartbeat (undecoded; includes code 41). |
| `ignorable` | Event that readers that do not handle it may safely ignore (undecoded). |
| `transaction_context` | Two-phase commit transaction context (undecoded). |
| `view_change` | Group replication view change (undecoded). |
| `xa_prepare` | XA transaction prepare (undecoded). |
| `unknown` | Event type this version does not name (including MariaDB-specific 160+ codes). |

`transaction_payload` is also an `EventType` value but **cannot** be used with `--events`: compressed transaction payload events are rejected at the framing layer and are not supported yet. Selecting it fails at argument parsing with exit code 2:

```text
error: invalid value 'transaction_payload' for '--events <EVENTS>': compressed transaction payload events are not selectable; they are rejected at the framing layer (see DESIGN.md)
```

Unknown values also fail at argument parsing (exit code 2); the error message lists every valid value:

```text
error: invalid value 'bogus' for '--events <EVENTS>': unknown event type; valid values: format_description, table_map, write_rows, update_rows, delete_rows, partial_update_rows, query, xid, gtid, anonymous_gtid, previous_gtids, rotate, stop, rows_query, incident, intvar, rand, user_var, begin_load_query, execute_load_query, heartbeat, ignorable, transaction_context, view_change, xa_prepare, transaction_payload, unknown
```

A `--table` value must split at the first `.` into a non-empty database and table (for example `app.orders`); otherwise it fails (exit code 2): `invalid --table value: expected database.table`.

## Common examples

```sh
# Multiple files, event types and tables
./target/release/binlog-inspect mysql-bin.000001 mysql-bin.000002 --events write_rows,update_rows --table app.orders --table app.users --output changes.jsonl
# Human-readable summaries only
./target/release/binlog-inspect mysql-bin.000001 --events query,xid --format text
# Read from standard input
cat mysql-bin.000001 | ./target/release/binlog-inspect - --events xid
# Requires a build with the remote feature
./target/release/binlog-inspect --url https://example.com/mysql-bin.000001 --format csv --output rows.csv
```

## Exit codes

| Exit code | Meaning |
| --- | --- |
| `0` | Success: every input was fully parsed. |
| `1` | Hard error: a file could not be opened, the file header is invalid, the output target already exists, or the first parse error under `--strict`; processing stops immediately and no output file is produced. |
| `2` | CLI usage error: clap argument validation failed (for example an unknown `--events` value or a `--table` without `.`). |
| `3` | Partial parse failure: in the default (non-`--strict`) mode a parse error stops the current file while remaining files are still processed; errors are summarized per file (path and offset) on stderr. |

`--strict` means the first error on any input aborts everything (exit code 1); without it an error only ends the current file. On exit code 3 the output contains the successfully parsed prefix of each file (intentional, useful for triage); an `--output` file is published normally — delete it if it is not wanted. Hard errors (exit code 1) leave no output file behind.

```text
error: the following binlogs could not be fully parsed:
  mysql-bin.000001: binlog error at offset 31: invalid or oversized event
```

## Output formats

- `jsonl`: one JSON object per matching event. Output from multiple inputs does not include source filenames; run each input separately if attribution is needed.
- `text`: one event per line, formatted as `{timestamp} {event_type} server={server_id} pos={log_pos} {payload JSON}`.
- `csv`: header `timestamp,event_type,database,table,before,after`. Only decoded row events (`kind` of `rows`) produce one record per row change; `partial_update_rows`, row events without a resolved table map and all non-row events produce no records. Image fields contain CSV-escaped JSON strings, and a missing image is JSON `null`.

### Real output samples

The samples below were produced from a synthetic binlog built from the repository's test fixture bytes (not real data): five consecutive events — a GTID (`uuid:gno`), a Query (`SELECT 1`), a Table Map (`app.t`, one `LONG` column), a Write Rows (value `42`) and an XID (`123`); the timestamp is fixed at `1700000000`, the server ID is 7, and the output is the actual result of `binlog-inspect sample.binlog`.

`--format jsonl` (default):

```jsonl
{"offset":4,"timestamp":1700000000,"event_type":"gtid","event_type_code":33,"server_id":7,"event_size":44,"log_pos":48,"payload":{"kind":"gtid","gtid":"11111111-1111-1111-1111-111111111111:1","tag":null}}
{"offset":48,"timestamp":1700000000,"event_type":"query","event_type_code":2,"server_id":7,"event_size":44,"log_pos":92,"payload":{"kind":"query","database":"app","sql":"SELECT 1"}}
{"offset":92,"timestamp":1700000000,"event_type":"table_map","event_type_code":19,"server_id":7,"event_size":39,"log_pos":131,"payload":{"kind":"table_map","table_id":1,"database":"app","table":"t","column_count":1}}
{"offset":131,"timestamp":1700000000,"event_type":"write_rows","event_type_code":30,"server_id":7,"event_size":36,"log_pos":167,"payload":{"kind":"rows","table_id":1,"database":"app","table":"t","changes":[{"before":null,"after":{"columns":[{"index":0,"name":"@0","mysql_type":"LONG","signedness":"unknown","value":{"type":"int","value":42}}]}}]}}
{"offset":167,"timestamp":1700000000,"event_type":"xid","event_type_code":16,"server_id":7,"event_size":27,"log_pos":194,"payload":{"kind":"xid","xid":123}}
```

`--format text`:

```text
1700000000 gtid server=7 pos=48 {"kind":"gtid","gtid":"11111111-1111-1111-1111-111111111111:1","tag":null}
1700000000 query server=7 pos=92 {"kind":"query","database":"app","sql":"SELECT 1"}
1700000000 table_map server=7 pos=131 {"kind":"table_map","table_id":1,"database":"app","table":"t","column_count":1}
1700000000 write_rows server=7 pos=167 {"kind":"rows","table_id":1,"database":"app","table":"t","changes":[{"before":null,"after":{"columns":[{"index":0,"name":"@0","mysql_type":"LONG","signedness":"unknown","value":{"type":"int","value":42}}]}}]}
1700000000 xid server=7 pos=194 {"kind":"xid","xid":123}
```

`--format csv` (only row events produce records):

```csv
timestamp,event_type,database,table,before,after
1700000000,"write_rows","app","t","null","{""columns"":[{""index"":0,""name"":""@0"",""mysql_type"":""LONG"",""signedness"":""unknown"",""value"":{""type"":""int"",""value"":42}}]}"
```

Reading the same file from standard input (filtered with `--events xid`):

```jsonl
{"offset":167,"timestamp":1700000000,"event_type":"xid","event_type_code":16,"server_id":7,"event_size":27,"log_pos":194,"payload":{"kind":"xid","xid":123}}
```

The column name `@0` in the samples is a generated name: the synthetic table map carries no column-name metadata, while real binlogs usually do.

## Data model

Common fields of every JSON object:

| Field | Type | Description |
| --- | --- | --- |
| `offset` | integer | Byte offset of the event header within the file. |
| `timestamp` | integer | Header timestamp (Unix seconds). |
| `event_type` | string | Canonical event type (snake_case; same values as `--events`). |
| `event_type_code` | integer | Raw MySQL event type number. |
| `server_id` | integer | Originating server ID. |
| `event_size` | integer | Total event size including the header. |
| `log_pos` | integer | Position of the next event as recorded in the header. |
| `payload` | object | Decoded event content; `kind` identifies it. |

### Payload fields per payload.kind

| `payload.kind` | Appears with `event_type` | Fields |
| --- | --- | --- |
| `format_description` | `format_description` | `server_version`: string, truncated at the first NUL. |
| `table_map` | `table_map` | `table_id`, `database`, `table` (strings), `column_count`: integer. |
| `rows` | `write_rows` / `update_rows` / `delete_rows` | `table_id`: integer; `database`, `table`: strings; `changes`: array, one `{"before": image or null, "after": image or null}` per row. A write normally has only an `after` image, a delete only a `before` image, and an update both. |
| `partial_update_rows` | `partial_update_rows` | `table_id`, `database`, `table`; `before`: array, one full row image or `null` (when the image is absent) per row. The JSON-diff after image is intentionally not decoded. |
| `unresolved` | `write_rows` / `update_rows` / `delete_rows` / `partial_update_rows` (no table map) | `table_id`: integer. |
| `query` | `query` | `database`, `sql`: strings. |
| `xid` | `xid` | `xid`: integer. |
| `gtid` | `gtid` / `anonymous_gtid` | `gtid`: string, formatted as `uuid:gno` (untagged), `uuid:tag:gno` (tagged, MySQL 8.4+) or `ANONYMOUS` (anonymous transaction); `tag`: string or `null`. |
| `previous_gtids` | `previous_gtids` | `gtid_set`: string, a mysqlbinlog-style set rendering (`uuid[:tag]:interval`, SIDs separated by commas). |
| `rotate` | `rotate` | `next_file`: string; `position`: integer. |
| `stop` | `stop` | No fields (empty object `{}`). |
| `rows_query` | `rows_query` | `sql`: string. |
| `incident` | `incident` | `incident_type`: string (for example `INCIDENT_LOST_EVENTS`; unrecognized codes render as `UNKNOWN(n)`); `message`: string. |
| `intvar` | `intvar` | `var_type`: string (`INVALID_INT_EVENT` / `LAST_INSERT_ID_EVENT` / `INSERT_ID_EVENT`); `value`: integer. |
| `unknown` | `rand`, `user_var`, `begin_load_query`, `execute_load_query`, `heartbeat`, `ignorable`, `transaction_context`, `view_change`, `xa_prepare`, `unknown`, and all MariaDB-specific types | `raw_len`: integer, length of the retained event data. |

### Row image structure

A row image (the "image" entries in the table above) follows table-column order:

| Field | Type | Description |
| --- | --- | --- |
| `columns` | array | One entry per table column, including columns omitted by a minimal row image. |

Each column (`ColumnValue`):

| Field | Type | Description |
| --- | --- | --- |
| `index` | integer | Zero-based position in the table. |
| `name` | string or `null` | Column name from binlog metadata; `null` or a generated name (such as `@0`) when metadata is missing. |
| `mysql_type` | string or `null` | Canonical MySQL column type name (for example `LONG`); `null` when the image omits the column. |
| `signedness` | `signed` / `unsigned` / `unknown` or `null` | Signedness metadata for numeric columns; `null` for non-numeric ones. `unknown` means the metadata is missing and the underlying decoder uses a signed default, so check the table schema. |
| `value` | object | The value; see below. |

`value.type` values:

| `value.type` | `value.value` shape | Description |
| --- | --- | --- |
| `absent` | no `value.value` key | The column was omitted from this image. |
| `null` | no `value.value` key | SQL NULL. Distinct from `absent`. |
| `bytes` | lowercase hexadecimal string | Binary and character content; no character set is assumed. |
| `int` | signed integer | Signed integer type. |
| `uint` | unsigned integer | Unsigned integer type. |
| `float` / `double` | string | Rendered as strings to preserve non-finite values. |
| `date` | `{year, month, day, hour, minute, second, micros}` | Date/time components, including zero dates. |
| `time` | `{negative, days, hours, minutes, seconds, micros}` | Signed TIME components, possibly exceeding 24 hours. |
| `json` | any JSON | Fully decoded JSON value. |

## Filtering

Event-type and table filters both apply; each accepts any member of its own list. Filtering happens after parsing and cannot bypass parsing errors.

- `--events`: keeps the listed `event_type` values; omit to keep all types.
- `--table`: keeps only matching table-map, row and partial-update events; non-table events such as Query, XID and GTID are excluded, and row events without a table map (`unresolved`) carry no table name so they never match. The value is split at the first `.` into `(database, table)` and compared exactly, without case normalization.

Range filters based on position, time or GTID are not available yet (planned; see the [ROADMAP](../ROADMAP.md)).

## Errors, input and safety

Events are read one at a time, with a 64 MiB maximum per event; memory use does not scale with file size. Plaintext files begin with `FE 62 69 6E`; encrypted files (`FD 62 69 6E`) are explicitly rejected with a hint to obtain plaintext through the MySQL server using `mysqlbinlog --read-from-remote-server`, taking care to protect the transfer and copy. HTTP(S) downloads are first written to an automatically cleaned temporary file and require sufficient disk space. Redirects from an HTTPS URL cannot downgrade to HTTP. Downloading does not decrypt data.

Framing (event sizes, checksums) and decoding errors are reported with the file offset: the SID count declared by previous-GTIDs headers and table-map optional metadata (including ENUM/SET variant counts) are bounds-checked before the underlying decoder runs, so hostile input produces an error instead of a crash. A CRC32 checksum mismatch is an error too. Errors are layered as described in [Exit codes](#exit-codes).

Unknown events retain their type code and `raw_len`; the `previous_gtids` event that every standard MySQL 5.7+/8.0 binlog contains is classified normally. These cases do not necessarily cause a nonzero exit, so success does not mean all content was decoded. Older versions, server variants and all types have not been comprehensively validated.

When the server sets `binlog_row_value_options=PARTIAL_JSON`, table maps carry optional metadata types (14/15) that the underlying library does not support, so such files fail at the first table map; this is a known library boundary, not something introduced by the pre-validation.

`--output` does not overwrite files, but shell `>` redirection is controlled by the shell and can overwrite its target.

## Differences from mysqlbinlog

- Different positioning: this tool is an offline plaintext binlog inspector; it does not implement the MySQL server protocol and does not decrypt. Use `mysqlbinlog --read-from-remote-server` against the server to obtain plaintext.
- Machine-oriented output: JSON Lines / CSV with one record per event, and row images that distinguish absent columns from SQL NULL; suitable for piping and scripting rather than mysqlbinlog's SQL replay output.
- Feature subset: no range filters such as `--start-position` / `--stop-position` / `--start-datetime` / `--include-gtid` (planned; see the [ROADMAP](../ROADMAP.md)), no replay-statement generation, no Rotate following, and compressed transactions are rejected at the framing layer.
- Verification behavior: CRC32 checksums are verified per event, and hostile event headers and table-map metadata are pre-validated fail-closed; `partial_update_rows` exposes only the before image.

## Use as a Rust library

In another project's `Cargo.toml`, reference the source using the appropriate path:

```toml
[dependencies]
binlog-inspect = { path = "../binlog-inspect" }
serde_json = "1"
```

The parser is generic over any `Read` input (a file, standard input, or an in-memory buffer), reads one event at a time, and bounds a single event's allocation to [`parser::MAX_EVENT_SIZE`](../src/parser.rs) (64 MiB):

```rust,no_run
use binlog_inspect::{event::{EventPayload, EventType}, parser::BinlogParser};
use std::io::Cursor;

// Build a minimal synthetic binlog: the 4-byte magic followed by one XID
// event (a 19-byte event header plus the 8-byte XID body).
fn xid_event(xid: u64) -> Vec<u8> {
    let size = 19u32 + 8;
    let mut event = Vec::new();
    event.extend(1u32.to_le_bytes()); // timestamp
    event.push(16); // XID_EVENT
    event.extend(7u32.to_le_bytes()); // server id
    event.extend(size.to_le_bytes());
    event.extend((4 + size).to_le_bytes()); // log_pos
    event.extend(0u16.to_le_bytes()); // flags
    event.extend(xid.to_le_bytes());
    event
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(xid_event(42));

    let mut parser = BinlogParser::from_reader(Cursor::new(bytes))?;
    for result in parser.events() {
        let event = result?;
        assert_eq!(event.event_type, EventType::Xid);
        println!("{}", serde_json::to_string(&event)?);
        if let EventPayload::Xid { xid } = event.payload {
            assert_eq!(xid, 42);
        }
    }
    Ok(())
}
```

Key points:

- `parser::BinlogParser`: `open` (local file, validates the magic and rejects encrypted headers), `from_reader` (any stream), `with_max_event_size` (override the 64 MiB default); `events()` iteration stops at the first error.
- The `event` module defines the output model; every type implements `Serialize` + `Deserialize` (`CellValue::Bytes` serializes to a lowercase hexadecimal string and deserialization expects the same form). `EventType::as_str` gives the snake_case name used in JSON, and `from_raw` maps raw type codes.
- `filter::EventFilter`: combined filtering with `kinds: HashSet<EventType>` and `tables: HashSet<(String, String)>`; `keep(&event)` decides.
- The `formatter` module: the `Formatter` trait writes to a `&mut dyn Write` and returns `Result<bool, FormatterError>` (whether the event produced output); `JsonLinesFormatter`, `TextFormatter` and `CsvFormatter` are provided (`header()` returns the CSV header).

Network downloading is implemented in the CLI and is not a public library API. See [execution and validation](../EXECUTION.md) for development checks and the scope of real-sample validation, and [design](../DESIGN.md) for further details (both in Chinese).
