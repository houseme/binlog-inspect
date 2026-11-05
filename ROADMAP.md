# ROADMAP

Based on the conclusions of three independent expert reviews dated 2026-11-05 (binlog protocol correctness / Rust engineering quality / documentation & UX). Every item includes acceptance criteria; the "Contract" section is the unified API specification for the parallel implementations, and implementations must conform to it.

Status markers: `[done W1]` implemented in the first batch, `[done W2]` implemented in the second batch, `[pending user decision]` waiting on the user, `[backlog]` not scheduled.

## R. Correctness Fixes (P0/P1)

- **R1 [done W1] Unify event types into the library-level `EventType` enum.**
  Status: the numeric-code→string map in `parser.rs` and the `--events` whitelist in `main.rs` were maintained separately and had already drifted (the help text lacked `transaction_payload`).
  Acceptance: `event::EventType` is the single source of truth (variants and mapping per the Contract); `ParsedEvent.event_type` is the enum; `--events` uses clap `ValueEnum`, unknown values error at parse time (exit code 2) and list all valid values; the JSON `event_type` field values remain exactly the old strings (snake_case).
- **R2 [done W1] Tagged GTIDs (code 42, MySQL 8.4+) must not lose the tag.**
  Status: output was `uuid:gno`, silently producing an invalid GTID. Acceptance: `payload.gtid` is the canonical full `uuid:tag:gno`, plus a structured `payload.tag` field (`null` when untagged); covered by tests.
- **R3 [done W1] Anonymous GTIDs (code 34) are named and decoded correctly.**
  Status: `event_type=gtid` while `payload.kind=unknown`. Acceptance: `event_type=anonymous_gtid`, `payload.kind=gtid`, `gtid="ANONYMOUS"` (matching mysqlbinlog).
- **R4 [done W1] `format_description.server_version` is truncated at the first NUL.**
  Status: output was `"8.0.30…\u0000…"`. Acceptance: no NUL padding; tested.
- **R5 [done W1] Hostile input must not abort the process (fail-closed contract).**
  Status: the crate performs unbounded `Vec::with_capacity` for code 35 (previous_gtids' `n_sids`) and for table-map optional metadata (ENUM/SET TLV `num_variants`).
  Acceptance: hand pre-validation before invoking the crate — compare code 35's header `n_sids` against the data length; validate each TME metadata TLV's declared length/variant counts against the remaining bytes; exceeding bounds returns an `InvalidData` error; panic-corpus tests include code 35 and hostile TLV fixtures.
- **R6 [done W1] Code 39 renamed to `partial_update_rows` with an independent payload.**
  Status: it was labeled `update_rows` and subsequently failed the whole file. Acceptance: decode the before image; the after diff is explicitly not decoded and documented; no longer enters the `update_rows` filter by mistake.
- **R7 [done, superseded by R25 W1] Remove the dead code 40 branch; `--events` no longer accepts `transaction_payload`.**
  Acceptance: code 40 is rejected at the framing layer (status quo preserved); `--events transaction_payload` errors at parse time with the reason; W2 turns it into real support via R24.
- **R8 [done W1] Row-image bitmap length validation.**
  Acceptance: when the collected `present` bit count ≠ column count, return `InvalidData` instead of silently truncating.

## C. CLI Reliability and Safety (P1)

- **R9 [done W1] Layered exit codes: 0 success; 1 hard error; 3 partial parse failure (clap usage errors stay 2).**
  The final error message must list failures per file (with paths and offsets).
- **R10 [done W1] `--output` atomic write + mode 0600.**
  Acceptance: write to a same-directory temporary file and rename/persist to the target after full success (an existing target still errors and is never overwritten); delete the temporary file on failure; unix mode 0600.
- **R11 [done W1] Refactor `process()` into an explicit `Outcome` enum**, no longer using `Ok(true)` to mean "partial failure".
- **R12 [done W1] Support stdin: file argument `-`.**
  Acceptance: `BinlogParser` becomes generic (`R: Read`), the CLI wires `-` to stdin; the per-event 64 MiB cap keeps memory bounded; tested.
- **R13 [done W1] Help text corrections.**
  `--strict` describes its actual semantics (any error terminates the current file; strict only aborts everything immediately); `value_name` of `--table`/`--url`/`--output` matches the docs; the no-input error message is feature-gated (non-remote builds do not mention `--url`).
- **R14 [done W1] `Formatter` trait writes directly to `Write`.**
  Acceptance: `fn format(&mut self, event, out) -> Result<bool, FormatterError>` (returns "did this event produce output"); `FormatterError` has Json/Io variants; the three formats produce bytes identical to the old version; `serde_json::to_writer` writes directly.

## F. Performance (P1)

- **R15 [done W1] Parser hot-path optimizations: reuse the event buffer across events; `BufReader` capacity 1 MiB; table-driven hex encoding.**
- **R16 [done W1] Remove the per-`format!` allocation from `EventFilter` table matching** (match against a set of `(String, String)` tuples).
- **R17 [done W1] Derive `Deserialize` for every type in the event model**, plus JSONL round-trip tests (deserialization of `CellValue::Bytes` expects hex strings, documented).

## L. Library Quality (P1)

- **R18 [done W1] Add `#![warn(missing_docs)]` and `#![forbid(unsafe_code)]` to `lib.rs`; crate docs include a runnable doc-test example.**
- **R19 [done W1] `mysql_type` outputs canonical names** (match over `ColumnType` constants to stable strings), not the crate's Debug formatting.
- **R20 [done W1] Expand event-type coverage.**
  Typed decoding: `Stop`, `PreviousGtids` (gtid_set string), `RowsQuery` (SQL), `Incident` (type + message), `Intvar` (type + value), tagged/anonymous GTIDs.
  Named types that keep an `Unknown{raw_len}` payload: `rand`, `user_var`, `begin_load_query`, `execute_load_query`, `heartbeat`, `ignorable`, `transaction_context`, `view_change`, `xa_prepare` (41 folded into `heartbeat`).
  MariaDB 160+ types remain `unknown`.
- **R21 [done W1] The parser exposes `pub const MAX_EVENT_SIZE` and a `with_max_event_size` constructor** (used by R32).

## D. Documentation and Engineering (P1)

- **R22 [done W1] Comprehensive documentation corrections (kept in sync across languages).**
  Additions: field tables for every payload kind; real output samples for the three formats; exit-code explanation; limitation notes (tagged-GTID support statement, rotate not followed, 64 MiB event cap, `previous_gtids` required by standard binlogs no longer shown as unknown, `--table` restrictions for identifiers containing dots); a "differences from mysqlbinlog" section; an install section; all `--events` values visible.
- **R23 [done W1; version now 0.3.0] Packaging metadata: Cargo.toml gains description/readme/keywords/release profile (lto+strip); version bumped to 0.2.0; CHANGELOG.md added.**
  `license`/`repository` are covered by R33.
- **R24 [done W1] CI enhancements: clippy+test also for no-default-features; rust-cache; dependabot; concurrency group; actions pinned by SHA.**

## W2. Feature Extensions (Second Batch)

- **R25 [done W2] Compressed transaction payload (code 40) support.**
  Acceptance: validate the compression-algorithm bytes before decompressing (preventing crate `unwrap` panics); use streaming `decompressed()` (the pre-allocating danger API is forbidden); cap total decompressed output (anti-bomb); inner events are decoded through a shared `EventStreamReader::read_decompressed` while maintaining inner table maps; output includes the compression type and uncompressed_size; nested TPE is unsupported (the crate already rejects it); tests with real/synthetic compressed samples; `--events transaction_payload` becomes selectable again.
- **R26 [done W2] Range filters: `--start-position`/`--stop-position` (byte offsets), `--start-datetime`/`--stop-datetime` (event timestamps, parsed as local time), `--include-gtid` (exact `uuid[:tag]:gno`, repeatable).**
  Filtering compares `offset`/`timestamp`/`payload.gtid` after parsing; parser state is unchanged.
- **R27 [done W2; transactions counts Gtid payload events incl. anonymous, XID not counted] `--stats` summary mode**: counts by event type/table, transaction count (GTID/XID), JSON to stdout (composable with other filters).
- **R28 [done W2; delivered as the --completions flag, not a subcommand, to keep the flat CLI] `binlog-inspect completions <shell>`** (clap_complete).
- **R29 [done W2] Remote download `--max-download-size` (default 4 GiB)**: abort with an error beyond the limit; document the boundary in DESIGN.
- **R30 [done W2; parse-time errors distinguish the 1 GiB limit; runtime oversized events share the framing message] `--max-event-size`** wired to the R21 constructor; the error message distinguishes "above the inspection limit" from "corrupt".

## P. Pending and Deferred

- **R31 [done] LICENSE choice: Apache-2.0**, confirmed through the repository's own git history (LICENSE file, `license = "Apache-2.0"`, SPDX headers in commit 95d2422 / 3f27b0e). Swap by replacing LICENSE and the Cargo.toml field if the choice ever changes.
- **R32 [pending user decision] crates.io publishing**: licensing and the repository URL now exist; only the publish act (and a maintainer-owned `repository = "https://github.com/houseme/binlog-inspect"` confirmation) remains. The README/USAGE already advertise library reuse.
- **R33 [backlog] Partial JSON diff application** (merging WL#2955 diffs into full values). High effort; W2 delivers only R6's honest presentation.
- **R34 [backlog] MariaDB-specific event types** (GTID 163 etc.). Requires MariaDB reference implementation and samples.
- **R35 [backlog] Advisory `log_pos` continuity checking** (needs artificial-flag awareness to avoid false positives).
- **R36 [backlog] Tolerance policy for row-event `num_columns` ≤ table-map column count** (currently strict equality, always true for single-primary binlogs; keep as-is and document).
- **R37 [backlog] MSRV verification / rust-toolchain pinning**; move `clap` behind a `cli` feature (if `EventType` derives `ValueEnum` when implementing R1, defer this item).
- **R38 [backlog] `cargo deny`/audit integration; split into a virtual workspace with lib/bin crates.**

## Contract: API Specification for the First Parallel Implementation Batch

Implementations must match the signatures below (both parallel implementers take this as authoritative; report contract defects in the final report instead of unilaterally deviating):

```rust
// —— src/event.rs ——
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    FormatDescription, TableMap, WriteRows, UpdateRows, DeleteRows,
    PartialUpdateRows, Query, Xid, Gtid, AnonymousGtid, PreviousGtids,
    Rotate, Stop, RowsQuery, Incident, Intvar, Rand, UserVar,
    BeginLoadQuery, ExecuteLoadQuery, Heartbeat, Ignorable,
    TransactionContext, ViewChange, XaPrepare, TransactionPayload, Unknown,
}
impl EventType {
    pub fn as_str(self) -> &'static str;      // snake_case, identical to the old JSON strings
    pub fn from_raw(code: u8) -> Self;        // see the mapping below
}
```

Raw-code mapping (`from_raw`): `2 Query, 3 Stop, 4 Rotate, 5 Intvar, 13 Rand, 14 UserVar,
15 FormatDescription, 16 Xid, 17 BeginLoadQuery, 18 ExecuteLoadQuery, 19 TableMap,
26 Incident, 27 Heartbeat, 28 Ignorable, 29 RowsQuery, 30 WriteRows, 31 UpdateRows,
32 DeleteRows, 33 Gtid, 34 AnonymousGtid, 35 PreviousGtids, 36 TransactionContext,
37 ViewChange, 38 XaPrepare, 39 PartialUpdateRows, 40 TransactionPayload, 41 Heartbeat,
42 Gtid; everything else (including MariaDB 160+) is Unknown`.

```rust
// —— ParsedEvent (JSON field names unchanged; event_type serializes as a snake_case string) ——
pub struct ParsedEvent {
    pub offset: u64, pub timestamp: u32, pub event_type: EventType,
    pub event_type_code: u8, pub server_id: u32, pub event_size: u32,
    pub log_pos: u32, pub payload: EventPayload,
}

// —— EventPayload (existing variant fields unchanged; additions/adjustments below) ——
pub enum EventPayload {
    FormatDescription { server_version: String },          // R4: NUL truncation
    TableMap { table_id: u64, database: String, table: String, column_count: u64 },
    Rows { table_id: u64, database: String, table: String, changes: Vec<RowChange> },
    PartialUpdateRows { table_id: u64, database: String, table: String,
                        before: Vec<Option<RowImage>> },    // R6: after diff not decoded
    Unresolved { table_id: u64 },
    Query { database: String, sql: String },
    Xid { xid: u64 },
    Gtid { gtid: String, tag: Option<String> },            // R2/R3: uuid[:tag]:gno; anonymous="ANONYMOUS"
    PreviousGtids { gtid_set: String },                     // R20: mysqlbinlog-style set string
    Rotate { next_file: String, position: u64 },
    Stop,                                                   // R20
    RowsQuery { sql: String },                              // R20
    Incident { incident_type: String, message: String },    // R20
    Intvar { var_type: String, value: u64 },                // R20
    Unknown { raw_len: usize },
}
```

```rust
// —— src/filter.rs ——
pub struct EventFilter {
    pub kinds: HashSet<EventType>,
    pub tables: HashSet<(String, String)>,   // R16; the CLI splits db.table at parse time
}

// —— src/formatter.rs ——
#[derive(Debug, thiserror::Error)]
pub enum FormatterError {
    #[error(transparent)] Json(#[from] serde_json::Error),
    #[error(transparent)] Io(#[from] std::io::Error),
}
pub trait Formatter {
    fn header(&self) -> Option<&'static str> { None }
    fn format(&mut self, event: &ParsedEvent, out: &mut dyn Write)
        -> Result<bool, FormatterError>;     // Ok(false) = no output for this event
}

// —— src/parser.rs ——
pub const MAX_EVENT_SIZE: u32 = 64 * 1024 * 1024;
pub struct BinlogParser<R: Read = std::fs::File> { /* ... */ }
impl BinlogParser<std::fs::File> {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ParserError>;   // includes magic validation
}
impl<R: Read> BinlogParser<R> {
    pub fn from_reader(reader: R) -> Result<Self, ParserError>;         // R12
    pub fn with_max_event_size(self, cap: u32) -> Self;                 // R21
    pub fn events(&mut self) -> impl Iterator<Item = Result<ParsedEvent, ParserError>> + '_;
}
```

CLI behavior specification: `--events` values are all `EventType` snake_case names, except `transaction_payload`, which is rejected with "compressed transaction payload events will be supported in a later version; they are currently rejected at the framing layer"; a `--table` value must be split at the first `.` into `(database, table)` with both parts non-empty, otherwise it errors; exit-code 0/1/2/3 semantics per R9; the file argument `-` reads stdin; the text format keeps `{ts} {event_type} server={id} pos={log_pos} {payload_json}`.
