# ROADMAP

Based on the conclusions of three independent expert reviews dated 2026-11-05 (binlog protocol correctness / Rust engineering quality / documentation & UX). Every item includes acceptance criteria; the "Contract" section is the unified API specification for the parallel implementations, and implementations must conform to it.

Status markers use `done` for implemented and verified work, `partial` for a delivered subset, and `backlog` for deferred work. W1–W3 are the original batches, W4 is the 2026-11-06 re-review, and W5 is the 2026-11-07 source and roadmap review. Historical findings below describe the code at the time of review. The current status and the W5 section record subsequent fixes.

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
- **R23 [done W1] Packaging metadata: Cargo.toml gains description/readme/keywords/release profile (lto+strip); version bumped to 0.2.0; CHANGELOG.md added.**
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
- **R32 [done W3] crates.io publishing**: v0.4.0 published on 2026-11-05 (the 0.1–0.3 lines were never published, so 0.4.0 is the first crates.io release), with docs.rs documentation and prebuilt binaries + sha256 checksums on the GitHub Release. `repository = "https://github.com/houseme/binlog-inspect"` confirmed in Cargo.toml.
- **R33 [done W3] Partial JSON diff application**: TLV 14/15 accepted (and stripped for the library after checksum verification), diffs applied against before values in the code 39 after image (`payload.after`), unappliable diffs preserved as loss-marking `partial_json` values.
- **R34 [backlog] MariaDB-specific event types** (GTID 163 etc.). Requires MariaDB reference implementation and samples; not implementable from this repository alone.
- **R35 [done W3] Advisory `log_pos` continuity checking**: non-fatal stderr warnings (offset + size mismatch, zero log_pos ignored, buffer capped) and `BinlogParser::take_warnings` for library callers.
- **R36 [done W3] Tolerance policy**: a row event may declare fewer columns than the table map (missing tail columns render as `absent`); declaring more is still an error.
- **R37 [done W4] The CLI layer moved behind a default-on `cli` feature** (clap, clap_complete, jiff, anyhow; binary declares `required-features = ["cli"]`). The manifest declares Rust 1.88 and CI runs its check/test gate (R43). Local verification uses the installed stable toolchain as required by AGENT.md.
- **R38 [partially done W3] `deny.toml` added, and `cargo deny check` (advisories, licenses, bans, sources) runs in the audit workflow** on a daily schedule and on manual dispatch, alongside the RustSec advisory scan; the virtual workspace lib/bin split remains [backlog].
- **R39 [done W4/W5] JSON value hardening.**
  Findings A1/A2/A4/A6/A7 of the 2026-11-06 protocol re-review.
  - Opaque jsonb members (`NEWDECIMAL`, DATE/TIME/DATETIME opaques — what MySQL writes for decimal literals or DECIMAL column values inside JSON) currently fail the whole file via `serde_json::Value::try_from(jsonb)`; decode through the library's `JsonDom` path instead (or per-cell loss marking), never failing the event on legitimate data.
  - Cap jsonb nesting depth (MySQL's own limit is 100) during conversion and return `InvalidData` on deeper hostile input — a depth-60k fixture currently aborts the process (stack overflow), violating fail-closed.
  - Pin the stripped-table-map checksum path with a test: flipping a byte inside a PARTIAL_JSON TLV of a checksummed table map must yield "event checksum mismatch" even though the library never sees those bytes.
  - Document and pin the JSON-diff edge-case semantics (object REPLACE as upsert, array INSERT at index ≤ len) with a comment referencing `sql-common/json_diff.cc` behavior.
  Acceptance: a fixture with an opaque-NEWDECIMAL JSON member decodes and the file's event count is intact; a depth-60k jsonb fixture yields `InvalidData` with an offset, not an abort; the corrupted-TLV checksum test fails with the documented message.
- **R40 [done W4/W5] CLI correctness and packaging hygiene.**
  Findings B1/B6/B7/B10 of the 2026-11-06 engineering re-review.
  - Broken-pipe exit 0 must hold for every write path: `FormatterError::Json(serde_json::Error)` wraps the io error one level down, so `is_broken_pipe` misses it (`serde_json::Error::io_error_kind()`); `binlog-inspect big.binlog | head -c 100` currently exits 1.
  - Drop the unused `clap` dev-dependency; the `required-features = ["cli"]` on the test targets is the correct mechanism.
  - `remote` is a CLI-layer feature: declare `remote = ["cli", …]` so the combination `--no-default-features --features remote` still builds the binary.
  - tests/remote.rs: a response with `Content-Length` larger than the body deadlocks until the 30 s drain bound; close the write side (or skip the wait) for known-truncated responses so the suite runs fast deterministically.
  Acceptance: a large-output piped-into-`head` test exits 0; `cargo test --locked --no-default-features --features remote` builds the binary; the remote suite has no 30 s stall.
- **R41 [done W4/W5] V1 row-event labeling consistency.**
  Finding A3. Codes 23–25 (`WRITE/UPDATE/DELETE_ROWS_EVENT_V1`, MySQL 5.5 era) are decoded as full row payloads by the library but labeled `EventType::Unknown` — `event_type=unknown` with `payload.kind=rows`. The pre-GA codes are 20–22 (which stay `Unknown{raw_len}`); correct the "pre-GA" naming wherever it appears. Map 23–25 onto `WriteRows`/`UpdateRows`/`DeleteRows`.
  Acceptance: a code-23 fixture emits `event_type=write_rows` with a decoded row payload; `--events write_rows` selects it; DESIGN/USAGE no longer call 23–25 pre-GA.
- **R42 [implemented W4; performance acceptance pending] Hot-path performance pass.**
  Findings B12/B13/B14. `signedness()` re-serializes the whole table map for every row event — cache it per table id (invalidate on re-registration; correctness first, benchmarks optional). `apply_pair` matches pending JSON cells against before columns with `Vec::find` (O(columns²) on hostile input) — both images are in table-column order, so a linear merge suffices. `Stats::record` allocates `format!("{db}.{t}")` per row event — reuse a scratch String.
  Acceptance: all existing tests pass unchanged; a micro-benchmark or before/after timing shows no regression; behavior (JSON output) is byte-identical.
- **R43 [done W4/W5] CI and packaging hardening.**
  Findings B5/B8/B9/B11/B15.
  - True MSRV is **1.88** (let-chains; edition 2024 alone would allow 1.85): verify by building with a 1.88 toolchain, then set `rust-version = "1.88"` and add a CI job pinned to 1.88 (closes the R37 remainder). If the toolchain cannot be installed in the implementing environment, do not claim the version — leave `rust-version` unset and report.
  - The lint job gains `cargo clippy --locked --all-targets --no-default-features -- -D warnings` and the matrix gains `--no-default-features --features remote`.
  - Pin third-party actions by full commit SHA (R24 policy) where the SHA can be resolved; keep version comments for dependabot.
  - `.crate` content: exclude internal-only files (AGENT.md, EXECUTION.md, ROADMAP.md, `.github/`) via `package.exclude`; CHANGELOG.md and DESIGN.md stay.
  - Regression tests: the 100-entry advisory-warning cap; `ParserError` messages carry the file offset.
  Acceptance: CI matrix covers the three feature combinations with clippy and test; the two regression tests are in place.
- **R44 [done W4/W5] Documentation truth pass.**
  Findings C1–C12. The USAGE `--events` tables and the `EventType::PartialUpdateRows` rustdoc still claim the after image is "not decoded" (false since R33); stale "(Chinese)" markers in README.en/USAGE; DESIGN's verification-strategy clippy wording; the Contract section predates R26/R33 and must be annotated as the historical batch-1 spec; USAGE library section needs the crates.io dependency form; CHANGELOG `[0.3.0]`/`[0.2.0]`/`[0.1.0]` headings lack link definitions (drop the brackets — no tags exist for them); R23's version marker; explicit toolchain anchor in README.md; `--events` table ordering.
  Acceptance: every documented statement matches behavior; the docs build clean; bilingual parity holds.
- **R45 [W5] Error-semver pass for 0.5.0**: structured `ParserError` variants and `#[non_exhaustive]` on the public error/payload enums — decided once while the API is young; a breaking change by design.
- **R46 [partial W5] Streaming TransactionPayload decoding**. R46a adds the library `visit_events` callback API, sharing framing, checksums and inner-event decoding with `events()`. It emits start/event/end notifications and terminates the parser on callback error, cancellation or panic. R46b remains in the backlog for CLI streaming output and its partial-output contract. The existing iterator and CLI collect the inner events of each payload.
- **R47 [partial W5] Fuzz/property harness**. R47a adds stable, deterministic properties through the public parser over synthetic previous-GTIDs, table-map/row, NONE payload and JSON fixtures. It covers chunked reads, truncation, bounded mutations, JSON round-trips and termination after errors. R47b retains continuous coverage-guided fuzzing and resource-isolated allocation stress tests in the backlog.

## W5-2. Second W5 Batch (2026-11-09, round-2 expert review)

From the 2026-11-09 two-expert re-review (engineering + documentation; the engineering reviewer empirically reproduced the R48 amplification: a 221-byte aliased jsonb decodes to 8,388,607 nodes, and ~331 wire bytes demand ~275 GB before the depth cap ever fires — a fail-closed violation).

- **R48 [W5-2] Decoded JSON node budget.** Thread a decoded-node budget (default 1,000,000) through `jsonb_to_serde`; exceeding it returns `InvalidData` carrying the offset instead of allocating towards an allocator abort. Cap `Vec::with_capacity(container.element_count())` (`count.min(4096)`) so a hostile element count cannot pre-allocate ~8 GiB from a ≤1 GiB event. Seed the wire-properties corpus with the aliased-jsonb fixture and a hostile single-container `element_count` fixture, and add the signedness re-registration plus library-level `with_max_event_size` tests that are still missing.
  Acceptance: the 221-byte reproduction errors cleanly; all suites unchanged; the new fixtures are in the corpus.
- **R45 [W5-2] Error-semver pass (delivers the 0.5.0 window item).** `#[non_exhaustive]` on `ParserError`, `FormatterError`, `EventType`, `EventPayload`, `CellValue`, `Signedness` (not on the plain output structs — it would forbid downstream construction). New structured `ParserError` variants with unchanged Display strings: `Checksum { offset }`, `Truncated { offset }`, `OversizedEvent { offset, size, limit }`, `TooManyInnerEvents { offset, limit }` (join with R46b), plus the existing `Io`/`EncryptedBinlog`/`InvalidHeader`; attach via a private `FrameError` in `read_framed_event`. Verified in review: `#[non_exhaustive]` composes with the clap `ValueEnum` derive, and no in-crate match needs a wildcard.
  Acceptance: the offset-in-error regression pins the new variants; clippy/tests/doc all green; version becomes 0.5.0.
- **R46b [W5-2] Inner-event memory bound.** `pub const DEFAULT_INNER_EVENT_LIMIT: usize = 250_000`, `pub fn with_inner_event_limit(self, limit: NonZeroUsize)` (mirrors `with_max_event_size`), CLI `--max-inner-events <COUNT>` (default 250_000, 0 rejected at parse time, exit 2). Enforced only in the collecting `transaction_payload()` path (`visit_events` is user-backpressured); breach emits `ParserError::TooManyInnerEvents` with wording naming the flag.
  Acceptance: a payload over the limit exits 3 (1 under `--strict`) with the documented message; raising the limit decodes it.
- **R47b [W5-2 partial] Coverage-guided fuzz scaffold.** A `fuzz/` workspace member (excluded from the .crate) with cargo-fuzz targets over the pure `&[u8]` prevalidation walkers (`validate_previous_gtids`, `validate_transaction_payload_header`, `validate_table_map_metadata`, `unsupported_tlv_ranges`, `verify_event_checksum`), the jsonb entry point (`jsonb_to_serde` with `-rss_limit_mb` — the R48 reproduction harness), the diff path grammar, and the CLI parsers; a scheduled, non-gating CI job runs a short fuzz round. proptest is skipped: `wire_properties.rs` already provides the deterministic corpus and proptest would duplicate it at real dev-dependency cost.
  Acceptance: `cargo fuzz build` succeeds locally or the job is recorded non-gating; the crate build is unaffected.
- **R51 [W5-2] Reliability and packaging hardening.** Advisory warnings survive a closed stderr (no `eprintln!` panic — exit 101 today via `2>&-`); `.gitignore` and `deny.toml` join `package.exclude`; the msrv job gains `cargo check --locked --no-default-features`; `Intvar.var_type`/`Incident.incident_type` emit canonical pinned strings instead of library `Debug` formatting.
  Acceptance: `binlog-inspect f 2>&- | head` no longer exits 101; the .crate list matches the policy; a test pins the canonical strings.
- **R52 [W5-2] Documentation consistency pass (round 2).** USAGE install sections name MSRV 1.88 (en/zh — C1); DESIGN's verification strategy matches the real `remote`-implies-`cli` matrix (C2); the jsonb depth cap and the opaque jsonb rendering rules get user-facing homes (README Limitations en/zh, USAGE errors/`value.type` sections, DESIGN boundaries — C3/C4); AGENT/EXECUTION/README gate lists match the three-variant clippy CI reality (C5); the CHANGELOG [Unreleased] scope line covers the W5 follow-ups (C6); the `unknown` rows mention pre-GA codes 20–22 (C7); R45's marker vocabulary is fixed (C8).
  Acceptance: the doc-drift checks an expert reviewer used all pass by inspection; bilingual parity holds.

## W5. Source Review and Delivery Scope (2026-11-07)

- **R39 follow-up** covers JSON quoted-path decoding, consistent container-depth counting at the 100-level boundary, validation of every column list in ENUM/SET metadata, and complete required column metadata before row decoding. Regression fixtures retain malformed input as an error or an explicit loss marker.
- **R40 follow-up** centralizes broken-pipe handling across CLI output paths. A closed-reader regression covers every completion shell on Unix, alongside the existing event-output pipe tests.
- **R43 follow-up** adds an explicit feature matrix axis, yielding three operating systems times four feature combinations. Feature-specific cache keys isolate build-output assertions. The remaining audit action is pinned to a verified commit.
- **R45** stays assigned to the 0.5.0 compatibility window. Its new error variants and non-exhaustive annotations require a coordinated API migration.
- **R46a and R47a** are the independently implemented W5 library and test deliveries. Their remaining work is recorded separately above.
- **R49 [done W5] Row iterator progress**. The deterministic mutation corpus reproduced an unbounded loop when a nonempty ordinary row body selected no columns. The parser now rejects that shape for V1/V2 writes, updates and deletes, while accepting empty row bodies, one-sided updates and the distinct partial-update value-options encoding.
- **Column compatibility**. Raw `VAR_STRING` and `TYPED_ARRAY` table-map columns return an explicit `Unsupported` error because the current dependency exposes inconsistent metadata to its row decoder. Typed arrays are a legitimate server type whose support requires a dedicated decoder fix.
- **R50 [backlog] Column metadata value constraints**. The W5 guards validate required byte spans. Precision/scale, fractional-second precision and other value-range constraints still require focused reproduction and compatibility checks against the dependency and server formats.
- **R48 [backlog] Decoded JSON resource budget**. Static review identified that repeated jsonb child offsets can reference the same subtree. Reproduce the decoded-output amplification in a resource-isolated harness before choosing node/byte limits and compatibility behavior.
- **R34 and R38** retain the MariaDB and workspace-split backlog. R42 still needs a reproducible performance acceptance record. The local CSV microbenchmarks from the source review showed baseline drift, so they establish no stable speedup percentage.

## Contract: API Specification for the First Parallel Implementation Batch

> Historical batch-1 specification, kept verbatim for provenance. The code has since evolved beyond it (R26 added `ranges`/GTID fields to `EventFilter`, R33 added `PartialUpdateRows.after`, `EventType` derives `ValueEnum` only under the `cli` feature); consult the rustdoc for the current signatures.

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
