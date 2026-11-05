# Changelog

This project follows the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and [Semantic Versioning](https://semver.org/). Entries are written in English; breaking changes are explicitly marked.

## [Unreleased]

Fourth batch, from the 2026-11-06 multi-expert re-review (ROADMAP R39–R44).

### Added

- JSON columns containing opaque jsonb values (decimals and date/time values stored in JSON — type byte `NEWDECIMAL` and friends) decode through the library's `JsonDom` rendering instead of failing the whole file; opaque diff members render as their canonical string form.
- Row events with type codes 23–25 (the MySQL 5.5-era V1 write/update/delete rows events) are labeled `write_rows`/`update_rows`/`delete_rows` instead of `unknown` — the payload was always decoded; only the label was wrong (the truly pre-GA codes are 20–22, which remain `unknown`).

### Fixed

- JSON columns whose jsonb tree nests deeper than MySQL's limit of 100 containers return a parse error carrying the offset; a hostile ~60,000-deep value previously overflowed the stack and aborted the process (fail-closed violation).
- The broken-pipe exit-0 contract now holds on every write path: `FormatterError::Json(serde_json::Error)` write failures are recognized as `BrokenPipe` via `serde_json::Error::io_error_kind()`, so piping into `head` exits 0 again.
- `rust-version = "1.88"` is claimed and enforced by a dedicated MSRV CI job (the crate's let-chains set the floor; the locked `uuid` was pinned to 1.26.1 because 1.27+ requires 1.89).
- All third-party GitHub Actions are pinned by full commit SHA (one exception recorded in the workflow: `rustsec/audit-check@v2`, whose SHA could not be resolved at the time).
- Documentation: the USAGE `--events` tables, the `EventType::PartialUpdateRows` rustdoc, and the library/limitation sections now describe the applied JSON-diff after image instead of the pre-R33 "not decoded" wording; the library section documents the full `EventFilter` (ranges, GTID allowlist) and the crates.io dependency form; stale language markers removed; the ROADMAP Contract section is annotated as the historical batch-1 spec.

### Changed

- **Packaging**: the `remote` feature now implies `cli` (so `--no-default-features --features remote` builds the binary); the unused `clap` dev-dependency is gone; the published `.crate` excludes internal engineering documents (`AGENT.md`, `EXECUTION.md`, `ROADMAP.md`, `docs/`, `tests/`, `.github/`).
- Performance: per-table signedness metadata no longer re-serializes the table map for every row event; JSON-diff cell matching is linear in the column count; `--stats` reuses a scratch string for `by_table` keys. JSON output is byte-identical.
- CI: the lint job runs clippy for no-default-features as well; the test matrix covers `--no-default-features --features remote`; the loopback download tests no longer spend a 30 s drain bound on truncated responses.

## [0.4.0] - 2026-11-05

Third batch: partial JSON diff application, backlogged correctness and packaging items.

### Added

- **Partial JSON updates (WL#2955) are fully decoded.** Binlogs produced with `binlog_row_value_options=PARTIAL_JSON` previously failed at the first row event because their table maps carry optional metadata types 14/15 that the underlying library does not know; those TLVs are now accepted (and transparently stripped before the library parses the table map, after checksum verification on the original bytes), and the JSON diff sequences in `partial_update_rows` after images are applied against the before image's JSON value: an applied column renders as a full JSON document (`"type": "json"`), a diff that cannot be applied renders as the new loss-marking value type `"type": "partial_json"` carrying the preserved diffs and the reason. New payload key `payload.after` on `partial_update_rows` (one applied row image or `null` per row, alongside the existing `before`).
- Advisory `log_pos` continuity checking (R35): a header `log_pos` that does not land right after its event (a sign of tampering or splicing) prints a non-fatal `warning: log_pos … does not match …` line on stderr; parsing continues and the exit status is unaffected. The warning buffer is capped, and `BinlogParser::take_warnings` exposes it to library callers.
- Column-count tolerance (R36), mirroring the MySQL applier: a row event may declare fewer columns than its table map records (the table grew after the event was written); missing tail columns render as explicit `absent` entries instead of failing the file. A row event declaring more columns than the table map remains an error.
- `deny.toml` for `cargo deny check` (license and duplicate-crate policy); both the RustSec advisory scan and `cargo deny check` run on a daily schedule in CI.

### Changed

- **Library breaking**: `EventPayload::PartialUpdateRows` gains an `after: Vec<Option<RowImage>>` field.
- **Packaging**: the CLI layer (clap, completions, datetime parsing, anyhow) moved behind a default-on `cli` feature (R37); library consumers can use `default-features = false` to drop it. The binary declares `required-features = ["cli"]`, so `--no-default-features` checks the library alone.
- The hand-rolled loopback HTTP test servers drain the request before responding, fixing a rare macOS RST flake in the download tests.

### Fixed

- The remote download's 1 MiB copy chunk is heap-allocated: as a stack array it overflowed the default 1 MiB main-thread stack on Windows, so every `--url` download aborted the process immediately before any network I/O (Linux and macOS have 8 MiB main stacks and were unaffected).
- The loopback test servers clear the inherited `O_NONBLOCK` flag on accepted sockets (a BSD/macOS behavior) and bound their accept wait, so a client that never connects fails fast with its own stderr instead of hanging the suite.

## 0.3.0 - 2026-11-05

Second batch: compressed transaction support, range filters, statistics, completions, and download/event size limits.

### Added

- **Compressed transaction payloads (code 40, WL#3549)** are now decoded instead of rejected: the compression header is hand-pre-validated before the underlying crate parses it (unknown algorithm bytes, oversized TLV skips and other hostile shapes are clean errors instead of crate panics), decompression always streams (the pre-allocating danger API is never used) and is bounded — a declared uncompressed size above 1 GiB is rejected up front, and decompressed output beyond the declared size plus a 1 MiB slack is rejected (bomb resistance); for `NONE` payloads the limit is the actual payload size plus slack, since the wire declares 0. Inner events are pre-validated like outer events and share table-map state; inner events that would rewrite parser state (nested format description, rotate, nested payload) are rejected. New payload `transaction_payload { compression, uncompressed_size, events }` where `events` are full event objects whose `offset` counts from the start of the decompressed stream.
- Range filters, all applied post-parse and combinable with every other filter: `--start-position` (inclusive) / `--stop-position` (exclusive, mysqlbinlog convention), `--start-datetime` / `--stop-datetime` (inclusive; `YYYY-MM-DD HH:MM:SS` in the system time zone or RFC3339), and `--include-gtid` (exact-match `uuid:gno` or `uuid:tag:gno`, repeatable; UUIDs lowercased, tags validated per MySQL tag rules, GNOs ≥ 1; only the GTID event is kept, not the whole transaction).
- `--stats`: one JSON statistics object (`files`, `events_total`, `bytes_total`, `transactions`, `by_type`, `by_table`, `errors`) over the kept events after all inputs; respects every other filter; `--format` is accepted but ignored.
- `--completions <bash|elvish|fish|powershell|zsh>`: print shell completions and exit before opening any input.
- `--max-download-size <BYTES>` (remote feature, default 4 GiB): a download exceeding the cap is aborted without leaking the URL.
- `--max-event-size <BYTES>` (default 67108864, hard limit 1 GiB, minimum 19): adjusts the per-event cap via the library's `with_max_event_size`.

### Changed

- `--events transaction_payload` is selectable again (it was rejected in 0.2.0 because the event was then rejected at the framing layer).
- A closed stdout (for example when piping into `head`) is treated as a normal end (exit 0) instead of a broken-pipe error.

### Fixed

- Previous-GTIDs intervals with degenerate endpoints (`start = 0` or `end <= start`) are rejected during pre-validation instead of overflowing the set-string renderer.
- Table-map pre-validation now mirrors the crate's `ParseBuf` lenenc semantics for header counts and ENUM/SET variant counts (`0xfb`/`0xff` decode as 0), so non-canonical encodings the crate accepts are no longer bypassed or falsely rejected; TLV length prefixes remain strict.
- A failed `--output` publish no longer leaves the temporary file behind.
- Large uncompressed (`NONE`) transaction payloads (above the old 1 MiB slack) are no longer falsely rejected.
- `--include-gtid` validation tightened: tag length (≤ 32) and charset per MySQL rules; GNO 0 rejected.

## 0.2.0 - 2026-11-05

First batch of review fixes (event classification, CLI reliability and safety, performance, library quality, documentation, and engineering).

### Added

- Event-type classification extended into the library-level `EventType` enum (27 snake_case variants, single source of truth). New typed decoding: `previous_gtids` (`gtid_set`, a mysqlbinlog-style set string), `stop` (empty object), `rows_query` (`sql`), `incident` (`incident_type`, `message`), `intvar` (`var_type`, `value`), and `partial_update_rows` (code 39, independent payload, decoding the full `before` row image; the after JSON diff is intentionally not decoded).
- Tagged GTIDs (code 42, MySQL 8.4+): `payload.gtid` emits the canonical full `uuid:tag:gno`, with a new JSON key `payload.tag` (`null` when untagged).
- Anonymous GTIDs (code 34): `event_type` correctly emits `anonymous_gtid`, `payload.kind` remains `gtid`, and `gtid` is `ANONYMOUS` (matching mysqlbinlog).
- Stable event naming for `rand`, `user_var`, `begin_load_query`, `execute_load_query`, `heartbeat` (including code 41), `ignorable`, `transaction_context`, `view_change`, `xa_prepare`; payloads keep `unknown` (only `raw_len`). MariaDB-specific types (160+) remain `unknown`.
- CLI supports stdin: the file argument `-`.
- `--output` atomic write: a hidden temporary file is created in the target directory (unix mode 0600), then published via link+unlink on completion, never overwriting an existing file; hard errors leave no file behind, and on partial parse failure (exit code 3) the output contains the successfully parsed prefix.
- Layered exit codes: 0 success; 1 hard error; 2 CLI usage error (clap); 3 partial parse failure (lenient mode, listing errors and offsets per file). `--strict` now aborts everything at the first error (exit code 1).
- Library API: `BinlogParser<R: Read>` (`open` / `from_reader` / `with_max_event_size`), `pub const MAX_EVENT_SIZE` (64 MiB), `EventType::as_str` / `from_raw`; all event-model types implement `Serialize` + `Deserialize` (`CellValue::Bytes` is a lowercase hex string; deserialization expects the same form).
- Hostile-input protection (fail-closed): previous-GTIDs header-declared `n_sids` and table-map optional metadata TLVs (including ENUM/SET variant counts) are hand pre-validated before being handed to the underlying crate, rejecting anything beyond the remaining bytes and preventing unbounded `Vec::with_capacity` from aborting the process.
- Documentation: this changelog added; the usage guide gained the full `payload.kind` field tables, real output samples for all three formats, the exit-code table, an install section, a "differences from mysqlbinlog" section, and library usage examples; ROADMAP added.
- Packaging: Cargo.toml gains `description`, `readme`, `keywords`, `categories`, and `[profile.release]` (`lto = "thin"`, `strip = true`).
- CI: clippy and tests for no-default-features, `Swatinem/rust-cache`, a concurrency group, and dependabot (cargo + github-actions, weekly).

### Changed

- **CLI breaking**: `--events` validation moved to argument-parse time (clap value parser); unknown values error immediately and exit with code 2 (the error message lists all valid values); `transaction_payload` is no longer selectable (compressed transactions are rejected at the framing layer; support planned for a later version).
- **Library breaking**: the `Formatter` trait now writes directly to `&mut dyn Write` and returns `Result<bool, FormatterError>` (whether the event produced output); `EventFilter` fields became `HashSet<EventType>` and `HashSet<(String, String)>`; `ParsedEvent.event_type` changed from a string to the `EventType` enum (JSON serialization values unchanged); `BinlogParser` is now generic over `R: Read`.
- `format_description.server_version` is truncated at the first NUL instead of emitting padding characters.
- `--table` must have the form `database.table`, split at the first `.` into non-empty database and table names; row events with unresolved table maps do not match table filters.
- The JSON `event_type` gained new values (`partial_update_rows`, `previous_gtids`, `stop`, `rows_query`, `incident`, `intvar`, `anonymous_gtid`, etc.); `previous_gtids`, required by standard MySQL 5.7+/8.0 binlogs, no longer shows as `unknown`.
- Parser hot-path optimizations: the event buffer is reused across events, `BufReader` capacity 1 MiB, table-driven hex encoding, and table matching without per-event string allocation.

### Fixed

- Tagged GTIDs (code 42) no longer lose the tag or emit the invalid `uuid:gno` form.
- Anonymous GTIDs (code 34) are no longer misreported as `gtid` events.
- Code 39 (partial JSON updates) is no longer mislabeled as `update_rows` in a way that failed the whole file.
- A present-bitmap bit count that disagrees with the column count in a row image now returns an error instead of silently truncating.
- Hostile previous-GTIDs (`n_sids` out of bounds) and table-map metadata TLVs no longer abort the process; they produce parse errors carrying the offset.

## 0.1.0 - 2026-11-04

### Added

- Initial release: an offline MySQL binlog inspection CLI and library, with event-by-event parsing of plaintext binlogs, typed decoding of format description/table map/query/XID/GTID/rotate and row events, JSON Lines/text/CSV output, event and table filters, CRC32 checksum verification, explicit rejection of encrypted files, and HTTP(S) download via the `remote` feature.

[Unreleased]: https://github.com/houseme/binlog-inspect/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/houseme/binlog-inspect/releases/tag/v0.4.0
