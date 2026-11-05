# Changelog

This project follows the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and [Semantic Versioning](https://semver.org/). Entries are written in English; breaking changes are explicitly marked.

## [Unreleased]

## [0.3.0] - 2026-11-05

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

## [0.2.0] - 2026-11-05

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

## [0.1.0] - 2026-11-04

### Added

- Initial release: an offline MySQL binlog inspection CLI and library, with event-by-event parsing of plaintext binlogs, typed decoding of format description/table map/query/XID/GTID/rotate and row events, JSON Lines/text/CSV output, event and table filters, CRC32 checksum verification, explicit rejection of encrypted files, and HTTP(S) download via the `remote` feature.

<!-- Version comparison links to be added once the repository URL is settled (ROADMAP R32). -->
