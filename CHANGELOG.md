# Changelog

This project follows the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and [Semantic Versioning](https://semver.org/). Entries are written in English; breaking changes are explicitly marked.

## [Unreleased]

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
