# binlog-inspect

[![Crates.io](https://img.shields.io/crates/v/binlog-inspect.svg)](https://crates.io/crates/binlog-inspect)
[![Documentation](https://docs.rs/binlog-inspect/badge.svg)](https://docs.rs/binlog-inspect)
[![CI](https://github.com/houseme/binlog-inspect/actions/workflows/ci.yml/badge.svg)](https://github.com/houseme/binlog-inspect/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-stable-orange.svg)](#rust-toolchain-compatibility)

English | [简体中文](README.zh-CN.md)

`binlog-inspect` is a Rust command-line tool and library for inspecting plaintext MySQL binary logs. It reads one event at a time as a stream, decodes events into a typed model decoupled from the underlying library (including tagged/anonymous GTIDs, `previous_gtids`, table maps and row images), and emits JSON Lines, text or CSV.

## Features

- Read one or more local binlogs, or standard input with `-`; download HTTP(S) files with the optional `remote` feature.
- Full event-type classification (27 types): typed decoding of format_description, table_map, query, xid, gtid (tagged, `uuid:tag:gno`), anonymous_gtid, previous_gtids, rotate, stop, rows_query, incident, intvar, partial_update_rows (before images) and write/update/delete row events; named but undecoded events retain their type and `raw_len`.
- Row images preserve column positions and distinguish absent columns from SQL NULL, with MySQL column type and signedness for numerics.
- Filter by event type, `database.table`, byte-offset ranges (`--start-position`/`--stop-position`), timestamp ranges (`--start-datetime`/`--stop-datetime`) and exact GTIDs (`--include-gtid`), with before/after row images.
- `--stats` prints one JSON summary (files, events, bytes, transactions, per-type and per-table counts, errors); `--completions` generates shell completion scripts.
- A 64 MiB per-event cap keeps memory bounded; hostile event headers and table-map metadata are pre-validated before decoding; supported CRC32 checksums are verified.
- `--output` is written atomically: mode 0600 on unix, and existing files are never overwritten.
- Layered exit codes: 0 success, 1 hard error, 2 usage error, 3 partial parse failure.

## Install and quick start

It is not published on crates.io yet; build or install from source:

```sh
cargo build --locked --release
# or install into ~/.cargo/bin
cargo install --path .
```

Run these commands from the project root; `--locked` uses the dependencies in `Cargo.lock`:

```sh
./target/release/binlog-inspect path/to/mysql-bin.000001
cat path/to/mysql-bin.000001 | ./target/release/binlog-inspect - --events xid
./target/release/binlog-inspect path/to/mysql-bin.000001 --events query,xid --format text
./target/release/binlog-inspect path/to/mysql-bin.000001 --table app.orders --format csv --output rows.csv
./target/release/binlog-inspect path/to/mysql-bin.000001 --stats
```

JSON Lines is written to standard output by default. See [the usage guide](docs/USAGE.en.md#exit-codes) for exit-code semantics; on a partial parse failure the output contains the successfully parsed prefix, so check the exit status. `--output` creates a new file and never overwrites an existing one. Output can contain business data and should be stored in a trusted location.

Enable the optional feature for remote downloads:

```sh
cargo run --locked --features remote -- --url https://example.com/mysql-bin.000001
```

## Rust toolchain compatibility

Requires a current Rust stable toolchain. The project uses the Rust 2024 edition; a minimum supported version has not been verified, so build with the latest stable toolchain.

## Limitations

- Only plaintext files are supported. Encrypted binlogs are rejected; HTTP download neither decrypts them nor implements the MySQL replication protocol.
- Compressed transactions (code 40) are decoded safely: the compression header is pre-validated, decompression is streamed and bounded (declared size + slack; >1 GiB declarations rejected), and inner events share the parser's table-map state.
- `partial_update_rows` decodes the before image and applies the JSON-diff after image against it; a diff that cannot be applied is preserved as a loss-marking `partial_json` value with its diffs and the reason.
- Rotate events are reported but not followed; list the next file yourself.
- MariaDB-specific event types (160+) remain `unknown`; named types such as `rand` and `user_var` keep only the type and `raw_len`.
- A single event may not exceed 64 MiB by default; the CLI can raise this with `--max-event-size` (up to the 1 GiB inspection limit), and library callers with `with_max_event_size`.
- Column names and numeric signedness depend on binlog metadata; bytes are encoded as hexadecimal without guessing a character set.
- Compatibility with every server version, event and column type has not been verified, and a successful exit does not mean every event was understood.

## Documentation and development

- [English usage guide](docs/USAGE.en.md) | [中文使用文档](docs/USAGE.zh-CN.md)
- [Design](DESIGN.md) (Chinese); [build and validation notes](EXECUTION.md) (Chinese)
- [ROADMAP](ROADMAP.md) (Chinese); [CHANGELOG](CHANGELOG.md)

```sh
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo test --locked --all-features
cargo build --locked --no-default-features
cargo build --locked --all-features
```
