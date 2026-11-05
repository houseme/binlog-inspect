# Execution and Verification

## Prerequisites and Build

Install the current Rust stable toolchain and build with locked dependencies:

```sh
cargo build --locked --no-default-features
cargo build --locked --all-features
```

## Usage

```sh
cargo run --locked -- path/to/mysql-bin.000001 --format jsonl
cargo run --locked -- path/to/mysql-bin.000001 --events query,xid --format text
cat path/to/mysql-bin.000001 | cargo run --locked -- - --events xid
cargo run --locked -- path/to/mysql-bin.000001 --table app.orders --format csv --output rows.csv
cargo run --locked --features remote -- --url https://example.com/mysql-bin.000001
```

Multiple local files, multiple URLs, `-` (stdin), and repeated `--table` options are supported. Output goes to stdout by default; `--output` writes atomically and never overwrites an existing file. `--events` takes a comma-separated list; see `--help` or the [usage guide](docs/USAGE.en.md) for all values; `transaction_payload` is not selectable. Exit codes are layered: 0 success, 1 hard error, 2 usage error, 3 partial parse failure; when errors occur the output may be incomplete, so check the exit status. See `DESIGN.md` for the data format, errors, and unsupported scenarios.

## Quality Gates

Run the following sequentially to avoid parallel builds with different features overwriting the CLI binary that the tests use:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo test --locked --all-features
cargo build --locked --no-default-features
cargo build --locked --all-features
```

The remote integration tests use a loopback HTTP server and never access the external network or MySQL. If your sandbox forbids listening on loopback ports, run the full test suite in an environment that allows it.

When validating against real files, avoid printing business data to a terminal or writing it into version control:

```sh
cargo run --locked --release -- /path/to/binlog --strict > /dev/null
mysqlbinlog --verify-binlog-checksum /path/to/binlog > /dev/null
```

Compare event counts and sampled values as needed, and record separately the reference tool, its version, the comparison scope, and any fields that were not verified. Real data must not become a test fixture. Never disable binlog encryption or change production server settings to make tests pass.

## Local Sample Validation Record (2026-11-04)

The following record was produced before the 0.2.0 event reclassification, when types such as `previous_gtids` were not yet decoded into typed variants and were counted as `unknown`, and the output format used for the numeric comparison differed from the current version; the counts in the conclusions are only valid for the build of that time.

Strict parsing of the user-provided plaintext MySQL 8.0.30-format sample read to EOF and exited with status 0. An independent event-header scan agreed with the parser on event types and totals — 620,173 events in total; there were no unresolved table maps. The MariaDB build of `mysqlbinlog --verify-binlog-checksum` completed and exited 0.

The row-value comparison covered only the 445 comparable integers among the first 53 row images: 443 matched, and the remaining two belonged to the before/after images of the same unsigned INT column — identical in the low 32 bits but displayed with different signs by this tool and the MariaDB tool. MariaDB's `-vv` output exited early on this sample and did not cover the whole file; the Oracle MySQL tooling or a real table schema is needed for further verification. Values of other event types and multi-row events have not been adequately compared. This record contains no business data, and agreement in event counts must not be read as full value correctness.
