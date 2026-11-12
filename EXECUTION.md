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

Multiple local files, multiple URLs, `-` (stdin), and repeated `--table` options are supported. Output goes to stdout by default; `--output` writes atomically and never overwrites an existing file. `--events` takes a comma-separated list; see `--help` or the [usage guide](docs/USAGE.en.md) for all values. Position, datetime and exact-GTID filters, `--stats`, `--completions`, `--max-event-size` and `--max-download-size` are documented in the usage guide. Exit codes are layered: 0 success, 1 hard error, 2 usage error, 3 partial parse failure; when errors occur the output may be incomplete, so check the exit status. See `DESIGN.md` for the data format, errors, and unsupported scenarios.

## Quality Gates

Run the following sequentially to avoid parallel builds with different features overwriting the CLI binary that the tests use:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --all-targets --no-default-features -- -D warnings
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

## Local Sample Validation Record (2026-11-05, v0.3.0 / re-validated v0.4.0)

Re-validation of the same user-provided MySQL 8.0.30-format sample (moved out of the repository tree; accessed read-only in place) with the 0.3.0 build, then re-confirmed unchanged on the 0.4.0 build: strict parse exit 0, 620,173 events, stderr empty (the new log_pos advisory stays silent on a genuine file), by_type identical. Only aggregate statistics were captured; no business data was printed or stored.

Strict parsing (`--strict > /dev/null`) read to EOF and exited 0 in about 1.3 s for the 79 MB file. `--stats` reported 620,173 events, `bytes_total` 79,685,521 (file size minus the 4-byte magic), `errors: 0`, and 116 distinct `database.table` entries. An independent 19-byte-header traversal counted exactly the same total (620,173) with the same per-code distribution, and every code maps onto the reported `by_type` counts: query(2)=124,034, rotate(4)=1, format_description(15)=1, xid(16)=124,034, table_map(19)=124,034, write_rows(30)=31,340, update_rows(31)=86,415, delete_rows(32)=6,279, gtid(33)=124,034, previous_gtids(35)=1. `previous_gtids` is now classified (it counted as `unknown` in the 2026-11-04 record); no other type appeared. The MariaDB build of `mysqlbinlog --verify-binlog-checksum` again completed and exited 0.

Scope caveats carried over: the sample contains no compressed transactions, tagged GTIDs, partial JSON updates, anonymous GTIDs or minimal row images, so the 0.3.0 features are exercised only by synthetic tests; value-level comparison against reference tooling remains limited to the 2026-11-04 record. Count agreement is not value correctness.

## Source Review Verification Record (2026-11-07, unreleased)

The W5 changes passed the stable-toolchain gates with locked dependencies. The all-features suite passed 155 tests, including two documentation tests. Default features, library-only, and remote-without-defaults test configurations also passed. Clippy passed for default, all-features and library-only targets, all three build configurations succeeded, and rustdoc completed with warnings denied. The two changed GitHub workflows passed actionlint, and the test matrix expands to 12 distinct OS/feature combinations.

New regression coverage includes visitor/collector equivalence for NONE and ZSTD payloads, shared table-map state, checksum ordering, callback cancellation/errors/panics, a 100,000-event visitor, row-iterator progress, complete required column metadata, JSON depth boundaries, and completion-script broken pipes. The deterministic wire corpus uses four synthetic families with 24 fixed-seed cases each, short reads and bounded mutations. It reproduced the zero-progress row loop and the unsupported metadata-layout panic that this batch fixes. Legacy JSON fixtures were corrected to include the required type-specific metadata.

All new fixtures are synthetic. Performance microbenchmarks showed baseline drift, so this record claims no stable throughput improvement. Live-server compatibility and continuous coverage-guided fuzzing remain separate validation work.

## Performance Acceptance Record (R42)

The harness lives in `tests/perf_acceptance.rs`: four deterministic, synthetic workloads timed end to end through the public library API (no RNG and no real data; all output is discarded to `std::io::sink()`). Every test in the harness is `#[ignore]`d, so the regular suite never runs it; the acceptance run is:

```sh
cargo test --locked --release --test perf_acceptance -- --ignored --nocapture
```

Each metric performs 3 warmup runs and then the median of 11 timed runs (`std::time::Instant`), printed with `--nocapture`. The harness asserts structural invariants only — fixture shape, consumed event counts, every partial-JSON diff applied — and nothing about absolute speed, so it cannot fail on a slow or busy machine. The four metrics cover the framing/decoding loop over a ~10 MB / 20k-event transactional binlog (`framing_loop`), the same file through `JsonLinesFormatter` (`jsonl_hot_loop`, the R42 regression metric), 1,000 rows x 8 JSON columns x 4 diffs through the partial-JSON path (`partial_json_diffs`, pinning the `apply_pair` merge), and 5,000 row changes through `CsvFormatter` (`csv_output`). Adding a metric later is one fixture builder, one workload function, and one entry in the harness's metric registry.

How to record: measure in one sitting on one machine, immediately after checking out the commit under review, and append a new entry below. Each entry lists the date, the commit SHA, `rustc -vV`, the CPU model and core count, the OS, and a table of metric / baseline / current / delta where the recorded number is the printed median wall-clock time of the release build (profile `lto = "thin"`, `strip = true`). A change is accepted when every metric's delta stays within ±5% of the previous entry's baseline; byte-identity of the JSON output is covered by the regular test suite, not here. Raw per-run timings stay out of version control — only the medians in the entries are tracked. Run-to-run noise of a few percent on an otherwise idle machine is normal; if an entry's min/max spread or a delta comparison straddles the 5% rule, re-run in a quieter window instead of weakening the rule. The harness is non-gating: it documents behavior, it does not pass or fail CI.

### 2026-11-13 (initial baseline)

- Commit: 1c8b8d0 (`test(perf): deterministic performance acceptance harness (R42)`); this entry is its own baseline, so current equals baseline and no delta applies.
- Toolchain: rustc 1.99.1 (58cf8f9c3 2026-10-13), host aarch64-apple-darwin, LLVM 23.1.1; cargo 1.99.1.
- CPU: Apple M5 Max, 18 logical cores.
- OS: macOS 27.2 (Build 26B123), arm64.

| metric | baseline (ms) | current (ms) | delta |
|---|---|---|---|
| framing_loop | 377.155 | 377.155 | — (initial) |
| jsonl_hot_loop | 500.501 | 500.501 | — (initial) |
| partial_json_diffs | 12.247 | 12.247 | — (initial) |
| csv_output | 7.981 | 7.981 | — (initial) |

Sanity invariants verified in the same run: 19,999 events consumed by both framing and JSONL metrics, 32,000 diffs applied across 8,000 JSON cells, and 5,000 CSV records from 5,000 row changes.
