# Fuzzing

Coverage-guided fuzz harnesses over the public parser (ROADMAP R47b). This
directory is a **detached cargo workspace** (the empty `[workspace]` table in
`Cargo.toml`): it is not a member of the root workspace, the crate's stable
quality gates never build it, and the root package's `package.exclude` keeps
it out of the published `.crate`.

## Targets

- **`parse_binlog`** — the priority target. Every input is fed straight to
  `BinlogParser::from_reader(std::io::Cursor::new(data))` and all events are
  iterated, so the whole fail-closed surface runs end to end: magic and
  encrypted-header validation, event framing, CRC32 checksums, the
  hostile-input pre-validation walks (previous-GTIDs counts, table-map
  metadata TLVs, compression-payload headers), row decoding and the jsonb
  conversion.
- **`jsonb_via_row`** — each input is wrapped as the JSON column value of a
  minimal synthetic binlog (magic + checksummed format description + table
  map with one JSON column + one write-rows event), reusing the fixture byte
  layouts of `tests/partial_json.rs`. This focuses the fuzzer on the jsonb
  path: container framing, the 100-container depth cap, opaque member
  rendering, and the decoded-node budget.

Both targets swallow decode results on purpose. The contract under test is
fail-closed: hostile input produces an error carrying the file offset, never
a panic, hang, or unbounded allocation. A finding is a process-level failure:
abort, OOM, or timeout.

## Known findings

- `jsonb_via_row`: the first local round (seconds in) crashed inside the
  `mysql_common` dependency on a hostile opaque jsonb member —
  `binlog/decimal/mod.rs:424: attempt to subtract with overflow` in
  `decimal_bin_size` when a NEWDECIMAL opaque declares `scale > precision`
  (cargo-fuzz builds with overflow checks). The harness reaches that decoder
  through `jsonb_to_serde`'s opaque rendering of hostile NEWDECIMAL members;
  pre-validation does not yet cover the decimal metadata bytes. Expect the
  scheduled CI job to keep reporting this crash until it is fixed; the job is
  non-gating on purpose.

## Prerequisites

libFuzzer's coverage instrumentation requires a nightly toolchain, so these
harnesses are outside the stable gates:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

## Running

From this directory:

```sh
cargo fuzz run parse_binlog  -- -rss_limit_mb=2048 -max_total_time=300
cargo fuzz run jsonb_via_row -- -rss_limit_mb=2048 -max_total_time=300
cargo fuzz build   # build every target without running it
```

`cargo fuzz run` resumes the per-target corpus in `corpus/<target>/`; the
committed seeds there are built from the synthetic fixture layouts of
`tests/partial_json.rs` (a minimal checksummed binlog, a truncated frame, a
corrupted checksum for `parse_binlog`; nested/aliased/deep/hostile jsonb
shapes for `jsonb_via_row`). On a crash libFuzzer writes the offending input
to `crash-<sha1>`; minimize with `cargo fuzz tmin` / `cargo fuzz cmin`.

## libFuzzer options

- `-rss_limit_mb=2048` — malloc/RSS limit for the harness. This matters most
  for the jsonb path: the historical R48 amplification (first reproduced by
  exactly this harness class) decoded a 221-byte aliased jsonb into
  8,388,607 nodes, and ~331 wire bytes demanded ~275 GB before the depth cap
  ever fired — a fail-closed violation. The decoded-node budget (1,000,000
  nodes) now bounds that, but keep the RSS limit so a regression resurfaces
  as a libFuzzer OOM report that still names the input, instead of an
  allocator abort that loses the repro.
- `-max_total_time=<seconds>` — prefer time-bounded rounds for local and CI
  runs (the scheduled, non-gating CI job in
  `.github/workflows/fuzz.yml` uses 60 s per target). An unbounded session
  belongs on a dedicated machine.

## Plain cargo build

The harnesses are only ever *fuzzed* through `cargo fuzz` (which drives a
nightly toolchain and passes the libFuzzer coverage-instrumentation flags).
A plain `cargo build` inside `fuzz/` on a current stable toolchain compiles
fine — `libfuzzer-sys` builds as an ordinary dependency — but the resulting
binaries carry no coverage instrumentation, so they are useless for actual
fuzzing; treat the stable build as a manifest/type check only.
`cargo metadata --manifest-path fuzz/Cargo.toml --no-deps` validates the
manifest without building anything. The root workspace never builds this
directory, and the crate's stable quality gates are unaffected by it.
