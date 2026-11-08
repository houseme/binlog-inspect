# Project Collaboration Conventions

This project provides a Rust 2024 CLI and a reusable library, with top priority on the correctness of binlog event boundaries, table maps, and numeric semantics. Follow the actual capabilities and limitations documented in `DESIGN.md`, and run verification as described in `EXECUTION.md`. Use the current stable toolchain and the repository's `Cargo.lock`; The manifest declares an MSRV of Rust 1.88, which has a dedicated CI check/test job.

- Core does not depend on CLI or network types; parsing uses `EventStreamReader` to maintain the FDE and table maps, and formatters receive only the project's event model.
- Read strictly one event at a time so untrusted events cannot trigger unbounded allocations; never load a whole binlog file into memory.
- Reject encrypted files explicitly; do not implement offline decryption, and do not mistake URL downloads for database-protocol reads.
- Never silently skip truncated data, checksum failures, compressed transactions, or data that cannot be parsed reliably; errors carry the file offset and the CLI exits non-zero.
- Ignored event types must be observable, and filtering must not change the state that parsing depends on. Row images must distinguish unrecorded columns from SQL NULL; never infer encodings or missing metadata out of thin air.
- Tests use synthetic, desensitized fixtures; real binlogs contain business data and must not be copied into tests, commits, or public output. New `unsafe` code is forbidden, and public APIs must be documented.
- Keep documentation in sync with behavior changes. As the final gate, run serially: `cargo fmt --all --check`, `cargo clippy --locked --all-targets --all-features -- -D warnings`, `cargo clippy --locked --all-targets --no-default-features -- -D warnings`, `cargo test --locked --all-features`, and builds with and without the `remote` feature.
