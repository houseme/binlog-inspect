// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Coverage-guided fuzzing of the whole parse pipeline (the priority target).
//!
//! Every input is a candidate binlog fed straight into the public parser:
//! magic and encrypted-header validation, event framing, CRC32 checksums, the
//! hostile-input pre-validation walks (previous-GTIDs counts, table-map
//! metadata TLVs, compression-payload headers), row decoding and the jsonb
//! conversion all run end to end. The contract under test is fail-closed:
//! hostile input must return an error carrying the file offset — never a
//! panic, hang, or unbounded allocation. Decoding results are swallowed on
//! purpose; process-level failures (abort, OOM, timeout) are the findings.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut parser) =
        binlog_inspect::parser::BinlogParser::from_reader(std::io::Cursor::new(data))
    {
        for event in parser.events() {
            // Errors and decoded events are both expected on hostile input;
            // only crashes and resource exhaustion are findings.
            let _ = event;
        }
    }
});
