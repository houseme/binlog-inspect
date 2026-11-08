// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use binlog_inspect::{
    event::{EventPayload, EventType, ParsedEvent},
    filter::{EventFilter, RangeFilter},
    formatter::{CsvFormatter, Formatter, JsonLinesFormatter, TextFormatter},
    parser::{BinlogParser, DEFAULT_INNER_EVENT_LIMIT, MAX_EVENT_SIZE},
};
use clap::{CommandFactory, Parser, ValueEnum};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(feature = "remote")]
mod remote;
/// Result of processing one input.
///
/// `Partial` records an input that stopped early on a parse error after
/// emitting the events before it; hard errors abort processing instead.
enum Outcome {
    Complete,
    Partial { file: String, error: String },
}
/// Upper bound for `--max-download-size` (4 GiB, R29).
#[cfg(feature = "remote")]
const MAX_DOWNLOAD_SIZE: u64 = 4 * 1024 * 1024 * 1024;
/// Hard inspection limit for `--max-event-size` (1 GiB, R30).
const MAX_EVENT_SIZE_LIMIT: u64 = 1_073_741_824;
#[derive(Parser)]
#[command(version, about = "Inspect plaintext MySQL binary logs")]
struct Cli {
    /// Local binlog files; "-" reads standard input.
    files: Vec<PathBuf>,
    /// Output format (ignored with --stats, which always emits JSON).
    #[arg(short, long, value_enum, default_value_t = Format::Jsonl)]
    format: Format,
    /// Write to a new file instead of stdout; existing files are not overwritten.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Event types to include, comma separated; may be repeated. Values:
    /// format_description, table_map, write_rows, update_rows, delete_rows,
    /// partial_update_rows, query, xid, gtid, anonymous_gtid, previous_gtids,
    /// rotate, stop, rows_query, incident, intvar, rand, user_var,
    /// begin_load_query, execute_load_query, heartbeat, ignorable,
    /// transaction_context, view_change, xa_prepare, transaction_payload,
    /// unknown
    #[arg(long, value_delimiter = ',', value_parser = parse_event_type)]
    events: Vec<EventType>,
    /// Filter to database.table; may be repeated.
    #[arg(long = "table", value_name = "database.table", value_parser = parse_table)]
    tables: Vec<(String, String)>,
    /// Keep events starting at byte offset OFFSET (inclusive).
    #[arg(long, value_name = "OFFSET")]
    start_position: Option<u64>,
    /// Keep events starting before byte offset OFFSET (exclusive, mysqlbinlog
    /// convention).
    #[arg(long, value_name = "OFFSET")]
    stop_position: Option<u64>,
    /// Keep events with timestamp at or after DATETIME; inclusive. DATETIME is
    /// "YYYY-MM-DD HH:MM:SS" in the system time zone or an RFC3339 timestamp.
    #[arg(long, value_name = "DATETIME", value_parser = parse_datetime)]
    start_datetime: Option<i64>,
    /// Keep events with timestamp at or before DATETIME; inclusive. DATETIME is
    /// "YYYY-MM-DD HH:MM:SS" in the system time zone or an RFC3339 timestamp.
    #[arg(long, value_name = "DATETIME", value_parser = parse_datetime)]
    stop_datetime: Option<i64>,
    /// Keep only GTID payload events whose GTID is exactly GTID
    /// (uuid:gno or uuid:tag:gno); may be repeated; no interval or set algebra.
    #[arg(long = "include-gtid", value_name = "GTID", value_parser = parse_gtid)]
    include_gtids: Vec<String>,
    /// Print one JSON statistics object instead of event lines: counts over
    /// the kept events only, after all inputs. --format is ignored.
    #[arg(long)]
    stats: bool,
    /// Print shell completions for SHELL and exit; all other options are
    /// ignored and no input is opened.
    #[arg(long, value_name = "SHELL", value_enum)]
    completions: Option<clap_complete::Shell>,
    /// Reject single events larger than BYTES bytes as "invalid or oversized"
    /// (default 67108864; BYTES may not exceed the 1 GiB inspection limit).
    #[arg(
        long,
        value_name = "BYTES",
        default_value_t = MAX_EVENT_SIZE,
        value_parser = parse_max_event_size
    )]
    max_event_size: u32,
    /// Stop an input with an error when one transaction payload contains more
    /// than COUNT inner events (default 250000); raising the limit trades
    /// memory use for payload depth.
    #[arg(
        long,
        value_name = "COUNT",
        default_value_t = NonZeroUsize::new(DEFAULT_INNER_EVENT_LIMIT).expect(
            "DEFAULT_INNER_EVENT_LIMIT is nonzero",
        ),
        value_parser = parse_inner_event_limit
    )]
    max_inner_events: NonZeroUsize,
    /// Abort on the first error in any input; without it, an error stops the
    /// current file, remaining files are still processed, and the exit code is
    /// non-zero (3).
    #[arg(long)]
    strict: bool,
    /// HTTP(S) URL to a binlog file, may be repeated.
    #[cfg(feature = "remote")]
    #[arg(long = "url", value_name = "URL")]
    urls: Vec<String>,
    /// Stop a --url download once it would exceed BYTES bytes (default 4294967296).
    #[cfg(feature = "remote")]
    #[arg(long, value_name = "BYTES", default_value_t = MAX_DOWNLOAD_SIZE)]
    max_download_size: u64,
}
#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Jsonl,
    Text,
    Csv,
}
/// What happens to each event that passes the filters.
enum Sink {
    /// Format and write event lines.
    Events(Box<dyn Formatter>),
    /// Accumulate statistics; the JSON object is written after all inputs.
    Stats(Stats),
}
/// Accumulated statistics for `--stats` (R27).
///
/// Counting happens while streaming over the events that pass all filters, so
/// the numbers describe the kept events only.
#[derive(Default, serde::Serialize)]
struct Stats {
    files: u64,
    events_total: u64,
    bytes_total: u64,
    transactions: u64,
    by_type: BTreeMap<&'static str, u64>,
    by_table: BTreeMap<String, u64>,
    errors: u64,
    /// Scratch key reused across `record` calls so the hot path only
    /// allocates on the first sighting of a table (R42); excluded from the
    /// JSON output.
    #[serde(skip)]
    table_key: String,
}
impl Stats {
    /// Records one kept event.
    fn record(&mut self, event: &ParsedEvent) {
        self.events_total += 1;
        self.bytes_total += u64::from(event.event_size);
        *self.by_type.entry(event.event_type.as_str()).or_default() += 1;
        match &event.payload {
            // Anonymous GTID events also carry a Gtid payload, so they count
            // as transactions.
            EventPayload::Gtid { .. } => self.transactions += 1,
            EventPayload::Rows {
                database,
                table,
                changes,
                ..
            } => self.count_row_changes(database, table, changes.len() as u64),
            EventPayload::PartialUpdateRows {
                database,
                table,
                before,
                ..
            } => self.count_row_changes(database, table, before.len() as u64),
            _ => {}
        }
    }
    /// Adds `n` row changes to `by_table` without a per-event allocation:
    /// the lookup borrows the scratch key, the clone happens only on the
    /// first insertion for that table.
    fn count_row_changes(&mut self, database: &str, table: &str, n: u64) {
        self.table_key.clear();
        self.table_key.push_str(database);
        self.table_key.push('.');
        self.table_key.push_str(table);
        match self.by_table.get_mut(self.table_key.as_str()) {
            Some(count) => *count += n,
            None => {
                self.by_table.insert(self.table_key.clone(), n);
            }
        }
    }
}
/// Parses one `--events` value against the canonical snake_case names.
///
/// Matching uses `EventType::as_str` so the accepted spellings stay identical
/// to the JSON `event_type` strings, independently of clap's derived value
/// naming.
fn parse_event_type(value: &str) -> Result<EventType, String> {
    let variants = EventType::value_variants();
    match variants
        .iter()
        .copied()
        .find(|event| event.as_str() == value)
    {
        Some(event) => Ok(event),
        None => Err(format!(
            "unknown event type; valid values: {}",
            variants
                .iter()
                .map(|event| event.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}
/// Parses one `--table` value into `(database, table)` at the first `.`.
fn parse_table(value: &str) -> Result<(String, String), String> {
    let invalid = || "invalid --table value: expected database.table".to_owned();
    let Some((database, table)) = value.split_once('.') else {
        return Err(invalid());
    };
    if database.is_empty() || table.is_empty() {
        return Err(invalid());
    }
    Ok((database.to_owned(), table.to_owned()))
}
/// Parses one `--start-datetime`/`--stop-datetime` value into Unix seconds.
///
/// Two shapes are accepted: an RFC3339 timestamp with an explicit offset or
/// `Z` (`2024-01-01T00:00:00Z`), and a local wall-clock datetime
/// (`2024-01-01 00:00:00`) interpreted in the system time zone. Date-only
/// strings are rejected so that a missing time never silently means midnight.
/// Invalid values are clap usage errors (exit code 2).
fn parse_datetime(value: &str) -> Result<i64, String> {
    if let Ok(timestamp) = value.parse::<jiff::Timestamp>() {
        return Ok(timestamp.as_second());
    }
    let invalid = || {
        format!(
            "invalid datetime '{value}': expected \"YYYY-MM-DD HH:MM:SS\" in the system time zone or an RFC3339 timestamp"
        )
    };
    if !(value.contains('T') || value.contains('t') || value.contains(' ')) {
        return Err(invalid());
    }
    let datetime = value
        .parse::<jiff::civil::DateTime>()
        .map_err(|_| invalid())?;
    let zoned = datetime
        .to_zoned(jiff::tz::TimeZone::system())
        .map_err(|_| invalid())?;
    Ok(zoned.timestamp().as_second())
}
/// Parses one `--include-gtid` value: exact `uuid:gno` or `uuid:tag:gno`.
///
/// The UUID is normalized to lowercase because that is how event output
/// renders it; the tag is case-sensitive and must satisfy the MySQL tag
/// rules (1-32 characters, starting with a letter or underscore). GNOs start
/// at one. The allow list matches whole strings only; no interval or set
/// algebra.
fn parse_gtid(value: &str) -> Result<String, String> {
    let invalid =
        || format!("invalid GTID '{value}': expected uuid:gno or uuid:tag:gno (exact match only)");
    let parts: Vec<&str> = value.split(':').collect();
    let (uuid, tag, gno) = match parts.as_slice() {
        [uuid, gno] => (*uuid, None, *gno),
        [uuid, tag, gno] => (*uuid, Some(*tag), *gno),
        _ => return Err(invalid()),
    };
    validate_gtid_uuid(uuid).map_err(|_| invalid())?;
    if let Some(tag) = tag {
        let starts_ok = tag.starts_with(|c: char| c.is_ascii_lowercase() || c == '_');
        let rest_ok = tag
            .chars()
            .skip(1)
            .all(|c| c.is_ascii_alphanumeric() || c == '_');
        if tag.len() > 32 || !starts_ok || !rest_ok {
            return Err(invalid());
        }
    }
    // MySQL GNOs start at one; zero cannot match a real transaction.
    let gno = gno.parse::<u64>().map_err(|_| invalid())?;
    if gno == 0 {
        return Err(invalid());
    }
    Ok(match tag {
        Some(tag) => format!("{}:{tag}:{gno}", uuid.to_ascii_lowercase()),
        None => format!("{}:{gno}", uuid.to_ascii_lowercase()),
    })
}
/// Validates the hyphenated 8-4-4-4-12 hexadecimal UUID of a GTID.
fn validate_gtid_uuid(uuid: &str) -> Result<(), ()> {
    if uuid.len() != 36 {
        return Err(());
    }
    for (index, byte) in uuid.bytes().enumerate() {
        let is_hyphen = index == 8 || index == 13 || index == 18 || index == 23;
        if is_hyphen {
            if byte != b'-' {
                return Err(());
            }
        } else if !byte.is_ascii_hexdigit() {
            return Err(());
        }
    }
    Ok(())
}
/// Parses one `--max-event-size` value in bytes.
///
/// Values above the 1 GiB inspection limit and below the 19-byte event
/// header are rejected at parse time (exit code 2); the resulting number
/// always fits `u32`.
fn parse_max_event_size(value: &str) -> Result<u32, String> {
    let bytes: u64 = value.parse().map_err(|_| {
        format!("invalid --max-event-size value '{value}': expected a number of bytes")
    })?;
    if bytes > MAX_EVENT_SIZE_LIMIT {
        return Err(format!(
            "--max-event-size {bytes} exceeds the 1 GiB inspection limit"
        ));
    }
    if bytes < 19 {
        return Err(format!(
            "--max-event-size {bytes} is smaller than the 19-byte event header"
        ));
    }
    Ok(u32::try_from(bytes).expect("bounded by the 1 GiB inspection limit"))
}
/// Parses one `--max-inner-events` value.
///
/// The bound exists to cap memory, so it cannot be disabled: zero is
/// rejected at parse time (exit code 2), mirroring `parse_max_event_size`.
fn parse_inner_event_limit(value: &str) -> Result<NonZeroUsize, String> {
    let count: usize = value.parse().map_err(|_| {
        format!("invalid --max-inner-events value '{value}': expected a number of events")
    })?;
    NonZeroUsize::new(count).ok_or_else(|| {
        format!(
            "--max-inner-events {count} must be at least one event; the limit cannot be disabled"
        )
    })
}
/// Processes one input; a parse error either aborts (strict) or yields `Partial`.
fn process<R: Read>(
    name: &str,
    parser: &mut BinlogParser<R>,
    filter: &EventFilter,
    sink: &mut Sink,
    out: &mut dyn Write,
    strict: bool,
) -> Result<Outcome> {
    // Failures are collected instead of returned from inside the loop so the
    // iterator borrow ends before the advisory warnings are drained.
    let mut failure: Option<(bool, binlog_inspect::parser::ParserError)> = None;
    for result in parser.events() {
        match result {
            Ok(event) => {
                if filter.keep(&event) {
                    match sink {
                        Sink::Events(formatter) => {
                            formatter.format(&event, out)?;
                        }
                        Sink::Stats(stats) => stats.record(&event),
                    }
                }
            }
            Err(err) => {
                failure = Some((strict, err));
                break;
            }
        }
    }
    for warning in parser.take_warnings() {
        advise(&format!("warning: {warning}"));
    }
    match failure {
        Some((true, err)) => Err(err).with_context(|| format!("cannot fully parse {name}")),
        Some((false, err)) => Ok(Outcome::Partial {
            file: name.to_owned(),
            error: err.to_string(),
        }),
        None => Ok(Outcome::Complete),
    }
}
/// Runs every input and flushes the output writer.
///
/// `written` is the path [`create_output`] returned: a temporary file to be
/// published later on unix, or the target itself on other platforms. In stats
/// mode the JSON object is written to the same destination after all inputs.
fn run_inputs(
    cli: &Cli,
    filter: &EventFilter,
    sink: &mut Sink,
    written: Option<&Path>,
) -> Result<Vec<Outcome>> {
    let mut out: Box<dyn Write> = match written {
        Some(path) => Box::new(io::BufWriter::new(
            std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .with_context(|| format!("cannot reopen output file {}", path.display()))?,
        )),
        None => Box::new(io::BufWriter::new(io::stdout())),
    };
    if let Sink::Events(formatter) = sink
        && let Some(header) = formatter.header()
    {
        writeln!(out, "{header}")?;
    }
    let mut outcomes = Vec::new();
    for file in &cli.files {
        let outcome = if file.as_os_str() == "-" {
            let stdin = io::stdin();
            let mut parser = BinlogParser::from_reader(stdin.lock())?
                .with_max_event_size(cli.max_event_size)
                .with_inner_event_limit(cli.max_inner_events);
            process("<stdin>", &mut parser, filter, sink, &mut out, cli.strict)?
        } else {
            let mut parser = BinlogParser::open(file)
                .with_context(|| format!("cannot inspect {}", file.display()))?
                .with_max_event_size(cli.max_event_size)
                .with_inner_event_limit(cli.max_inner_events);
            process(
                &file.display().to_string(),
                &mut parser,
                filter,
                sink,
                &mut out,
                cli.strict,
            )?
        };
        outcomes.push(outcome);
    }
    #[cfg(feature = "remote")]
    for url in &cli.urls {
        // Never render the URL in errors: query parameters can carry credentials.
        let download = remote::download(url, cli.max_download_size)?;
        let path: &Path = download.as_ref();
        let mut parser = BinlogParser::open(path)
            .context("cannot inspect downloaded binlog")?
            .with_max_event_size(cli.max_event_size)
            .with_inner_event_limit(cli.max_inner_events);
        outcomes.push(process(
            "downloaded binlog",
            &mut parser,
            filter,
            sink,
            &mut out,
            cli.strict,
        )?);
    }
    if let Sink::Stats(stats) = sink {
        stats.files = outcomes.len() as u64;
        stats.errors = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Outcome::Partial { .. }))
            .count() as u64;
        // The JSON is built in memory first so that a closed stdout surfaces
        // as a plain io error (broken pipe is treated as a normal exit).
        let mut json = Vec::new();
        serde_json::to_writer(&mut json, stats)?;
        out.write_all(&json)?;
        writeln!(out)?;
    }
    out.flush()?;
    Ok(outcomes)
}
/// Creates the file the output is written to and returns its path.
///
/// On unix this is a hidden 0600 temporary file in the target's directory;
/// [`publish_output`] links it into place after all data is written, and
/// `link` fails with AlreadyExists when the target exists, so an existing
/// file — including a hard link or symlink pointing at an input — is never
/// replaced, which a rename would silently do. Other platforms create the
/// target itself with create_new, which is the never-overwrite guarantee
/// there; nothing is renamed afterwards.
fn create_output(target: &Path) -> Result<PathBuf> {
    if target.exists() {
        bail!(
            "cannot create output {} (existing files are not overwritten)",
            target.display()
        );
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
        let parent = target.parent().unwrap_or_else(|| Path::new("."));
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let name = target.file_name().map_or_else(
            || "binlog-inspect-out".to_owned(),
            |name| name.to_string_lossy().into_owned(),
        );
        let written = parent.join(format!(".{name}.tmp-{}-{nanos}", std::process::id()));
        options.open(&written).with_context(|| {
            format!(
                "cannot create output {} (temporary file {} failed)",
                target.display(),
                written.display()
            )
        })?;
        Ok(written)
    }
    #[cfg(not(unix))]
    {
        options
            .open(target)
            .with_context(|| format!("cannot create output {}", target.display()))?;
        Ok(target.to_path_buf())
    }
}
/// Publishes the fully written file to its target.
///
/// Unix-only work: `hard_link` + `remove_file`, because `link` refuses to
/// replace an existing target. Elsewhere the target was written in place and
/// publishing is a no-op.
fn publish_output(written: &Path, target: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::fs::hard_link(written, target).map_err(|error| {
            let context = if error.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "cannot create output {} (existing files are not overwritten)",
                    target.display()
                )
            } else {
                format!("cannot create output {}", target.display())
            };
            anyhow::Error::new(error).context(context)
        })?;
        std::fs::remove_file(written)
            .with_context(|| format!("cannot remove temporary output {}", written.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (written, target);
    }
    Ok(())
}
/// Whether the error chain is a closed stdout (a reader such as head exited).
///
/// Every write path is covered: the JSONL and text-payload formatters wrap
/// writer failures in `FormatterError::Json(serde_json::Error)`, which hides
/// the io error one level down, so the kind is recovered through
/// `serde_json::Error::io_error_kind`. Only `BrokenPipe` counts as the
/// graceful "reader went away" case.
fn is_broken_pipe(error: &anyhow::Error) -> bool {
    use binlog_inspect::formatter::FormatterError;
    error.chain().any(|cause| {
        if let Some(io_error) = cause.downcast_ref::<io::Error>() {
            return io_error.kind() == io::ErrorKind::BrokenPipe;
        }
        match cause.downcast_ref::<FormatterError>() {
            Some(FormatterError::Io(io_error)) => io_error.kind() == io::ErrorKind::BrokenPipe,
            Some(FormatterError::Json(json_error)) => {
                json_error.io_error_kind() == Some(io::ErrorKind::BrokenPipe)
            }
            _ => false,
        }
    })
}
fn main() -> Result<()> {
    match run() {
        Err(error) if is_broken_pipe(&error) => Ok(()),
        result => result,
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    // --completions ignores every other option and never opens any input.
    if let Some(shell) = cli.completions {
        let mut command = Cli::command();
        // Generate into a buffer instead of writing straight to stdout:
        // clap_complete's shell generators panic on write errors, and the
        // broken-pipe exit-0 contract must hold here too (R40).
        let mut script = Vec::new();
        clap_complete::generate(shell, &mut command, env!("CARGO_BIN_NAME"), &mut script);
        let mut stdout = io::stdout().lock();
        stdout.write_all(&script)?;
        stdout.flush()?;
        return Ok(());
    }
    #[cfg(feature = "remote")]
    let has_urls = !cli.urls.is_empty();
    #[cfg(not(feature = "remote"))]
    let has_urls = false;
    if cli.files.is_empty() && !has_urls {
        #[cfg(feature = "remote")]
        bail!("provide at least one FILE (use - for stdin) or --url");
        #[cfg(not(feature = "remote"))]
        bail!("provide at least one FILE (use - for stdin)");
    }
    let filter = EventFilter {
        kinds: cli.events.iter().copied().collect(),
        tables: cli.tables.iter().cloned().collect(),
        ranges: RangeFilter {
            start_position: cli.start_position,
            stop_position: cli.stop_position,
            start_datetime: cli.start_datetime,
            stop_datetime: cli.stop_datetime,
        },
        gtids: cli.include_gtids.iter().cloned().collect(),
    };
    let mut sink = if cli.stats {
        Sink::Stats(Stats::default())
    } else {
        Sink::Events(match cli.format {
            Format::Jsonl => Box::new(JsonLinesFormatter),
            Format::Text => Box::new(TextFormatter),
            Format::Csv => Box::new(CsvFormatter),
        })
    };
    let written: Option<PathBuf> = match &cli.output {
        Some(path) => Some(create_output(path)?),
        None => None,
    };
    let result = run_inputs(&cli, &filter, &mut sink, written.as_deref());
    if result.is_err() {
        // Any failure mid-run leaves no output behind.
        if let Some(written) = &written {
            let _ = std::fs::remove_file(written);
        }
    }
    let outcomes = result?;
    if let Some(written) = written.as_deref() {
        let target = cli.output.as_deref().expect("output set with written path");
        if let Err(error) = publish_output(written, target) {
            // Publish failures must not leave the temporary file behind.
            let _ = std::fs::remove_file(written);
            return Err(error);
        }
    }
    let partial: Vec<(String, String)> = outcomes
        .into_iter()
        .filter_map(|outcome| match outcome {
            Outcome::Complete => None,
            Outcome::Partial { file, error } => Some((file, error)),
        })
        .collect();
    if !partial.is_empty() {
        advise("error: the following binlogs could not be fully parsed:");
        for (file, error) in &partial {
            advise(&format!("  {file}: {error}"));
        }
        std::process::exit(3);
    }
    Ok(())
}
/// Writes one advisory line to standard error, ignoring write failures.
///
/// Warnings and partial-failure summaries are advisory output: a closed
/// stderr (`2>&-`) or a closed pipe must never change the exit status, and
/// the `eprintln!` macro panics on write errors (exit 101), so failures are
/// dropped here instead (R51).
fn advise(message: &str) {
    let _ = writeln!(io::stderr(), "{message}");
}
