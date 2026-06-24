//! Command-line definitions shared by Zuicity binaries.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, atomic::Ordering},
};

use clap::{ArgAction, Args, Parser, Subcommand};
use time::{OffsetDateTime, macros::format_description};
use zuicity_protocol::AtomicCounter64;

const CLIENT_TOP_LEVEL_HELP: &str = "zuicity-client is a quic-based proxy client.\n\nUsage:\n  zuicity-client [command]\n\nAvailable Commands:\n  help        Help about any command\n  run         To run zuicity-client in the foreground.\n\nFlags:\n  -h, --help      help for zuicity-client\n  -v, --version   version for zuicity-client\n\nUse \"zuicity-client [command] --help\" for more information about a command.\n";

const SERVER_TOP_LEVEL_HELP: &str = "zuicity-server is a quic-based proxy server.\n\nUsage:\n  zuicity-server [command]\n\nAvailable Commands:\n  generate-certchain-hash To generate the hash of a full chain certificate.\n  generate-sharelink      To generate the sharelink from the config file.\n  help                    Help about any command\n  run                     To run zuicity-server in the foreground.\n\nFlags:\n  -h, --help      help for zuicity-server\n  -v, --version   version for zuicity-server\n\nUse \"zuicity-server [command] --help\" for more information about a command.\n";

const CLIENT_RUN_HELP: &str = "To run zuicity-client in the foreground.\n\nUsage:\n  zuicity-client run [flags]\n\nFlags:\n  -c, --config string              specify config file path\n      --disable-timestamp          deprecated; use log-disable-timestamp instead\n  -h, --help                       help for run\n      --log-disable-color          disable colorful log output\n      --log-disable-timestamp      disable timestamp\n      --log-file string            log file path to write (default \"/var/log/zuicity-client.log\")\n      --log-file-compress          enable log compression; default: true (default true)\n      --log-file-format string     specify log format; options: [raw|json] (default \"raw\")\n      --log-file-max-age int       specify the maximum number of days to retain old log files based on the timestamp encoded in their filename; unit: day (default 1)\n      --log-file-max-backups int   specify the maximum number of old log files to retain (default 1)\n      --log-file-max-size int      specify maximum size of the log file before it gets rotated; unit: MB (default 10)\n      --log-output string          specify the log outputs; options: [console|file|console,file] (default \"console\")\n";

const SERVER_RUN_HELP: &str = "To run zuicity-server in the foreground.\n\nUsage:\n  zuicity-server run [flags]\n\nFlags:\n  -c, --config string              specify config file path\n      --disable-timestamp          deprecated; use log-disable-timestamp instead\n  -h, --help                       help for run\n      --log-disable-color          disable colorful log output\n      --log-disable-timestamp      disable timestamp\n      --log-file string            log file path to write (default \"/var/log/zuicity-client.log\")\n      --log-file-compress          enable log compression; default: true (default true)\n      --log-file-format string     specify log format; options: [raw|json] (default \"raw\")\n      --log-file-max-age int       specify the maximum number of days to retain old log files based on the timestamp encoded in their filename; unit: day (default 1)\n      --log-file-max-backups int   specify the maximum number of old log files to retain (default 1)\n      --log-file-max-size int      specify maximum size of the log file before it gets rotated; unit: MB (default 10)\n      --log-output string          specify the log outputs; options: [console|file|console,file] (default \"console\")\n";

const SERVER_CERTCHAIN_HASH_HELP: &str = "To generate the hash of a full chain certificate.\n\nUsage:\n  zuicity-server generate-certchain-hash [fullchain_file]\n\nFlags:\n  -h, --help   help for generate-certchain-hash\n";

const SERVER_SHARELINK_HELP: &str = "To generate the sharelink from the config file.\n\nUsage:\n  zuicity-server generate-sharelink [config_file]\n\nFlags:\n  -c, --config string              specify config file path\n      --disable-timestamp          deprecated; use log-disable-timestamp instead\n  -h, --help                       help for generate-sharelink\n      --log-disable-color          disable colorful log output\n      --log-disable-timestamp      disable timestamp\n      --log-file string            log file path to write (default \"/var/log/zuicity-client.log\")\n      --log-file-compress          enable log compression; default: true (default true)\n      --log-file-format string     specify log format; options: [raw|json] (default \"raw\")\n      --log-file-max-age int       specify the maximum number of days to retain old log files based on the timestamp encoded in their filename; unit: day (default 1)\n      --log-file-max-backups int   specify the maximum number of old log files to retain (default 1)\n      --log-file-max-size int      specify maximum size of the log file before it gets rotated; unit: MB (default 10)\n      --log-output string          specify the log outputs; options: [console|file|console,file] (default \"console\")\n";

const ZUICITY_VERSION_FOOTER: &str = concat!(
    "version ",
    env!("ZUICITY_BUILD_VERSION"),
    "\nrust runtime ",
    env!("ZUICITY_RUSTC_VERSION"),
    " ",
    env!("ZUICITY_TARGET_OS"),
    "/",
    env!("ZUICITY_TARGET_ARCH"),
    "\nCGO_ENABLED: 0",
    "\nCopyright (c) 2023 zuicity\nLicense GNU AGPLv3 <https://github.com/juicity/juicity/blob/main/LICENSE>"
);

/// Formats JSON decode errors with upstream `ReadConfig` wording for CLI output.
pub fn format_read_config_decode_error(input: &str, err: zuicity_config::ConfigError) -> String {
    match err {
        zuicity_config::ConfigError::Json(json_error) if json_error.is_eof() => {
            if input.trim().is_empty() {
                "EOF".to_owned()
            } else {
                "unexpected EOF".to_owned()
            }
        }
        other => other.to_string(),
    }
}

/// Worker-thread count for the proxy runtimes.
///
/// Returns `None` to keep tokio's default (one worker per core). Otherwise the
/// runtime is capped so idle deployments do not pay a per-core worker stack and
/// allocator arena. `ZUICITY_WORKER_THREADS` overrides the cap (0 = tokio
/// default); absent, the cap is `min(available cores, 4)`.
pub fn zuicity_runtime_worker_threads() -> Option<usize> {
    if let Ok(raw) = std::env::var("ZUICITY_WORKER_THREADS") {
        return match raw.trim().parse::<usize>() {
            Ok(0) => None,
            Ok(n) => Some(n),
            Err(_) => None,
        };
    }
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    Some(cores.min(4).max(1))
}

/// Upstream logging output target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogOutput {
    /// Write human-readable logs to stdout.
    Console,
    /// Write logs to a rotating file.
    File,
}

/// Upstream logging file format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogFileFormat {
    /// Human-readable zerolog console format.
    Raw,
    /// JSON zerolog event format.
    Json,
}

/// Parsed log level accepted by upstream zerolog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogLevel {
    /// Upstream zerolog NoLevel; config runtime loggers suppress all events.
    NoLevel,
    /// Trace log level.
    Trace,
    /// Debug log level.
    Debug,
    /// Info log level.
    Info,
    /// Warn log level.
    Warn,
    /// Error log level.
    Error,
    /// Fatal log level.
    Fatal,
    /// Panic log level.
    Panic,
}

impl LogLevel {
    const fn priority(self) -> u8 {
        match self {
            Self::Trace => 0,
            Self::Debug => 1,
            Self::Info => 2,
            Self::Warn => 3,
            Self::Error => 4,
            Self::Fatal => 5,
            Self::Panic => 6,
            Self::NoLevel => 7,
        }
    }

    const fn allows(self, event_level: Self) -> bool {
        !matches!(self, Self::NoLevel) && event_level.priority() >= self.priority()
    }

    fn console_label(self) -> &'static str {
        match self {
            Self::NoLevel => "",
            Self::Trace => "TRC",
            Self::Debug => "DBG",
            Self::Info => "INF",
            Self::Warn => "WRN",
            Self::Error => "ERR",
            Self::Fatal => "FTL",
            Self::Panic => "PNC",
        }
    }

    fn json_label(self) -> &'static str {
        match self {
            Self::NoLevel => "",
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Fatal => "fatal",
            Self::Panic => "panic",
        }
    }
}

/// Normalized logging settings derived from CLI flags and config log level.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogSettings {
    /// Parsed log level.
    pub level: LogLevel,
    /// Deduplicated output targets, preserving upstream order.
    pub outputs: Vec<LogOutput>,
    /// Whether logs include timestamps.
    pub timestamp_enabled: bool,
    /// Whether colorful console output is disabled.
    pub disable_color: bool,
    /// Log file path when file output is enabled.
    pub file: Option<String>,
    /// File writer format.
    pub file_format: LogFileFormat,
    /// Maximum file size before rotation, in MB.
    pub file_max_size_mb: u64,
    /// Number of old log files to retain.
    pub file_max_backups: u64,
    /// Maximum old log age, in days.
    pub file_max_age_days: u64,
    /// Whether old log files are compressed.
    pub file_compress: bool,
}

/// A single rendered log event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogEvent {
    /// Event level.
    pub level: LogLevel,
    /// Event message.
    pub message: String,
    /// Optional event timestamp.
    pub timestamp: Option<String>,
    /// Optional source caller.
    pub caller: Option<String>,
}

impl LogEvent {
    /// Constructs a new log event.
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            level,
            message: message.into(),
            timestamp: None,
            caller: None,
        }
    }

    /// Adds a timestamp to the log event.
    pub fn with_timestamp(mut self, timestamp: impl Into<String>) -> Self {
        self.timestamp = Some(timestamp.into());
        self
    }

    /// Adds a caller location to the log event.
    pub fn with_caller(mut self, caller: impl Into<String>) -> Self {
        self.caller = Some(caller.into());
        self
    }
}

impl LogSettings {
    /// Renders a console-style event line.
    pub fn render_raw_event(&self, event: &LogEvent) -> String {
        let mut line = String::new();
        if self.timestamp_enabled {
            if let Some(timestamp) = event.timestamp.as_deref() {
                line.push_str(timestamp);
                line.push(' ');
            }
        }
        line.push_str(event.level.console_label());
        line.push(' ');
        if let Some(caller) = event.caller.as_deref() {
            line.push_str(caller);
            line.push_str(" > ");
        } else {
            line.push_str("> ");
        }
        line.push_str(event.message.as_str());
        line.push('\n');
        line
    }

    /// Renders a file-style event line.
    pub fn render_file_event(&self, event: &LogEvent) -> String {
        match self.file_format {
            LogFileFormat::Raw => self.render_raw_event(event),
            LogFileFormat::Json => {
                let mut line = String::from("{");
                line.push_str("\"level\":");
                push_json_string(&mut line, event.level.json_label());
                if let Some(caller) = event.caller.as_deref() {
                    line.push_str(",\"caller\":");
                    push_json_string(&mut line, caller);
                }
                if self.timestamp_enabled {
                    if let Some(timestamp) = event.timestamp.as_deref() {
                        line.push_str(",\"time\":");
                        push_json_string(&mut line, timestamp);
                    }
                }
                line.push_str(",\"message\":");
                push_json_string(&mut line, event.message.as_str());
                line.push('}');
                line.push('\n');
                line
            }
        }
    }
}

fn push_json_string(dst: &mut String, value: &str) {
    use std::fmt::Write as _;

    dst.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => dst.push_str("\\\\"),
            '"' => dst.push_str("\\\""),
            '\n' => dst.push_str("\\n"),
            '\r' => dst.push_str("\\r"),
            '\t' => dst.push_str("\\t"),
            '\u{08}' => dst.push_str("\\b"),
            '\u{0c}' => dst.push_str("\\f"),
            c if c.is_control() => {
                let _ = write!(dst, "\\u{:04x}", c as u32);
            }
            c => dst.push(c),
        }
    }
    dst.push('"');
}

/// Rotating file writer that matches upstream lumberjack backup naming.
#[derive(Debug)]
pub struct RotatingFileWriter {
    path: PathBuf,
    file: Option<fs::File>,
    current_size: u64,
    max_size_bytes: u64,
    max_backups: usize,
    _max_age_days: u64,
    _compress: bool,
}

impl RotatingFileWriter {
    fn open(
        path: impl Into<PathBuf>,
        max_size_mb: u64,
        max_backups: u64,
        max_age_days: u64,
        compress: bool,
    ) -> io::Result<Self> {
        let path = path.into();
        let current_size = fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            file: Some(file),
            current_size,
            max_size_bytes: max_size_mb.saturating_mul(1024 * 1024),
            max_backups: max_backups as usize,
            _max_age_days: max_age_days,
            _compress: compress,
        })
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        if self.should_rotate(buf.len() as u64) {
            self.rotate()?;
        }
        let Some(file) = self.file.as_mut() else {
            return Err(io::Error::other("rotating log writer is closed"));
        };
        file.write_all(buf)?;
        self.current_size = self.current_size.saturating_add(buf.len() as u64);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            file.flush()?;
        }
        Ok(())
    }

    fn should_rotate(&self, next_len: u64) -> bool {
        self.max_size_bytes > 0
            && self.current_size > 0
            && self.current_size.saturating_add(next_len) > self.max_size_bytes
    }

    fn rotate(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
            drop(file);
        }
        if self.path.exists() {
            let backup = self.rotated_path()?;
            fs::rename(&self.path, &backup)?;
            self.prune_backups()?;
        }
        self.file = Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?,
        );
        self.current_size = 0;
        Ok(())
    }

    fn rotated_path(&self) -> io::Result<PathBuf> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let stem = self
            .path
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid log file stem"))?;
        let ext = self.path.extension().and_then(|value| value.to_str());
        let timestamp = Self::rotation_timestamp();
        for attempt in 0_u32.. {
            let candidate_name = match ext {
                Some(ext) if attempt == 0 => format!("{stem}-{timestamp}.{ext}"),
                Some(ext) => format!("{stem}-{timestamp}-{attempt}.{ext}"),
                None if attempt == 0 => format!("{stem}-{timestamp}"),
                None => format!("{stem}-{timestamp}-{attempt}"),
            };
            let candidate = parent.join(candidate_name);
            if !candidate.exists() {
                return Ok(candidate);
            }
        }
        unreachable!("rotation path search should always terminate")
    }

    fn rotation_timestamp() -> String {
        let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
        now.format(&format_description!(
            "[year]-[month]-[day]T[hour]-[minute]-[second].[subsecond digits:3]"
        ))
        .unwrap_or_else(|_| {
            format!(
                "{:020}.{:03}",
                now.unix_timestamp(),
                now.nanosecond() / 1_000_000,
            )
        })
    }

    fn prune_backups(&self) -> io::Result<()> {
        if self.max_backups == 0 {
            return self.remove_all_backups();
        }
        let mut backups = self.backup_paths()?;
        if backups.len() <= self.max_backups {
            return Ok(());
        }
        backups.sort();
        let remove_count = backups.len() - self.max_backups;
        for path in backups.into_iter().take(remove_count) {
            let _ = fs::remove_file(path);
        }
        Ok(())
    }

    fn remove_all_backups(&self) -> io::Result<()> {
        for path in self.backup_paths()? {
            let _ = fs::remove_file(path);
        }
        Ok(())
    }

    fn backup_paths(&self) -> io::Result<Vec<PathBuf>> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let stem = self
            .path
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid log file stem"))?;
        let prefix = format!("{stem}-");
        let suffix = self
            .path
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| format!(".{value}"))
            .unwrap_or_default();
        let mut backups = Vec::new();
        for entry in fs::read_dir(parent)? {
            let entry = entry?;
            let path = entry.path();
            if path == self.path {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if name.starts_with(&prefix) && name.ends_with(&suffix) {
                backups.push(path);
            }
        }
        Ok(backups)
    }
}

impl io::Write for RotatingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        RotatingFileWriter::flush(self)
    }
}

/// Thread-safe runtime logging counters for embedders and tests.
#[derive(Clone, Debug, Default)]
pub struct RuntimeLogMetrics {
    inner: Arc<RuntimeLogMetricsInner>,
}

#[derive(Debug, Default)]
struct RuntimeLogMetricsInner {
    events: AtomicCounter64,
    console_events: AtomicCounter64,
    file_events: AtomicCounter64,
    console_bytes: AtomicCounter64,
    file_bytes: AtomicCounter64,
}

impl RuntimeLogMetrics {
    fn event_written(&self) {
        self.inner.events.fetch_add(1, Ordering::Relaxed);
    }

    fn console_written(&self, bytes: u64) {
        self.inner.console_events.fetch_add(1, Ordering::Relaxed);
        self.inner.console_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn file_written(&self, bytes: u64) {
        self.inner.file_events.fetch_add(1, Ordering::Relaxed);
        self.inner.file_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Returns a stable snapshot of runtime logging counters.
    #[must_use]
    pub fn snapshot(&self) -> RuntimeLogMetricsSnapshot {
        RuntimeLogMetricsSnapshot {
            events: self.inner.events.load(Ordering::Relaxed),
            console_events: self.inner.console_events.load(Ordering::Relaxed),
            file_events: self.inner.file_events.load(Ordering::Relaxed),
            console_bytes: self.inner.console_bytes.load(Ordering::Relaxed),
            file_bytes: self.inner.file_bytes.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of runtime logging counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeLogMetricsSnapshot {
    /// Total successfully processed log events.
    pub events: u64,
    /// Total console writes.
    pub console_events: u64,
    /// Total file writes.
    pub file_events: u64,
    /// Total bytes written to console outputs.
    pub console_bytes: u64,
    /// Total bytes written to file outputs.
    pub file_bytes: u64,
}

/// Runtime logger backed by upstream-shaped renderers and concrete writers.
#[derive(Debug)]
pub struct RuntimeLogger<C = std::io::Stdout, F = std::fs::File> {
    settings: LogSettings,
    console_writer: Option<C>,
    file_writer: Option<F>,
    metrics: RuntimeLogMetrics,
}

/// Default runtime logger that writes to stdout and a configured file.
pub type DefaultRuntimeLogger = RuntimeLogger<std::io::Stdout, RotatingFileWriter>;

impl<C, F> RuntimeLogger<C, F>
where
    C: io::Write,
    F: io::Write,
{
    /// Constructs a logger from already-opened writers.
    pub fn with_writers(
        settings: LogSettings,
        console_writer: Option<C>,
        file_writer: Option<F>,
    ) -> Self {
        Self::with_writers_and_observer(
            settings,
            console_writer,
            file_writer,
            RuntimeLogMetrics::default(),
        )
    }

    /// Constructs a logger from already-opened writers and a metrics observer.
    pub fn with_writers_and_observer(
        settings: LogSettings,
        console_writer: Option<C>,
        file_writer: Option<F>,
        metrics: RuntimeLogMetrics,
    ) -> Self {
        Self {
            settings,
            console_writer,
            file_writer,
            metrics,
        }
    }

    /// Returns this logger's normalized settings.
    #[must_use]
    pub const fn settings(&self) -> &LogSettings {
        &self.settings
    }

    /// Returns this logger's metrics observer.
    #[must_use]
    pub const fn metrics(&self) -> &RuntimeLogMetrics {
        &self.metrics
    }

    /// Writes an event to every configured output.
    pub fn write_event(&mut self, event: &LogEvent) -> io::Result<()> {
        if !self.settings.level.allows(event.level) {
            return Ok(());
        }
        for output in &self.settings.outputs {
            match output {
                LogOutput::Console => {
                    if let Some(writer) = self.console_writer.as_mut() {
                        let rendered = self.settings.render_raw_event(event);
                        writer.write_all(rendered.as_bytes())?;
                        writer.flush()?;
                        self.metrics.console_written(rendered.len() as u64);
                    }
                }
                LogOutput::File => {
                    if let Some(writer) = self.file_writer.as_mut() {
                        let rendered = self.settings.render_file_event(event);
                        writer.write_all(rendered.as_bytes())?;
                        writer.flush()?;
                        self.metrics.file_written(rendered.len() as u64);
                    }
                }
            }
        }
        self.metrics.event_written();
        Ok(())
    }

    /// Returns the owned writers, primarily for tests.
    #[must_use]
    pub fn into_writers(self) -> (Option<C>, Option<F>) {
        (self.console_writer, self.file_writer)
    }
}

/// `tracing` layer that forwards events into a [`RuntimeLogger`].
#[derive(Debug)]
pub struct RuntimeTracingLayer<C = std::io::Stdout, F = RotatingFileWriter>
where
    C: io::Write + Send + 'static,
    F: io::Write + Send + 'static,
{
    handle: RuntimeTracingLoggerHandle<C, F>,
}

/// Handle for retrieving the logger owned by a [`RuntimeTracingLayer`].
#[derive(Debug)]
pub struct RuntimeTracingLoggerHandle<C = std::io::Stdout, F = RotatingFileWriter>
where
    C: io::Write + Send + 'static,
    F: io::Write + Send + 'static,
{
    inner: Arc<Mutex<Option<RuntimeLogger<C, F>>>>,
}

impl<C, F> Clone for RuntimeTracingLoggerHandle<C, F>
where
    C: io::Write + Send + 'static,
    F: io::Write + Send + 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<C, F> RuntimeTracingLayer<C, F>
where
    C: io::Write + Send + 'static,
    F: io::Write + Send + 'static,
{
    /// Creates a layer and a retrieval handle around a runtime logger.
    #[must_use]
    pub fn new(logger: RuntimeLogger<C, F>) -> (Self, RuntimeTracingLoggerHandle<C, F>) {
        let handle = RuntimeTracingLoggerHandle {
            inner: Arc::new(Mutex::new(Some(logger))),
        };
        (
            Self {
                handle: handle.clone(),
            },
            handle,
        )
    }

    /// Returns a cloneable handle to the layer-owned logger.
    #[must_use]
    pub fn handle(&self) -> RuntimeTracingLoggerHandle<C, F> {
        self.handle.clone()
    }
}

impl<C, F> RuntimeTracingLoggerHandle<C, F>
where
    C: io::Write + Send + 'static,
    F: io::Write + Send + 'static,
{
    /// Writes an event through the layer-owned runtime logger.
    pub fn write_event(&self, event: &LogEvent) -> io::Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("runtime tracing logger lock poisoned"))?;
        if let Some(logger) = guard.as_mut() {
            logger.write_event(event)
        } else {
            Ok(())
        }
    }

    /// Takes the logger out of the layer.
    pub fn into_logger(self) -> Option<RuntimeLogger<C, F>> {
        self.inner.lock().ok()?.take()
    }
}

impl<C, F, S> tracing_subscriber::Layer<S> for RuntimeTracingLayer<C, F>
where
    C: io::Write + Send + 'static,
    F: io::Write + Send + 'static,
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let metadata = event.metadata();
        let mut fields = RuntimeTracingEventVisitor::default();
        event.record(&mut fields);
        let mut message = fields.message.unwrap_or_default();
        for (key, value) in fields.fields {
            if !message.is_empty() {
                message.push(' ');
            }
            message.push_str(&key);
            message.push('=');
            message.push_str(&value);
        }
        let log_level = tracing_level_to_log_level(metadata.level());
        let log_event = LogEvent::new(log_level, message).with_caller(metadata.target());
        if let Ok(mut guard) = self.handle.inner.lock() {
            if let Some(logger) = guard.as_mut() {
                let _ = logger.write_event(&log_event);
            }
        }
    }
}

#[derive(Default)]
struct RuntimeTracingEventVisitor {
    message: Option<String>,
    fields: Vec<(String, String)>,
}

impl tracing::field::Visit for RuntimeTracingEventVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.record_value(field.name(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record_value(field.name(), value.to_owned());
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.record_value(field.name(), value.to_string());
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.record_value(field.name(), value.to_string());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.record_value(field.name(), value.to_string());
    }
}

impl RuntimeTracingEventVisitor {
    fn record_value(&mut self, name: &str, value: String) {
        if name == "message" {
            self.message = Some(value);
        } else {
            self.fields.push((name.to_owned(), value));
        }
    }
}

fn tracing_level_to_log_level(level: &tracing::Level) -> LogLevel {
    match *level {
        tracing::Level::TRACE => LogLevel::Trace,
        tracing::Level::DEBUG => LogLevel::Debug,
        tracing::Level::INFO => LogLevel::Info,
        tracing::Level::WARN => LogLevel::Warn,
        tracing::Level::ERROR => LogLevel::Error,
    }
}

impl DefaultRuntimeLogger {
    /// Opens stdout and file writers for the requested outputs.
    pub fn open(settings: LogSettings) -> io::Result<Self> {
        let console_writer = settings
            .outputs
            .contains(&LogOutput::Console)
            .then(std::io::stdout);
        let file_writer = if settings.outputs.contains(&LogOutput::File) {
            settings
                .file
                .as_deref()
                .filter(|path| !path.is_empty())
                .map(|path| {
                    RotatingFileWriter::open(
                        path,
                        settings.file_max_size_mb,
                        settings.file_max_backups,
                        settings.file_max_age_days,
                        settings.file_compress,
                    )
                })
                .transpose()?
        } else {
            None
        };
        Ok(Self::with_writers(settings, console_writer, file_writer))
    }
}

/// Constructs the upstream default console logger used before config-specific logging is ready.
#[must_use]
pub fn default_console_logger() -> DefaultRuntimeLogger {
    RuntimeLogger::with_writers(
        LogSettings {
            level: LogLevel::Debug,
            outputs: vec![LogOutput::Console],
            timestamp_enabled: true,
            disable_color: false,
            file: None,
            file_format: LogFileFormat::Raw,
            file_max_size_mb: 10,
            file_max_backups: 1,
            file_max_age_days: 1,
            file_compress: true,
        },
        Some(std::io::stdout()),
        None,
    )
}

/// Log settings parse error.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LogSettingsError {
    /// Invalid log level.
    #[error("ParseLevel: {0}")]
    InvalidLevel(String),
    /// Invalid log output target.
    #[error("invalid log output {0}")]
    InvalidOutput(String),
    /// Invalid file log format.
    #[error("invalid log-file-format {0}")]
    InvalidFileFormat(String),
}

/// Runtime logger construction error.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeLoggerError {
    /// Log setting normalization failed.
    #[error(transparent)]
    Settings(#[from] LogSettingsError),
    /// Opening a configured writer failed.
    #[error("open log writer: {0}")]
    Writer(#[from] io::Error),
}

/// Shared log flags mirrored from upstream Juicity.
#[derive(Clone, Debug, Args)]
pub struct LogArgs {
    /// Specify config file path.
    #[arg(short = 'c', long = "config")]
    pub config: Option<String>,
    /// Specify the log outputs; options: [console|file|console,file].
    #[arg(long = "log-output", default_value = "console")]
    pub log_output: String,
    /// Disable colorful log output.
    #[arg(long = "log-disable-color", default_value_t = false)]
    pub log_disable_color: bool,
    /// Deprecated; use log-disable-timestamp instead.
    #[arg(long = "disable-timestamp", default_value_t = false)]
    pub disable_timestamp: bool,
    /// Disable timestamp.
    #[arg(long = "log-disable-timestamp", default_value_t = false)]
    pub log_disable_timestamp: bool,
    /// Log file path to write.
    #[arg(long = "log-file", default_value = "/var/log/zuicity-client.log")]
    pub log_file: String,
    /// Specify log format; options: [raw|json].
    #[arg(long = "log-file-format", default_value = "raw")]
    pub log_file_format: String,
    /// Specify maximum size before rotation, in MB.
    #[arg(long = "log-file-max-size", default_value_t = 10)]
    pub log_file_max_size: u64,
    /// Specify maximum old log files to retain.
    #[arg(long = "log-file-max-backups", default_value_t = 1)]
    pub log_file_max_backups: u64,
    /// Specify maximum days to retain old log files.
    #[arg(long = "log-file-max-age", default_value_t = 1)]
    pub log_file_max_age: u64,
    /// Enable log compression.
    #[arg(long = "log-file-compress", default_value_t = true)]
    pub log_file_compress: bool,
}

impl LogArgs {
    /// Normalizes upstream logging flags into typed settings.
    /// Constructs a runtime logger from this flag set and a config log level.
    pub fn runtime_logger(
        &self,
        log_level: &str,
    ) -> Result<DefaultRuntimeLogger, RuntimeLoggerError> {
        let settings = self.log_settings(log_level)?;
        Ok(DefaultRuntimeLogger::open(settings)?)
    }

    /// Normalizes upstream logging flags into typed settings.
    pub fn log_settings(&self, log_level: &str) -> Result<LogSettings, LogSettingsError> {
        let mut outputs = Vec::new();
        let raw_outputs = if self.log_output.is_empty() {
            "console"
        } else {
            self.log_output.as_str()
        };
        for output in raw_outputs.split(',').map(str::trim) {
            if output.is_empty() {
                continue;
            }
            let parsed = match output {
                "console" => LogOutput::Console,
                "file" => LogOutput::File,
                other => return Err(LogSettingsError::InvalidOutput(other.to_owned())),
            };
            if !outputs.contains(&parsed) {
                outputs.push(parsed);
            }
        }

        Ok(LogSettings {
            level: parse_log_level(log_level)?,
            outputs,
            timestamp_enabled: !(self.disable_timestamp || self.log_disable_timestamp),
            disable_color: self.log_disable_color,
            file: if self.log_file.is_empty() {
                None
            } else {
                Some(self.log_file.clone())
            },
            file_format: parse_log_file_format(&self.log_file_format)?,
            file_max_size_mb: self.log_file_max_size,
            file_max_backups: self.log_file_max_backups,
            file_max_age_days: self.log_file_max_age,
            file_compress: self.log_file_compress,
        })
    }
}

fn parse_log_level(value: &str) -> Result<LogLevel, LogSettingsError> {
    match value {
        "" => Ok(LogLevel::NoLevel),
        "trace" => Ok(LogLevel::Trace),
        "debug" => Ok(LogLevel::Debug),
        "info" => Ok(LogLevel::Info),
        "warn" | "warning" => Ok(LogLevel::Warn),
        "error" => Ok(LogLevel::Error),
        "fatal" => Ok(LogLevel::Fatal),
        "panic" => Ok(LogLevel::Panic),
        other => Err(LogSettingsError::InvalidLevel(other.to_owned())),
    }
}

fn parse_log_file_format(value: &str) -> Result<LogFileFormat, LogSettingsError> {
    match value {
        "raw" | "" => Ok(LogFileFormat::Raw),
        "json" => Ok(LogFileFormat::Json),
        other => Err(LogSettingsError::InvalidFileFormat(other.to_owned())),
    }
}

/// zuicity-client CLI.
#[derive(Clone, Debug, Parser)]
#[command(
    name = "zuicity-client",
    about = "zuicity-client is a quic-based proxy client.",
    version = ZUICITY_VERSION_FOOTER,
    disable_version_flag = true,
    override_help = CLIENT_TOP_LEVEL_HELP
)]
pub struct ClientCli {
    /// Show version information.
    #[arg(short = 'v', long = "version", action = ArgAction::Version)]
    pub version: Option<bool>,
    /// Client subcommand.
    #[command(subcommand)]
    pub command: ClientCommand,
}

/// Client subcommands.
#[derive(Clone, Debug, Subcommand)]
pub enum ClientCommand {
    /// To run zuicity-client in the foreground.
    #[command(override_help = CLIENT_RUN_HELP)]
    Run(LogArgs),
}

/// zuicity-server CLI.
#[derive(Clone, Debug, Parser)]
#[command(
    name = "zuicity-server",
    about = "zuicity-server is a quic-based proxy server.",
    version = ZUICITY_VERSION_FOOTER,
    disable_version_flag = true,
    override_help = SERVER_TOP_LEVEL_HELP
)]
pub struct ServerCli {
    /// Show version information.
    #[arg(short = 'v', long = "version", action = ArgAction::Version)]
    pub version: Option<bool>,
    /// Server subcommand.
    #[command(subcommand)]
    pub command: ServerCommand,
}

/// Server subcommands.
#[derive(Clone, Debug, Subcommand)]
pub enum ServerCommand {
    /// To run zuicity-server in the foreground.
    #[command(override_help = SERVER_RUN_HELP)]
    Run(LogArgs),
    /// To generate the hash of a full chain certificate.
    #[command(override_help = SERVER_CERTCHAIN_HASH_HELP)]
    GenerateCertchainHash {
        /// Full chain certificate file. Upstream accepts zero or more and uses the first at runtime.
        #[arg(value_name = "fullchain_file")]
        fullchain_file: Vec<String>,
    },
    /// To generate the sharelink from the config file.
    #[command(override_help = SERVER_SHARELINK_HELP)]
    GenerateSharelink {
        /// Optional positional config path accepted by upstream help/parser.
        #[arg(value_name = "config_file")]
        config_file: Option<String>,
        /// Shared config/log arguments.
        #[command(flatten)]
        args: LogArgs,
    },
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, error::ErrorKind};

    use super::*;

    #[test]
    fn log_args_normalize_upstream_timestamp_and_output_defaults() {
        let cli = ClientCli::try_parse_from([
            "zuicity-client",
            "run",
            "--disable-timestamp",
            "--log-output",
            " file, console ,file ",
            "--log-file",
            "/tmp/zuicity.log",
            "--log-file-format",
            "json",
        ])
        .expect("parse client run log args");
        let ClientCommand::Run(args) = cli.command;
        let settings = args.log_settings("debug").expect("normalize log settings");

        assert_eq!(settings.level, LogLevel::Debug);
        assert_eq!(settings.outputs, vec![LogOutput::File, LogOutput::Console]);
        assert!(!settings.timestamp_enabled);
        assert_eq!(settings.file.as_deref(), Some("/tmp/zuicity.log"));
        assert_eq!(settings.file_format, LogFileFormat::Json);
        assert_eq!(settings.file_max_size_mb, 10);
        assert_eq!(settings.file_max_backups, 1);
        assert_eq!(settings.file_max_age_days, 1);
        assert!(settings.file_compress);
        assert!(!settings.disable_color);
    }

    #[test]
    fn log_settings_render_raw_event_matches_upstream_console_shape() {
        let settings = LogSettings {
            level: LogLevel::Info,
            outputs: vec![LogOutput::Console],
            timestamp_enabled: true,
            disable_color: true,
            file: None,
            file_format: LogFileFormat::Raw,
            file_max_size_mb: 10,
            file_max_backups: 1,
            file_max_age_days: 1,
            file_compress: true,
        };
        let event = LogEvent::new(LogLevel::Info, "client listener ready")
            .with_timestamp("2026-06-10 02:03:04")
            .with_caller("run.go:44");

        assert_eq!(
            settings.render_raw_event(&event),
            "2026-06-10 02:03:04 INF run.go:44 > client listener ready\n"
        );
    }

    #[test]
    fn log_settings_render_json_event_matches_upstream_file_shape() {
        let settings = LogSettings {
            level: LogLevel::Info,
            outputs: vec![LogOutput::File],
            timestamp_enabled: true,
            disable_color: true,
            file: Some("/tmp/zuicity.log".to_owned()),
            file_format: LogFileFormat::Json,
            file_max_size_mb: 10,
            file_max_backups: 1,
            file_max_age_days: 1,
            file_compress: true,
        };
        let event = LogEvent::new(LogLevel::Warn, "upstream relay recovered")
            .with_timestamp("2026-06-10T02:03:05+08:00")
            .with_caller("server.go:470");

        assert_eq!(
            settings.render_file_event(&event),
            "{\"level\":\"warn\",\"caller\":\"server.go:470\",\"time\":\"2026-06-10T02:03:05+08:00\",\"message\":\"upstream relay recovered\"}\n"
        );
    }

    #[test]
    fn runtime_logger_writes_console_and_json_file_outputs() {
        let settings = LogSettings {
            level: LogLevel::Info,
            outputs: vec![LogOutput::Console, LogOutput::File],
            timestamp_enabled: true,
            disable_color: true,
            file: Some("/tmp/zuicity.log".to_owned()),
            file_format: LogFileFormat::Json,
            file_max_size_mb: 10,
            file_max_backups: 1,
            file_max_age_days: 1,
            file_compress: true,
        };
        let event = LogEvent::new(LogLevel::Warn, "upstream relay recovered")
            .with_timestamp("2026-06-10T02:03:05+08:00")
            .with_caller("server.go:470");

        let mut logger = RuntimeLogger::with_writers(settings, Some(Vec::new()), Some(Vec::new()));
        logger.write_event(&event).expect("write log event");
        let (console, file) = logger.into_writers();

        assert_eq!(
            String::from_utf8(console.expect("console writer")).expect("utf8 console"),
            "2026-06-10T02:03:05+08:00 WRN server.go:470 > upstream relay recovered\n"
        );
        assert_eq!(
            String::from_utf8(file.expect("file writer")).expect("utf8 file"),
            "{\"level\":\"warn\",\"caller\":\"server.go:470\",\"time\":\"2026-06-10T02:03:05+08:00\",\"message\":\"upstream relay recovered\"}\n"
        );
    }

    #[test]
    fn runtime_logger_suppresses_events_for_empty_upstream_log_level() {
        let cli = ClientCli::try_parse_from(["zuicity-client", "run"])
            .expect("parse client run log args");
        let ClientCommand::Run(args) = cli.command;
        let settings = args.log_settings("").expect("normalize empty log level");
        assert_eq!(settings.level, LogLevel::NoLevel);
        let event = LogEvent::new(LogLevel::Fatal, "hidden fatal").with_caller("run.go:118");
        let metrics = RuntimeLogMetrics::default();
        let mut logger = RuntimeLogger::with_writers_and_observer(
            settings,
            Some(Vec::new()),
            Option::<Vec<u8>>::None,
            metrics.clone(),
        );

        logger.write_event(&event).expect("suppress log event");
        let (console, file) = logger.into_writers();

        assert_eq!(console.expect("console writer"), Vec::<u8>::new());
        assert!(file.is_none());
        assert_eq!(metrics.snapshot(), RuntimeLogMetricsSnapshot::default());
    }

    #[test]
    fn runtime_logger_notifies_observer_metrics_for_each_output() {
        let settings = LogSettings {
            level: LogLevel::Info,
            outputs: vec![LogOutput::Console, LogOutput::File],
            timestamp_enabled: true,
            disable_color: true,
            file: Some("/tmp/zuicity.log".to_owned()),
            file_format: LogFileFormat::Json,
            file_max_size_mb: 10,
            file_max_backups: 1,
            file_max_age_days: 1,
            file_compress: true,
        };
        let event = LogEvent::new(LogLevel::Warn, "upstream relay recovered")
            .with_timestamp("2026-06-10T02:03:05+08:00")
            .with_caller("server.go:470");
        let expected_console_bytes = settings.render_raw_event(&event).len() as u64;
        let expected_file_bytes = settings.render_file_event(&event).len() as u64;
        let metrics = RuntimeLogMetrics::default();

        let mut logger = RuntimeLogger::with_writers_and_observer(
            settings,
            Some(Vec::new()),
            Some(Vec::new()),
            metrics.clone(),
        );
        logger.write_event(&event).expect("write log event");

        assert_eq!(
            metrics.snapshot(),
            RuntimeLogMetricsSnapshot {
                events: 1,
                console_events: 1,
                file_events: 1,
                console_bytes: expected_console_bytes,
                file_bytes: expected_file_bytes,
            }
        );
    }

    #[test]
    fn runtime_tracing_layer_writes_events_through_runtime_logger() {
        use tracing_subscriber::prelude::*;

        let settings = LogSettings {
            level: LogLevel::Debug,
            outputs: vec![LogOutput::Console, LogOutput::File],
            timestamp_enabled: false,
            disable_color: true,
            file: Some("/tmp/zuicity.log".to_owned()),
            file_format: LogFileFormat::Json,
            file_max_size_mb: 10,
            file_max_backups: 1,
            file_max_age_days: 1,
            file_compress: true,
        };
        let metrics = RuntimeLogMetrics::default();
        let logger = RuntimeLogger::with_writers_and_observer(
            settings,
            Some(Vec::new()),
            Some(Vec::new()),
            metrics.clone(),
        );
        let (layer, handle) = RuntimeTracingLayer::new(logger);
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                target: "zuicity_cli::tests",
                network = "tcp",
                remote = "127.0.0.1:443",
                "relay opened"
            );
        });

        let logger = handle
            .into_logger()
            .expect("tracing subscriber released logger");
        let (console, file) = logger.into_writers();
        let console = String::from_utf8(console.expect("console writer")).expect("utf8 console");
        let file = String::from_utf8(file.expect("file writer")).expect("utf8 file");

        assert_eq!(
            console,
            "INF zuicity_cli::tests > relay opened network=tcp remote=127.0.0.1:443\n"
        );
        assert_eq!(
            file,
            "{\"level\":\"info\",\"caller\":\"zuicity_cli::tests\",\"message\":\"relay opened network=tcp remote=127.0.0.1:443\"}\n"
        );
        assert_eq!(
            metrics.snapshot(),
            RuntimeLogMetricsSnapshot {
                events: 1,
                console_events: 1,
                file_events: 1,
                console_bytes: console.len() as u64,
                file_bytes: file.len() as u64,
            }
        );
    }

    #[test]
    fn runtime_logger_rotates_file_like_upstream_lumberjack_shape() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "zuicity-log-rotation-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create log dir");
        let log_path = dir.join("zuicity.log");
        let settings = LogSettings {
            level: LogLevel::Info,
            outputs: vec![LogOutput::File],
            timestamp_enabled: false,
            disable_color: true,
            file: Some(log_path.to_string_lossy().into_owned()),
            file_format: LogFileFormat::Raw,
            file_max_size_mb: 1,
            file_max_backups: 2,
            file_max_age_days: 1,
            file_compress: false,
        };
        let payload = "A".repeat(600_000);
        let mut logger = RuntimeLogger::open(settings).expect("open runtime logger");
        for message in ["rotate-one", "rotate-two", "rotate-three"] {
            logger
                .write_event(
                    &LogEvent::new(LogLevel::Info, format!("{message} {payload}"))
                        .with_caller("rotate.go:1"),
                )
                .expect("write log event");
        }
        drop(logger);

        let mut names = std::fs::read_dir(&dir)
            .expect("read log dir")
            .map(|entry| {
                entry
                    .expect("dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        names.sort();
        assert!(names.contains(&"zuicity.log".to_owned()), "names={names:?}");
        let backups = names
            .iter()
            .filter(|name| {
                name.starts_with("zuicity-")
                    && name.ends_with(".log")
                    && name.len() > "zuicity-.log".len()
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 2, "names={names:?}");
        let active = std::fs::read_to_string(&log_path).expect("read active log");
        assert!(active.contains("rotate-three"), "active log was {active:?}");
    }

    #[test]
    fn top_level_help_matches_upstream_visible_sections() {
        let client_help = ClientCli::command().render_long_help().to_string();
        assert!(
            client_help.contains("Usage:\n  zuicity-client [command]"),
            "client help: {client_help:?}"
        );
        assert!(
            client_help.contains("Available Commands:"),
            "client help: {client_help:?}"
        );
        assert!(
            client_help.contains("help        Help about any command"),
            "client help: {client_help:?}"
        );
        assert!(
            client_help.contains("run         To run zuicity-client in the foreground."),
            "client help: {client_help:?}"
        );
        assert!(
            client_help.contains("Flags:\n  -h, --help      help for zuicity-client\n  -v, --version   version for zuicity-client"),
            "client help: {client_help:?}"
        );
        assert!(
            client_help.contains(
                "Use \"zuicity-client [command] --help\" for more information about a command."
            ),
            "client help: {client_help:?}"
        );

        let server_help = ServerCli::command().render_long_help().to_string();
        assert!(
            server_help.contains("Usage:\n  zuicity-server [command]"),
            "server help: {server_help:?}"
        );
        assert!(
            server_help.contains("Available Commands:"),
            "server help: {server_help:?}"
        );
        assert!(
            server_help.contains(
                "generate-certchain-hash To generate the hash of a full chain certificate."
            ),
            "server help: {server_help:?}"
        );
        assert!(
            server_help
                .contains("run                     To run zuicity-server in the foreground."),
            "server help: {server_help:?}"
        );
        assert!(
            server_help.contains("Flags:\n  -h, --help      help for zuicity-server\n  -v, --version   version for zuicity-server"),
            "server help: {server_help:?}"
        );
        assert!(
            server_help.contains(
                "Use \"zuicity-server [command] --help\" for more information about a command."
            ),
            "server help: {server_help:?}"
        );
    }

    #[test]
    fn run_help_matches_upstream_visible_sections() {
        let mut client_command = ClientCli::command();
        let client_help = client_command
            .find_subcommand_mut("run")
            .expect("client run subcommand")
            .render_long_help()
            .to_string();
        assert!(
            client_help.contains(
                "To run zuicity-client in the foreground.\n\nUsage:\n  zuicity-client run [flags]"
            ),
            "client run help: {client_help:?}"
        );
        assert!(
            client_help
                .contains("Flags:\n  -c, --config string              specify config file path"),
            "client run help: {client_help:?}"
        );
        assert!(
            client_help.contains(
                "      --disable-timestamp          deprecated; use log-disable-timestamp instead"
            ),
            "client run help: {client_help:?}"
        );
        assert!(
            client_help.contains("  -h, --help                       help for run"),
            "client run help: {client_help:?}"
        );
        assert!(
            client_help.contains("      --log-file string            log file path to write (default \"/var/log/zuicity-client.log\")"),
            "client run help: {client_help:?}"
        );
        assert!(
            client_help.contains("      --log-file-compress          enable log compression; default: true (default true)"),
            "client run help: {client_help:?}"
        );
        assert!(
            client_help.contains("      --log-output string          specify the log outputs; options: [console|file|console,file] (default \"console\")"),
            "client run help: {client_help:?}"
        );

        let mut server_command = ServerCli::command();
        let server_help = server_command
            .find_subcommand_mut("run")
            .expect("server run subcommand")
            .render_long_help()
            .to_string();
        assert!(
            server_help.contains(
                "To run zuicity-server in the foreground.\n\nUsage:\n  zuicity-server run [flags]"
            ),
            "server run help: {server_help:?}"
        );
        assert!(
            server_help
                .contains("Flags:\n  -c, --config string              specify config file path"),
            "server run help: {server_help:?}"
        );
        assert!(
            server_help.contains("  -h, --help                       help for run"),
            "server run help: {server_help:?}"
        );
        assert!(
            server_help.contains("      --log-file string            log file path to write (default \"/var/log/zuicity-client.log\")"),
            "server run help: {server_help:?}"
        );
        assert!(
            server_help.contains("      --log-output string          specify the log outputs; options: [console|file|console,file] (default \"console\")"),
            "server run help: {server_help:?}"
        );
    }

    #[test]
    fn server_helper_help_matches_upstream_visible_sections() {
        let mut server_command = ServerCli::command();
        let certchain_help = server_command
            .find_subcommand_mut("generate-certchain-hash")
            .expect("generate-certchain-hash subcommand")
            .render_long_help()
            .to_string();
        assert!(
            certchain_help.contains(
                "To generate the hash of a full chain certificate.\n\nUsage:\n  zuicity-server generate-certchain-hash [fullchain_file]"
            ),
            "certchain help: {certchain_help:?}"
        );
        assert!(
            certchain_help.contains("Flags:\n  -h, --help   help for generate-certchain-hash"),
            "certchain help: {certchain_help:?}"
        );

        let mut server_command = ServerCli::command();
        let sharelink_help = server_command
            .find_subcommand_mut("generate-sharelink")
            .expect("generate-sharelink subcommand")
            .render_long_help()
            .to_string();
        assert!(
            sharelink_help.contains(
                "To generate the sharelink from the config file.\n\nUsage:\n  zuicity-server generate-sharelink [config_file]"
            ),
            "sharelink help: {sharelink_help:?}"
        );
        assert!(
            sharelink_help
                .contains("Flags:\n  -c, --config string              specify config file path"),
            "sharelink help: {sharelink_help:?}"
        );
        assert!(
            sharelink_help
                .contains("  -h, --help                       help for generate-sharelink"),
            "sharelink help: {sharelink_help:?}"
        );
        assert!(
            sharelink_help.contains("      --log-file string            log file path to write (default \"/var/log/zuicity-client.log\")"),
            "sharelink help: {sharelink_help:?}"
        );
        assert!(
            sharelink_help.contains("      --log-output string          specify the log outputs; options: [console|file|console,file] (default \"console\")"),
            "sharelink help: {sharelink_help:?}"
        );
    }

    #[test]
    fn server_helper_positional_parser_matches_upstream_shape() {
        let cli = ServerCli::try_parse_from(["zuicity-server", "generate-certchain-hash"])
            .expect("upstream defers missing fullchain_file to runtime help");
        match cli.command {
            ServerCommand::GenerateCertchainHash { fullchain_file } => {
                assert!(fullchain_file.is_empty());
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let cli = ServerCli::try_parse_from([
            "zuicity-server",
            "generate-certchain-hash",
            "/tmp/a.pem",
            "/tmp/b.pem",
        ])
        .expect("upstream accepts extra positional args and uses args[0]");
        match cli.command {
            ServerCommand::GenerateCertchainHash { fullchain_file } => {
                assert_eq!(fullchain_file, vec!["/tmp/a.pem", "/tmp/b.pem"]);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let cli = ServerCli::try_parse_from([
            "zuicity-server",
            "generate-sharelink",
            "/tmp/positional-config.json",
        ])
        .expect("upstream accepts positional config_file even though runtime uses -c/--config");
        match cli.command {
            ServerCommand::GenerateSharelink { config_file, args } => {
                assert_eq!(config_file.as_deref(), Some("/tmp/positional-config.json"));
                assert!(args.config.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn top_level_version_flags_match_upstream_surface() {
        for (mut command, binary_name) in [
            (ClientCli::command(), "zuicity-client"),
            (ServerCli::command(), "zuicity-server"),
        ] {
            let err = command
                .try_get_matches_from_mut([binary_name, "--version"])
                .unwrap_err();
            assert_eq!(err.kind(), ErrorKind::DisplayVersion, "{binary_name}");
            let rendered = err.to_string();
            assert!(
                rendered.starts_with(&format!(
                    "{binary_name} version {}",
                    env!("ZUICITY_BUILD_VERSION")
                )),
                "{binary_name} version output: {rendered:?}"
            );
            assert!(
                rendered.contains(&format!(
                    "\nrust runtime {} {}/{}\n",
                    env!("ZUICITY_RUSTC_VERSION"),
                    env!("ZUICITY_TARGET_OS"),
                    env!("ZUICITY_TARGET_ARCH")
                )),
                "{binary_name} version output: {rendered:?}"
            );
            assert!(
                rendered.contains("\nCGO_ENABLED: 0\n"),
                "{binary_name} version output: {rendered:?}"
            );
            assert!(
                rendered.contains("License GNU AGPLv3"),
                "{binary_name} version output: {rendered:?}"
            );
        }
    }
}
