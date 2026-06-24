//! zuicity-client CLI entrypoint.

use clap::Parser;
use tracing_subscriber::prelude::*;
use zuicity_cli::{
    ClientCli, ClientCommand, DefaultRuntimeLogger, LogArgs, LogEvent, LogLevel,
    RuntimeTracingLayer, RuntimeTracingLoggerHandle, default_console_logger,
    format_read_config_decode_error, zuicity_runtime_worker_threads,
};
use zuicity_client::{ClientRuntime, ClientRuntimeConfig};
use zuicity_config::{ClientConfig, ConfigError, RawConfig, load_json_str, validate_client};
use zuicity_transport::{StreamPolicy, TlsPolicy};

fn main() -> anyhow::Result<()> {
    let cli = ClientCli::parse();
    match cli.command {
        ClientCommand::Run(args) => run_client(args),
    }
}

fn run_client(args: LogArgs) -> anyhow::Result<()> {
    let raw_config = match load_client_raw_config(&args) {
        Ok(config) => config,
        Err(err) => fatal_config_error(&err),
    };
    let mut logger = match args.runtime_logger(&raw_config.log_level) {
        Ok(logger) => logger,
        Err(err) => fatal_logger_init_error(&err.to_string()),
    };
    let client_uuid = raw_config.uuid.clone();
    let config = match validate_client(raw_config) {
        Ok(config) => config,
        Err(ConfigError::InvalidPinnedCertChainSha256) => {
            fatal_client_serve_error(&mut logger, "failed to decode PinnedCertChainSha256")
        }
        Err(ConfigError::Uuid(_)) => {
            fatal_client_serve_error(&mut logger, &format_upstream_uuid_parse_error(&client_uuid))
        }
        Err(err) => fatal_config_error(&err.to_string()),
    };
    if config.raw.listen.is_empty() && config.raw.forward.is_empty() {
        fatal_missing_entrypoint_error(&mut logger);
    }
    let (layer, logger) = RuntimeTracingLayer::new(logger);
    let subscriber = tracing_subscriber::registry().with(layer);
    if let Err(err) = tracing::subscriber::set_global_default(subscriber) {
        fatal_logger_init_error(&err.to_string());
    }
    match run_client_runtime(config, logger.clone()) {
        Ok(()) => Ok(()),
        Err(err) => fatal_runtime_error(&logger, &err.to_string()),
    }
}

fn run_client_runtime(
    config: ClientConfig,
    logger: RuntimeTracingLoggerHandle,
) -> anyhow::Result<()> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if let Some(threads) = zuicity_runtime_worker_threads() {
        builder.worker_threads(threads);
    }
    builder
        .enable_all()
        .build()?
        .block_on(run_client_runtime_async(config, logger))
}

async fn run_client_runtime_async(
    config: ClientConfig,
    logger: RuntimeTracingLoggerHandle,
) -> anyhow::Result<()> {
    let shutdown = client_shutdown_signal()?;
    let runtime = ClientRuntime::new(ClientRuntimeConfig {
        config,
        tls: TlsPolicy::upstream(),
        streams: StreamPolicy::upstream(),
    });
    let mixed_listener = runtime
        .bind_configured_mixed_listener_with_roots(&[])
        .await?;
    let tcp_forwarders = runtime
        .bind_configured_tcp_forwarders_with_roots(&[])
        .await?;
    let udp_forwarders = runtime
        .bind_configured_udp_forwarders_with_roots(&[])
        .await?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut tasks = tokio::task::JoinSet::new();
    if let Some(listener) = mixed_listener {
        let shutdown_rx = shutdown_rx.clone();
        tasks.spawn(async move {
            listener
                .run_loop_until(wait_for_client_runtime_shutdown(shutdown_rx))
                .await
                .map(|_| ())
        });
    }
    for forwarder in tcp_forwarders {
        let shutdown_rx = shutdown_rx.clone();
        tasks.spawn(async move {
            forwarder
                .run_tcp_forward_loop_until(wait_for_client_runtime_shutdown(shutdown_rx))
                .await
                .map(|_| ())
        });
    }
    for forwarder in udp_forwarders {
        let shutdown_rx = shutdown_rx.clone();
        tasks.spawn(async move {
            forwarder
                .run_udp_forward_loop_until(wait_for_client_runtime_shutdown(shutdown_rx))
                .await
                .map(|_| ())
        });
    }

    if tasks.is_empty() {
        shutdown.await;
        write_exit_log(&logger, "run.go:65");
        return Ok(());
    }

    tokio::select! {
        () = shutdown => {
            write_exit_log(&logger, "run.go:72");
            let _ = shutdown_tx.send(true);
            while let Some(joined) = tasks.join_next().await {
                match joined {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => return Err(err.into()),
                    Err(err) => return Err(err.into()),
                }
            }
            Ok(())
        }
        joined = tasks.join_next() => match joined {
            Some(Ok(Ok(()))) => anyhow::bail!("zuicity-client runtime task exited unexpectedly"),
            Some(Ok(Err(err))) => Err(err.into()),
            Some(Err(err)) => Err(err.into()),
            None => Ok(()),
        },
    }
}

async fn wait_for_client_runtime_shutdown(mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

type ShutdownFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

#[cfg(unix)]
fn client_shutdown_signal() -> std::io::Result<ShutdownFuture> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigquit = signal(SignalKind::quit())?;
    let mut sigill = signal(SignalKind::from_raw(4)).ok();

    Ok(Box::pin(async move {
        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
            _ = sighup.recv() => {}
            _ = sigquit.recv() => {}
            _ = async {
                if let Some(sigill) = sigill.as_mut() {
                    let _ = sigill.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
        }
    }))
}

#[cfg(not(unix))]
fn client_shutdown_signal() -> std::io::Result<ShutdownFuture> {
    Ok(Box::pin(async {
        let _ = tokio::signal::ctrl_c().await;
    }))
}

fn load_client_raw_config(args: &LogArgs) -> Result<RawConfig, String> {
    let Some(path) = args.config.as_deref() else {
        return Err("argument \"--config\" or \"-c\" is required but not provided".to_owned());
    };
    let data = std::fs::read_to_string(path)
        .map_err(|err| format!("ReadConfig: {}", format_open_error(path, err)))?;
    load_json_str(&data).map_err(|err| {
        format!(
            "ReadConfig: {}",
            format_read_config_decode_error(&data, err)
        )
    })
}

fn write_exit_log(logger: &RuntimeTracingLoggerHandle, caller: &str) {
    let event = LogEvent::new(LogLevel::Warn, "Exiting").with_caller(caller);
    let _ = logger.write_event(&event);
}

fn fatal_config_error(error: &str) -> ! {
    fatal_with_default_logger("run.go:50", "Failed to read config", error)
}

fn fatal_logger_init_error(error: &str) -> ! {
    fatal_with_default_logger("run.go:54", "Failed to init logger", error)
}

fn fatal_missing_entrypoint_error(logger: &mut DefaultRuntimeLogger) -> ! {
    let event = LogEvent::new(
        LogLevel::Fatal,
        "Please fill in at least one of `listen` and `forward` in the config file.",
    )
    .with_caller("run.go:118");
    let _ = logger.write_event(&event);
    std::process::exit(1);
}

fn fatal_client_serve_error(logger: &mut DefaultRuntimeLogger, error: &str) -> ! {
    let event =
        LogEvent::new(LogLevel::Fatal, format!(r#"error="{error}""#)).with_caller("run.go:63");
    let _ = logger.write_event(&event);
    std::process::exit(1);
}

fn format_upstream_uuid_parse_error(uuid: &str) -> String {
    match uuid.len() {
        32 | 36 | 38 | 45 => "parse UUID: invalid UUID format".to_owned(),
        len => format!("parse UUID: invalid UUID length: {len}"),
    }
}

fn fatal_runtime_error(logger: &RuntimeTracingLoggerHandle, error: &str) -> ! {
    let event =
        LogEvent::new(LogLevel::Fatal, format!("error=\"{error}\"")).with_caller("run.go:61");
    let _ = logger.write_event(&event);
    std::process::exit(1);
}

fn fatal_with_default_logger(caller: &str, message: &str, error: &str) -> ! {
    let mut logger = default_console_logger();
    let event =
        LogEvent::new(LogLevel::Fatal, format!("{message} error=\"{error}\"")).with_caller(caller);
    let _ = logger.write_event(&event);
    std::process::exit(1);
}

fn format_open_error(path: &str, err: std::io::Error) -> String {
    format!("open {path}: {}", format_io_error(err))
}

fn format_io_error(err: std::io::Error) -> String {
    match err.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".to_owned(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_owned(),
        _ => err.to_string().to_ascii_lowercase(),
    }
}
