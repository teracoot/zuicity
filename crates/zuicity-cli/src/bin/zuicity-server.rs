//! zuicity-server CLI entrypoint.

use std::{
    io::{Cursor, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    time::Duration,
};

use clap::{CommandFactory, Parser};
use tracing_subscriber::prelude::*;
use url::{Url, form_urlencoded};
use x509_parser::pem::parse_x509_pem;
use zuicity_cli::{
    DefaultRuntimeLogger, LogArgs, LogEvent, LogLevel, RuntimeTracingLayer,
    RuntimeTracingLoggerHandle, ServerCli, ServerCommand, default_console_logger,
    format_read_config_decode_error, zuicity_runtime_worker_threads,
};
use zuicity_config::{
    ConfigError, FwmarkParseErrorKind, RawConfig, ServerConfig, load_json_str, validate_server,
};
use zuicity_protocol::generate_cert_chain_hash_base64_from_pem;
use zuicity_server::{ServerRuntime, ServerRuntimeConfig};

const DNS_QUERY_ID: u16 = 0x4a43;
const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const MYIP_OPENDNS_QNAME: &[&str] = &["myip", "opendns", "com"];

fn main() -> anyhow::Result<()> {
    let cli = ServerCli::parse();
    match cli.command {
        ServerCommand::Run(args) => run_server(args),
        ServerCommand::GenerateCertchainHash { fullchain_file } => {
            let Some(first_fullchain_file) = fullchain_file.first() else {
                // Upstream prints this command's help and exits non-zero when no path is supplied.
                let mut command = ServerCli::command();
                command
                    .find_subcommand_mut("generate-certchain-hash")
                    .expect("generate-certchain-hash subcommand")
                    .print_help()?;
                std::process::exit(1);
            };
            let pem = match std::fs::read(first_fullchain_file) {
                Ok(pem) => pem,
                Err(err) => {
                    let mut stdout = std::io::stdout().lock();
                    writeln!(
                        stdout,
                        "open {}: {}",
                        first_fullchain_file,
                        format_io_error(err)
                    )?;
                    return Ok(());
                }
            };
            let hash = generate_cert_chain_hash_base64_from_pem(&pem)?;
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "{hash}")?;
            Ok(())
        }
        ServerCommand::GenerateSharelink { args, .. } => run_generate_sharelink(args),
    }
}

fn run_generate_sharelink(args: LogArgs) -> anyhow::Result<()> {
    match generate_sharelink(&args) {
        Ok(link) => {
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "{link}")?;
            Ok(())
        }
        Err(message) => {
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "{message}")?;
            std::process::exit(1);
        }
    }
}

fn generate_sharelink(args: &LogArgs) -> Result<String, String> {
    let Some(config_path) = args.config.as_deref() else {
        return Err("argument \"--config\" or \"-c\" is required but not provided".to_owned());
    };

    let raw_config = read_server_config_for_sharelink(config_path)?;
    let server_config = validate_server(raw_config).map_err(|err| err.to_string())?;
    let (_host, port) = split_listen_port(&server_config.raw.listen)
        .map_err(|err| format!("parse 'listen': {err}"))?;
    let Some((uuid, password)) = server_config.users.iter().next() else {
        return Err("no users".to_owned());
    };

    let (cert_pem, common_name) = read_certificate_and_common_name(&server_config.raw.certificate)?;
    validate_private_key(&server_config.raw.private_key)?;
    let pinned_hash = generate_cert_chain_hash_base64_from_pem(&cert_pem).map_err(|err| {
        format!(
            "generateCertChainHash: {}",
            err.to_string().to_ascii_lowercase()
        )
    })?;
    let public_ip = lookup_public_ipv4_opendns()?;

    build_sharelink(
        uuid.to_string().as_str(),
        password,
        public_ip,
        port,
        &common_name,
        &pinned_hash,
    )
}

fn read_server_config_for_sharelink(
    config_path: &str,
) -> Result<zuicity_config::RawConfig, String> {
    let data = std::fs::read_to_string(config_path)
        .map_err(|err| format!("ReadConfig: {}", format_open_error(config_path, err)))?;
    load_json_str(&data).map_err(|err| {
        format!(
            "ReadConfig: {}",
            format_read_config_decode_error(&data, err)
        )
    })
}

fn read_certificate_and_common_name(path: &str) -> Result<(Vec<u8>, String), String> {
    let pem = std::fs::read(path).map_err(|err| format_open_error(path, err))?;
    let (_, block) = parse_x509_pem(&pem).map_err(|err| err.to_string())?;
    let cert = block.parse_x509().map_err(|err| err.to_string())?;
    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("")
        .to_owned();
    Ok((pem, common_name))
}

fn validate_private_key(path: &str) -> Result<(), String> {
    let key = std::fs::read(path).map_err(|err| format_open_error(path, err))?;
    let mut reader = Cursor::new(key);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "tls: failed to find any PEM data in key input".to_owned())?;
    Ok(())
}

fn build_sharelink(
    uuid: &str,
    password: &str,
    public_ip: Ipv4Addr,
    port: &str,
    common_name: &str,
    pinned_hash: &str,
) -> Result<String, String> {
    let mut url = Url::parse(&format!("juicity://{public_ip}:{port}"))
        .map_err(|err| format!("parse sharelink url: {err}"))?;
    url.set_username(uuid)
        .map_err(|_| "set sharelink username".to_owned())?;
    url.set_password(Some(password))
        .map_err(|_| "set sharelink password".to_owned())?;

    let mut query = form_urlencoded::Serializer::new(String::new());
    query.append_pair("allow_insecure", "1");
    query.append_pair("congestion_control", "bbr");
    query.append_pair("pinned_certchain_sha256", pinned_hash);
    query.append_pair("sni", common_name);
    let query = query.finish();
    url.set_query(Some(&query));
    Ok(url.to_string())
}

fn lookup_public_ipv4_opendns() -> Result<Ipv4Addr, String> {
    let query = build_dns_a_query(DNS_QUERY_ID, MYIP_OPENDNS_QNAME)?;
    let resolver = SocketAddr::from(([208, 67, 222, 222], 53));
    let mut stream = TcpStream::connect_timeout(&resolver, DNS_TIMEOUT)
        .map_err(|err| format!("lookup myip.opendns.com: {err}"))?;
    stream
        .set_read_timeout(Some(DNS_TIMEOUT))
        .map_err(|err| format!("lookup myip.opendns.com: {err}"))?;
    stream
        .set_write_timeout(Some(DNS_TIMEOUT))
        .map_err(|err| format!("lookup myip.opendns.com: {err}"))?;

    let query_len = u16::try_from(query.len()).map_err(|_| "dns query too large".to_owned())?;
    stream
        .write_all(&query_len.to_be_bytes())
        .and_then(|()| stream.write_all(&query))
        .map_err(|err| format!("lookup myip.opendns.com: {err}"))?;

    let mut len = [0_u8; 2];
    stream
        .read_exact(&mut len)
        .map_err(|err| format!("lookup myip.opendns.com: {err}"))?;
    let response_len = u16::from_be_bytes(len) as usize;
    let mut response = vec![0_u8; response_len];
    stream
        .read_exact(&mut response)
        .map_err(|err| format!("lookup myip.opendns.com: {err}"))?;
    parse_dns_a_response(&response, DNS_QUERY_ID)
}

fn build_dns_a_query(id: u16, labels: &[&str]) -> Result<Vec<u8>, String> {
    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    for label in labels {
        let len = u8::try_from(label.len()).map_err(|_| "dns label too long".to_owned())?;
        query.push(len);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    Ok(query)
}

fn parse_dns_a_response(response: &[u8], expected_id: u16) -> Result<Ipv4Addr, String> {
    if response.len() < 12 {
        return Err("lookup myip.opendns.com: short dns response".to_owned());
    }
    let id = u16::from_be_bytes([response[0], response[1]]);
    if id != expected_id {
        return Err("lookup myip.opendns.com: mismatched dns response".to_owned());
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_dns_name(response, offset)?;
        if offset + 4 > response.len() {
            return Err("lookup myip.opendns.com: truncated dns question".to_owned());
        }
        offset += 4;
    }
    for _ in 0..ancount {
        offset = skip_dns_name(response, offset)?;
        if offset + 10 > response.len() {
            return Err("lookup myip.opendns.com: truncated dns answer".to_owned());
        }
        let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let record_class = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
        let rdlength = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlength > response.len() {
            return Err("lookup myip.opendns.com: truncated dns rdata".to_owned());
        }
        if record_type == 1 && record_class == 1 && rdlength == 4 {
            return Ok(Ipv4Addr::new(
                response[offset],
                response[offset + 1],
                response[offset + 2],
                response[offset + 3],
            ));
        }
        offset += rdlength;
    }
    Err("lookup myip.opendns.com: no address".to_owned())
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> Result<usize, String> {
    for _ in 0..128 {
        let Some(&len) = packet.get(offset) else {
            return Err("lookup myip.opendns.com: truncated dns name".to_owned());
        };
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= packet.len() {
                return Err("lookup myip.opendns.com: truncated dns pointer".to_owned());
            }
            return Ok(offset + 2);
        }
        if len == 0 {
            return Ok(offset + 1);
        }
        offset = offset
            .checked_add(1 + usize::from(len))
            .ok_or_else(|| "lookup myip.opendns.com: dns name overflow".to_owned())?;
        if offset > packet.len() {
            return Err("lookup myip.opendns.com: truncated dns label".to_owned());
        }
    }
    Err("lookup myip.opendns.com: dns name pointer loop".to_owned())
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

fn split_listen_port(value: &str) -> Result<(&str, &str), &'static str> {
    if let Some(rest) = value.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err("missing ']' in address");
        };
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let Some(port) = after.strip_prefix(':') else {
            return Err("missing port in address");
        };
        if port.is_empty() {
            return Err("missing port in address");
        }
        return Ok((host, port));
    }

    let Some((host, port)) = value.rsplit_once(':') else {
        return Err("missing port in address");
    };
    if port.is_empty() {
        return Err("missing port in address");
    }
    Ok((host, port))
}

fn run_server(args: LogArgs) -> anyhow::Result<()> {
    let raw_config = match load_server_raw_config(&args) {
        Ok(config) => config,
        Err(err) => fatal_server_config_error(&err),
    };
    let mut logger = match args.runtime_logger(&raw_config.log_level) {
        Ok(logger) => logger,
        Err(err) => fatal_server_logger_init_error(&err.to_string()),
    };
    let config = match validate_server(raw_config) {
        Ok(config) => config,
        Err(ConfigError::InvalidUserUuid { uuid, .. }) => {
            fatal_server_serve_error(&mut logger, &format_upstream_user_uuid_parse_error(&uuid))
        }
        Err(ConfigError::InvalidFwmark { value, kind }) => fatal_server_serve_error(
            &mut logger,
            &format_upstream_fwmark_parse_error(&value, &kind),
        ),
        Err(ConfigError::InvalidSendThrough { value, .. }) => fatal_server_serve_error(
            &mut logger,
            &format_upstream_send_through_parse_error(&value),
        ),
        Err(err) => fatal_server_config_error(&err.to_string()),
    };
    // Upstream loads the certificate and private key inside `Serve(conf)` via
    // `tls.LoadX509KeyPair`, which reads the certificate file first and then the
    // key file. Surface missing files at the same runtime fatal site (run.go:49)
    // with Go's `open <path>: no such file or directory` text.
    let cert_pem = match std::fs::read(&config.raw.certificate) {
        Ok(bytes) => bytes,
        Err(err) => fatal_server_serve_error(
            &mut logger,
            &format_open_error(&config.raw.certificate, err),
        ),
    };
    let key_pem = match std::fs::read(&config.raw.private_key) {
        Ok(bytes) => bytes,
        Err(err) => fatal_server_serve_error(
            &mut logger,
            &format_open_error(&config.raw.private_key, err),
        ),
    };
    if config.raw.listen.is_empty() {
        fatal_server_serve_error(&mut logger, r#""Listen" is required"#);
    }
    let (layer, logger) = RuntimeTracingLayer::new(logger);
    let subscriber = tracing_subscriber::registry().with(layer);
    if let Err(err) = tracing::subscriber::set_global_default(subscriber) {
        fatal_server_logger_init_error(&err.to_string());
    }
    match run_server_runtime(config, cert_pem, key_pem, logger.clone()) {
        Ok(()) => Ok(()),
        Err(err) => fatal_server_runtime_error(&logger, &err.to_string()),
    }
}

fn run_server_runtime(
    config: ServerConfig,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    logger: RuntimeTracingLoggerHandle,
) -> anyhow::Result<()> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if let Some(threads) = zuicity_runtime_worker_threads() {
        builder.worker_threads(threads);
    }
    builder
        .enable_all()
        .build()?
        .block_on(run_server_runtime_async(config, cert_pem, key_pem, logger))
}

async fn run_server_runtime_async(
    config: ServerConfig,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    logger: RuntimeTracingLoggerHandle,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = config.raw.listen.parse()?;
    let runtime = ServerRuntime::new(ServerRuntimeConfig::from_config(config));
    let bound = runtime.bind_with_pem(listen_addr, &cert_pem, &key_pem)?;
    let shutdown = server_shutdown_signal()?;

    bound.run_proxy_loop_until(shutdown).await?;
    write_server_exit_log(&logger, "run.go:43");
    Ok(())
}

type ShutdownFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

#[cfg(unix)]
fn server_shutdown_signal() -> std::io::Result<ShutdownFuture> {
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
fn server_shutdown_signal() -> std::io::Result<ShutdownFuture> {
    Ok(Box::pin(async {
        let _ = tokio::signal::ctrl_c().await;
    }))
}

fn load_server_raw_config(args: &LogArgs) -> Result<RawConfig, String> {
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

fn write_server_exit_log(logger: &RuntimeTracingLoggerHandle, caller: &str) {
    let event = LogEvent::new(LogLevel::Warn, "Exiting").with_caller(caller);
    let _ = logger.write_event(&event);
}

fn fatal_server_config_error(error: &str) -> ! {
    fatal_server_with_default_logger("run.go:35", "Failed to read config", error)
}

fn fatal_server_logger_init_error(error: &str) -> ! {
    fatal_server_with_default_logger("run.go:39", "Failed to init logger", error)
}

fn fatal_server_runtime_error(logger: &RuntimeTracingLoggerHandle, error: &str) -> ! {
    let event =
        LogEvent::new(LogLevel::Fatal, format!("error=\"{error}\"")).with_caller("run.go:42");
    let _ = logger.write_event(&event);
    std::process::exit(1);
}

fn fatal_server_serve_error(logger: &mut DefaultRuntimeLogger, error: &str) -> ! {
    let event =
        LogEvent::new(LogLevel::Fatal, format!(r#"error="{error}""#)).with_caller("run.go:49");
    let _ = logger.write_event(&event);
    std::process::exit(1);
}

fn format_upstream_user_uuid_parse_error(uuid: &str) -> String {
    match uuid.len() {
        32 | 36 | 38 | 45 => format!("parse uuid({uuid}): invalid UUID format"),
        len => format!("parse uuid({uuid}): invalid UUID length: {len}"),
    }
}

fn format_upstream_fwmark_parse_error(value: &str, kind: &FwmarkParseErrorKind) -> String {
    format!(r#"parse fwmark: strconv.ParseUint: parsing "{value}": {kind}"#)
}

fn format_upstream_send_through_parse_error(value: &str) -> String {
    format!(r#"parse send_through: ParseAddr("{value}"): unable to parse IP"#)
}

fn fatal_server_with_default_logger(caller: &str, message: &str, error: &str) -> ! {
    let mut logger = default_console_logger();
    let event =
        LogEvent::new(LogLevel::Fatal, format!("{message} error=\"{error}\"")).with_caller(caller);
    let _ = logger.write_event(&event);
    std::process::exit(1);
}
