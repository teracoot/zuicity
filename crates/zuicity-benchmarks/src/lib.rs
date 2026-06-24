//! Shared fixtures for Zuicity benchmark harnesses.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

/// Current process memory sample for benchmark artifact runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessMemorySnapshot {
    /// Resident set size in kibibytes.
    pub resident_set_kib: u64,
}

/// Reads the current process resident set size for benchmark artifact evidence.
pub fn current_process_memory_snapshot() -> anyhow::Result<ProcessMemorySnapshot> {
    current_process_memory_snapshot_impl()
}

#[cfg(target_os = "linux")]
fn current_process_memory_snapshot_impl() -> anyhow::Result<ProcessMemorySnapshot> {
    let status = std::fs::read_to_string("/proc/self/status").context("read /proc/self/status")?;
    let rss_line = status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .context("find VmRSS in /proc/self/status")?;
    let mut fields = rss_line.split_whitespace();
    let label = fields.next().context("parse VmRSS label")?;
    ensure!(label == "VmRSS:", "unexpected VmRSS label {label}");
    let value = fields
        .next()
        .context("parse VmRSS value")?
        .parse::<u64>()
        .context("parse VmRSS value as KiB")?;
    let unit = fields.next().context("parse VmRSS unit")?;
    ensure!(unit == "kB", "unexpected VmRSS unit {unit}");
    ensure!(value > 0, "VmRSS value must be non-zero");
    Ok(ProcessMemorySnapshot {
        resident_set_kib: value,
    })
}

#[cfg(not(target_os = "linux"))]
fn current_process_memory_snapshot_impl() -> anyhow::Result<ProcessMemorySnapshot> {
    anyhow::bail!("current-process RSS memory snapshot is only implemented on Linux")
}

use anyhow::{Context, ensure};
use zuicity_client::{ClientRuntime, ClientRuntimeConfig, MixedProtocol, TcpForwardTarget};
use zuicity_config::{ClientConfig, ConfigError, RawConfig, ServerConfig, load_json_str};
use zuicity_dae::{DaeJuicityConnector, DaeMetricsSnapshot, DaeOutboundConfig};
use zuicity_server::{BoundServerRuntime, ServerRuntime, ServerRuntimeConfig};
use zuicity_transport::{AuthenticatedConnection, JuicityQuicClient};

/// Shared benchmark password.
pub const BENCH_PASSWORD: &str = "benchmark password";
/// Shared benchmark UUID string.
pub const BENCH_UUID_STR: &str = "00000000-0000-0000-0000-000000000001";
/// Default timeout for live benchmark smoke operations.
pub const LIVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Client JSON fixture with both mixed listener and forward entries.
#[must_use]
pub fn client_json_fixture() -> &'static str {
    r#"{
        "listen":"127.0.0.1:1080",
        "server":"127.0.0.1:23182",
        "uuid":"00000000-0000-0000-0000-000000000001",
        "password":"benchmark password",
        "sni":"localhost",
        "allow_insecure":true,
        "forward":{"127.0.0.1:10000/tcp":"127.0.0.1:22","127.0.0.1:10001/udp":"127.0.0.1:53"},
        "congestion_control":"bbr",
        "pinned_certchain_sha256":"AQID"
    }"#
}

/// Server JSON fixture using the shared benchmark credential.
#[must_use]
pub fn server_json_fixture() -> &'static str {
    r#"{
        "listen":"127.0.0.1:23182",
        "users":{"00000000-0000-0000-0000-000000000001":"benchmark password"},
        "certificate":"fullchain.pem",
        "private_key":"private.key",
        "congestion_control":"bbr",
        "fwmark":"0x20",
        "send_through":"127.0.0.1"
    }"#
}

/// Parses the client JSON fixture without validation.
pub fn parse_client_fixture() -> Result<RawConfig, ConfigError> {
    load_json_str(client_json_fixture())
}

/// Parses the server JSON fixture without validation.
pub fn parse_server_fixture() -> Result<RawConfig, ConfigError> {
    load_json_str(server_json_fixture())
}

/// Parses and validates the client benchmark fixture.
pub fn validated_client_fixture() -> Result<ClientConfig, ConfigError> {
    zuicity_config::validate_client(parse_client_fixture()?)
}

/// Parses and validates the server benchmark fixture.
pub fn validated_server_fixture() -> Result<ServerConfig, ConfigError> {
    zuicity_config::validate_server(parse_server_fixture()?)
}

/// Live loopback server fixture used by handshake and relay benchmarks.
pub struct LiveServerFixture {
    /// Cloneable client connection parameters.
    pub client: LiveClientFixture,
    /// Bound server runtime.
    pub bound: BoundServerRuntime,
}

/// Cloneable client connection parameters for a live benchmark server.
#[derive(Clone, Debug)]
pub struct LiveClientFixture {
    /// Server certificate material trusted by benchmark clients.
    pub cert_pem: Vec<u8>,
    /// Server address.
    pub server_addr: SocketAddr,
    /// Shared benchmark UUID.
    pub uuid: uuid::Uuid,
    /// Shared benchmark password bytes.
    pub password: Vec<u8>,
}

impl LiveServerFixture {
    /// Starts a bound Rust server runtime on loopback with a generated certificate.
    pub fn start() -> anyhow::Result<Self> {
        Self::start_with_server_extra_fields("")
    }

    fn start_with_server_extra_fields(extra_fields: &str) -> anyhow::Result<Self> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .context("generate benchmark certificate")?;
        let raw = load_json_str(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}{extra_fields}}}"#,
            uuid = BENCH_UUID_STR,
            password = BENCH_PASSWORD,
            extra_fields = extra_fields,
        ))?;
        let runtime = ServerRuntime::new(ServerRuntimeConfig::from_config(
            zuicity_config::validate_server(raw)?,
        ));
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let uuid = uuid::Uuid::parse_str(BENCH_UUID_STR).context("parse benchmark uuid")?;
        Ok(Self {
            client: LiveClientFixture {
                cert_pem: cert.cert.pem().into_bytes(),
                server_addr,
                uuid,
                password: BENCH_PASSWORD.as_bytes().to_vec(),
            },
            bound,
        })
    }
}

/// Connects one authenticated Rust client to a live benchmark server.
pub async fn connect_client(
    fixture: &LiveClientFixture,
) -> anyhow::Result<AuthenticatedConnection> {
    let client = JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
    Ok(tokio::time::timeout(
        LIVE_TIMEOUT,
        client.connect_with_roots(
            fixture.server_addr,
            "localhost",
            &fixture.cert_pem,
            false,
            fixture.uuid,
            &fixture.password,
        ),
    )
    .await
    .context("client connect timed out")??)
}

/// Maximum bounded concurrency for local benchmark client helpers.
pub const CONCURRENT_TCP_CLIENT_LIMIT: usize = 32;
/// Timeout for one bounded concurrent TCP client task group.
pub const CONCURRENT_TCP_TIMEOUT: Duration = Duration::from_secs(10);

/// Summary returned by the bounded concurrent TCP client benchmark helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConcurrentTcpRunSummary {
    /// Concurrent client tasks requested.
    pub clients: usize,
    /// Requests sent by each client task.
    pub requests_per_client: usize,
    /// Total completed TCP echo requests.
    pub completed_requests: usize,
    /// Total echoed payload bytes received by all clients.
    pub bytes_echoed: usize,
}

/// Runs bounded concurrent Rust/Rust TCP echo clients through a live benchmark server.
pub async fn run_concurrent_tcp_clients(
    fixture: LiveServerFixture,
    clients: usize,
    requests_per_client: usize,
) -> anyhow::Result<ConcurrentTcpRunSummary> {
    ensure!(clients > 0, "client count must be non-zero");
    ensure!(
        clients <= CONCURRENT_TCP_CLIENT_LIMIT,
        "client count {clients} exceeds benchmark limit {CONCURRENT_TCP_CLIENT_LIMIT}"
    );
    ensure!(
        requests_per_client > 0,
        "requests per client must be non-zero"
    );

    let echo = zuicity_testkit::TcpEchoServer::start()
        .await
        .context("start concurrent TCP echo")?;
    let echo_addr = echo.local_addr();
    let client_fixture = fixture.client.clone();
    let bound = fixture.bound;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        bound
            .run_proxy_loop_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let mut tasks = tokio::task::JoinSet::new();
    for client_id in 0..clients {
        let client_fixture = client_fixture.clone();
        tasks.spawn(async move {
            tokio::time::timeout(CONCURRENT_TCP_TIMEOUT, async move {
                let mut completed_requests = 0_usize;
                let mut bytes_echoed = 0_usize;
                for request_id in 0..requests_per_client {
                    let connection = connect_client(&client_fixture).await?;
                    let payload =
                        format!("benchmark concurrent tcp client {client_id} request {request_id}")
                            .into_bytes();
                    let mut stream = connection
                        .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
                        .await
                        .context("open concurrent TCP proxy stream")?;
                    stream
                        .write_all(&payload)
                        .await
                        .context("write concurrent TCP payload")?;
                    stream.finish().context("finish concurrent TCP stream")?;
                    let echoed = stream
                        .read_to_end(payload.len() + 64)
                        .await
                        .context("read concurrent TCP echo")?;
                    ensure!(echoed == payload, "concurrent TCP echo mismatch");
                    completed_requests += 1;
                    bytes_echoed += echoed.len();
                }
                Ok::<_, anyhow::Error>((completed_requests, bytes_echoed))
            })
            .await
            .context("concurrent TCP client timed out")?
        });
    }

    let mut completed_requests = 0_usize;
    let mut bytes_echoed = 0_usize;
    let mut first_error = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok((completed, bytes))) => {
                completed_requests += completed;
                bytes_echoed += bytes;
            }
            Ok(Err(error)) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error.into());
                }
            }
        }
    }

    let _ = shutdown_tx.send(());
    let _server_report = tokio::time::timeout(CONCURRENT_TCP_TIMEOUT, server_task)
        .await
        .context("concurrent TCP server shutdown timed out")??
        .context("concurrent TCP server loop failed")?;
    echo.shutdown()
        .await
        .context("shutdown concurrent TCP echo")?;

    if let Some(error) = first_error {
        return Err(error);
    }

    Ok(ConcurrentTcpRunSummary {
        clients,
        requests_per_client,
        completed_requests,
        bytes_echoed,
    })
}

/// Maximum bounded client count for local server lifecycle churn benchmark helpers.
pub const SERVER_LIFECYCLE_CHURN_CLIENT_LIMIT: usize = 16;
/// Timeout for one bounded server lifecycle churn task group.
pub const SERVER_LIFECYCLE_CHURN_TIMEOUT: Duration = Duration::from_secs(10);

/// Summary returned by the bounded server lifecycle TCP/UDP churn helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerLifecycleChurnSummary {
    /// Concurrent TCP clients requested.
    pub tcp_clients: usize,
    /// Concurrent UDP-over-stream clients requested.
    pub udp_clients: usize,
    /// Completed TCP echo relays observed by clients.
    pub completed_tcp_relays: usize,
    /// Completed UDP echo relays observed by clients.
    pub completed_udp_relays: usize,
    /// Total echoed payload bytes received by all clients.
    pub bytes_echoed: usize,
    /// Server accepted authenticated QUIC connections.
    pub server_accepted_connections: u64,
    /// Server completed TCP proxy relays.
    pub server_completed_tcp_relays: u64,
    /// Server completed UDP-over-stream relays.
    pub server_completed_udp_relays: u64,
    /// Server bytes copied from Juicity clients to targets.
    pub server_bytes_from_client: u64,
    /// Server bytes copied from targets back to Juicity clients.
    pub server_bytes_from_target: u64,
}

/// Runs bounded concurrent TCP and UDP-over-stream clients through the combined server loop.
pub async fn run_server_lifecycle_churn(
    fixture: LiveServerFixture,
    tcp_clients: usize,
    udp_clients: usize,
) -> anyhow::Result<ServerLifecycleChurnSummary> {
    ensure!(tcp_clients > 0, "TCP client count must be non-zero");
    ensure!(udp_clients > 0, "UDP client count must be non-zero");
    ensure!(
        tcp_clients + udp_clients <= SERVER_LIFECYCLE_CHURN_CLIENT_LIMIT,
        "client count {} exceeds benchmark limit {SERVER_LIFECYCLE_CHURN_CLIENT_LIMIT}",
        tcp_clients + udp_clients
    );

    let tcp_echo = zuicity_testkit::TcpEchoServer::start()
        .await
        .context("start server lifecycle TCP echo")?;
    let udp_echo = zuicity_testkit::UdpEchoServer::start()
        .await
        .context("start server lifecycle UDP echo")?;
    let tcp_addr = tcp_echo.local_addr();
    let udp_addr = udp_echo.local_addr();
    let client_fixture = fixture.client.clone();
    let bound = fixture.bound;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        bound
            .run_proxy_loop_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let mut tasks = tokio::task::JoinSet::new();
    for client_id in 0..tcp_clients {
        let client_fixture = client_fixture.clone();
        tasks.spawn(async move {
            tokio::time::timeout(SERVER_LIFECYCLE_CHURN_TIMEOUT, async move {
                let connection = connect_client(&client_fixture).await?;
                let payload =
                    format!("benchmark server lifecycle tcp client {client_id}").into_bytes();
                let mut stream = connection
                    .open_tcp_proxy_stream(tcp_addr.ip(), tcp_addr.port())
                    .await
                    .context("open server lifecycle TCP proxy stream")?;
                stream
                    .write_all(&payload)
                    .await
                    .context("write server lifecycle TCP payload")?;
                stream
                    .finish()
                    .context("finish server lifecycle TCP stream")?;
                let echoed = stream
                    .read_to_end(payload.len() + 64)
                    .await
                    .context("read server lifecycle TCP echo")?;
                ensure!(echoed == payload, "server lifecycle TCP echo mismatch");
                Ok::<_, anyhow::Error>((true, echoed.len()))
            })
            .await
            .context("server lifecycle TCP client timed out")?
        });
    }
    for client_id in 0..udp_clients {
        let client_fixture = client_fixture.clone();
        tasks.spawn(async move {
            tokio::time::timeout(SERVER_LIFECYCLE_CHURN_TIMEOUT, async move {
                let connection = connect_client(&client_fixture).await?;
                let payload =
                    format!("benchmark server lifecycle udp client {client_id}").into_bytes();
                let mut stream = connection
                    .open_udp_over_stream(udp_addr.ip(), udp_addr.port())
                    .await
                    .context("open server lifecycle UDP-over-stream")?;
                stream
                    .send_datagram(&payload)
                    .await
                    .context("send server lifecycle UDP payload")?;
                let echoed = stream
                    .recv_datagram(payload.len() + 64)
                    .await
                    .context("read server lifecycle UDP echo")?;
                ensure!(
                    echoed.target == udp_addr,
                    "server lifecycle UDP target mismatch"
                );
                ensure!(
                    echoed.payload == payload,
                    "server lifecycle UDP echo mismatch"
                );
                stream
                    .finish()
                    .context("finish server lifecycle UDP stream")?;
                Ok::<_, anyhow::Error>((false, echoed.payload.len()))
            })
            .await
            .context("server lifecycle UDP client timed out")?
        });
    }

    let mut completed_tcp_relays = 0_usize;
    let mut completed_udp_relays = 0_usize;
    let mut bytes_echoed = 0_usize;
    let mut first_error = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok((is_tcp, bytes))) => {
                if is_tcp {
                    completed_tcp_relays += 1;
                } else {
                    completed_udp_relays += 1;
                }
                bytes_echoed += bytes;
            }
            Ok(Err(error)) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error.into());
                }
            }
        }
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = shutdown_tx.send(());
    let server_report = tokio::time::timeout(SERVER_LIFECYCLE_CHURN_TIMEOUT, server_task)
        .await
        .context("server lifecycle loop shutdown timed out")??
        .context("server lifecycle loop failed")?;
    tcp_echo
        .shutdown()
        .await
        .context("shutdown server lifecycle TCP echo")?;
    udp_echo
        .shutdown()
        .await
        .context("shutdown server lifecycle UDP echo")?;

    if let Some(error) = first_error {
        return Err(error);
    }

    ensure!(
        server_report.accepted_connections == (tcp_clients + udp_clients) as u64,
        "server lifecycle accepted connection count mismatch"
    );
    ensure!(
        server_report.completed_tcp_relays == completed_tcp_relays as u64,
        "server lifecycle TCP relay count mismatch"
    );
    ensure!(
        server_report.completed_udp_relays == completed_udp_relays as u64,
        "server lifecycle UDP relay count mismatch"
    );
    ensure!(
        server_report.bytes_from_client == bytes_echoed as u64,
        "server lifecycle client byte count mismatch"
    );
    ensure!(
        server_report.bytes_from_target == bytes_echoed as u64,
        "server lifecycle target byte count mismatch"
    );

    Ok(ServerLifecycleChurnSummary {
        tcp_clients,
        udp_clients,
        completed_tcp_relays,
        completed_udp_relays,
        bytes_echoed,
        server_accepted_connections: server_report.accepted_connections,
        server_completed_tcp_relays: server_report.completed_tcp_relays,
        server_completed_udp_relays: server_report.completed_udp_relays,
        server_bytes_from_client: server_report.bytes_from_client,
        server_bytes_from_target: server_report.bytes_from_target,
    })
}

/// Maximum bounded concurrency for local mixed-listener SOCKS5 UDP benchmark helpers.
pub const CONCURRENT_SOCKS5_UDP_ASSOCIATION_LIMIT: usize = 16;
/// Timeout for one bounded concurrent SOCKS5 UDP association task group.
pub const CONCURRENT_SOCKS5_UDP_TIMEOUT: Duration = Duration::from_secs(10);

/// Summary returned by the bounded concurrent SOCKS5 UDP association benchmark helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConcurrentSocks5UdpRunSummary {
    /// Concurrent SOCKS5 UDP associations requested.
    pub associations: usize,
    /// UDP datagrams sent through each association.
    pub datagrams_per_association: usize,
    /// Total completed UDP echo datagrams.
    pub completed_datagrams: usize,
    /// Total echoed payload bytes received by all UDP clients.
    pub bytes_echoed: usize,
    /// Mixed listener TCP control connections accepted.
    pub listener_accepted_connections: u64,
    /// Mixed listener completed SOCKS5 UDP ASSOCIATE relays.
    pub listener_completed_udp_associations: u64,
    /// Server accepted Juicity UDP-over-stream connections.
    pub server_accepted_connections: u64,
    /// Server completed UDP-over-stream relays.
    pub server_completed_udp_relays: u64,
}

/// Runs bounded concurrent SOCKS5 UDP ASSOCIATE clients through the mixed listener and Rust server.
pub async fn run_concurrent_socks5_udp_associations(
    fixture: LiveServerFixture,
    associations: usize,
    datagrams_per_association: usize,
) -> anyhow::Result<ConcurrentSocks5UdpRunSummary> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    ensure!(associations > 0, "association count must be non-zero");
    ensure!(
        associations <= CONCURRENT_SOCKS5_UDP_ASSOCIATION_LIMIT,
        "association count {associations} exceeds benchmark limit {CONCURRENT_SOCKS5_UDP_ASSOCIATION_LIMIT}"
    );
    ensure!(
        datagrams_per_association > 0,
        "datagrams per association must be non-zero"
    );

    let echo = zuicity_testkit::UdpEchoServer::start()
        .await
        .context("start concurrent SOCKS5 UDP echo")?;
    let echo_addr = echo.local_addr();
    let server_addr = fixture.client.server_addr;
    let uuid = fixture.client.uuid;
    let password = String::from_utf8(fixture.client.password.clone())
        .context("benchmark password fixture is utf8")?;
    let roots_pem = fixture.client.cert_pem.clone();
    let bound = fixture.bound;
    let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        bound
            .run_udp_over_stream_loop_until(async {
                let _ = server_shutdown_rx.await;
            })
            .await
    });

    let raw = load_json_str(&format!(
        r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"localhost"}}"#
    ))?;
    let runtime = ClientRuntime::new(ClientRuntimeConfig {
        config: zuicity_config::validate_client(raw)?,
        tls: zuicity_transport::TlsPolicy::upstream(),
        streams: zuicity_transport::StreamPolicy::upstream(),
    });
    let listener = runtime
        .bind_mixed_listener_with_roots(([127, 0, 0, 1], 0).into(), &roots_pem)
        .await
        .context("bind mixed listener for SOCKS5 UDP benchmark")?;
    let mixed_addr = listener.local_addr()?;
    let (listener_shutdown_tx, listener_shutdown_rx) = tokio::sync::oneshot::channel();
    let listener_task = tokio::spawn(async move {
        listener
            .run_loop_until(async {
                let _ = listener_shutdown_rx.await;
            })
            .await
    });

    let mut tasks = tokio::task::JoinSet::new();
    for association_id in 0..associations {
        tasks.spawn(async move {
            tokio::time::timeout(CONCURRENT_SOCKS5_UDP_TIMEOUT, async move {
                let mut control = tokio::net::TcpStream::connect(mixed_addr)
                    .await
                    .context("connect SOCKS5 UDP control")?;
                control
                    .write_all(&[0x05, 0x01, 0x00])
                    .await
                    .context("write SOCKS5 greeting")?;
                let mut greeting_response = [0_u8; 2];
                control
                    .read_exact(&mut greeting_response)
                    .await
                    .context("read SOCKS5 greeting response")?;
                ensure!(greeting_response == [0x05, 0x00], "unexpected SOCKS5 greeting response");
                control
                    .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .context("write SOCKS5 UDP ASSOCIATE request")?;
                let mut associate_response = [0_u8; 10];
                control
                    .read_exact(&mut associate_response)
                    .await
                    .context("read SOCKS5 UDP ASSOCIATE response")?;
                ensure!(&associate_response[..4] == &[0x05, 0x00, 0x00, 0x01], "unexpected SOCKS5 UDP ASSOCIATE response");
                let associate_addr = SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(
                        associate_response[4],
                        associate_response[5],
                        associate_response[6],
                        associate_response[7],
                    )),
                    u16::from_be_bytes([associate_response[8], associate_response[9]]),
                );
                ensure!(associate_addr.port() == mixed_addr.port(), "SOCKS5 UDP relay port mismatch");
                let udp = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                    .await
                    .context("bind SOCKS5 UDP client")?;
                let SocketAddr::V4(echo_v4) = echo_addr else {
                    anyhow::bail!("UDP echo benchmark fixture should bind IPv4 loopback");
                };
                let mut completed = 0_usize;
                let mut bytes_echoed = 0_usize;
                let mut response = [0_u8; 1024];
                for datagram_id in 0..datagrams_per_association {
                    let payload = format!(
                        "benchmark concurrent socks5 udp association {association_id} datagram {datagram_id}"
                    )
                    .into_bytes();
                    let mut request = Vec::with_capacity(10 + payload.len());
                    request.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
                    request.extend_from_slice(&echo_v4.ip().octets());
                    request.extend_from_slice(&echo_v4.port().to_be_bytes());
                    request.extend_from_slice(&payload);
                    udp.send_to(&request, associate_addr)
                        .await
                        .context("send SOCKS5 UDP datagram")?;
                    let (received, from) = udp
                        .recv_from(&mut response)
                        .await
                        .context("receive SOCKS5 UDP response")?;
                    ensure!(from == associate_addr, "SOCKS5 UDP response peer mismatch");
                    ensure!(received >= 10, "short SOCKS5 UDP response");
                    ensure!(&response[..4] == &[0x00, 0x00, 0x00, 0x01], "invalid SOCKS5 UDP response header");
                    ensure!(&response[4..8] == echo_v4.ip().octets().as_slice(), "SOCKS5 UDP response address mismatch");
                    ensure!(
                        u16::from_be_bytes([response[8], response[9]]) == echo_v4.port(),
                        "SOCKS5 UDP response port mismatch"
                    );
                    ensure!(&response[10..received] == payload.as_slice(), "SOCKS5 UDP echo mismatch");
                    completed += 1;
                    bytes_echoed += payload.len();
                }
                control.shutdown().await.context("shutdown SOCKS5 UDP control")?;
                Ok::<_, anyhow::Error>((completed, bytes_echoed))
            })
            .await
            .context("concurrent SOCKS5 UDP association timed out")?
        });
    }

    let mut completed_datagrams = 0_usize;
    let mut bytes_echoed = 0_usize;
    let mut first_error = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok((completed, bytes))) => {
                completed_datagrams += completed;
                bytes_echoed += bytes;
            }
            Ok(Err(error)) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error.into());
                }
            }
        }
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = listener_shutdown_tx.send(());
    let listener_report = tokio::time::timeout(CONCURRENT_SOCKS5_UDP_TIMEOUT, listener_task)
        .await
        .context("mixed listener shutdown timed out")??
        .context("mixed listener loop failed")?;
    let _ = server_shutdown_tx.send(());
    let server_report = tokio::time::timeout(CONCURRENT_SOCKS5_UDP_TIMEOUT, server_task)
        .await
        .context("UDP server shutdown timed out")??
        .context("UDP server loop failed")?;
    echo.shutdown()
        .await
        .context("shutdown concurrent SOCKS5 UDP echo")?;

    if let Some(error) = first_error {
        return Err(error);
    }

    Ok(ConcurrentSocks5UdpRunSummary {
        associations,
        datagrams_per_association,
        completed_datagrams,
        bytes_echoed,
        listener_accepted_connections: listener_report.accepted_connections,
        listener_completed_udp_associations: listener_report.completed_udp_associations,
        server_accepted_connections: server_report.accepted_connections,
        server_completed_udp_relays: server_report.completed_udp_relays,
    })
}

/// Mixed-listener TCP front-end path selected by the live benchmark helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixedTcpBenchmarkMode {
    /// HTTP CONNECT front-end path.
    HttpConnect,
    /// SOCKS5 CONNECT front-end path.
    Socks5Connect,
}

/// Summary returned by one live mixed-listener TCP benchmark helper run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MixedTcpEchoSummary {
    /// Mixed-listener front-end mode exercised by this helper run.
    pub mode: MixedTcpBenchmarkMode,
    /// Bytes written through the mixed-listener client connection.
    pub payload_bytes: usize,
    /// Bytes echoed back through the mixed-listener client connection.
    pub echoed_bytes: usize,
    /// Protocol classified by the upstream-compatible first-byte dispatch rule.
    pub listener_protocol: MixedProtocol,
    /// Mixed listener TCP connections accepted by this helper run.
    pub listener_accepted_connections: u64,
    /// Mixed listener TCP relays completed by this helper run.
    pub listener_completed_tcp_relays: u64,
    /// Server accepted Juicity connections.
    pub server_accepted_connections: u64,
    /// Server completed TCP relays.
    pub server_completed_tcp_relays: u64,
}

/// Runs one live TCP echo through the mixed SOCKS5/HTTP listener and Rust server.
pub async fn run_mixed_tcp_echo(
    mode: MixedTcpBenchmarkMode,
) -> anyhow::Result<MixedTcpEchoSummary> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let echo = zuicity_testkit::TcpEchoServer::start()
        .await
        .context("start mixed TCP echo")?;
    let echo_addr = echo.local_addr();
    let SocketAddr::V4(echo_v4) = echo_addr else {
        anyhow::bail!("mixed TCP echo benchmark fixture should bind IPv4 loopback");
    };
    let fixture = LiveServerFixture::start()?;
    let server_addr = fixture.client.server_addr;
    let uuid = fixture.client.uuid;
    let password = String::from_utf8(fixture.client.password.clone())
        .context("benchmark password fixture is utf8")?;
    let roots_pem = fixture.client.cert_pem.clone();
    let bound = fixture.bound;
    let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let raw = load_json_str(&format!(
        r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"localhost"}}"#
    ))?;
    let runtime = ClientRuntime::new(ClientRuntimeConfig {
        config: zuicity_config::validate_client(raw)?,
        tls: zuicity_transport::TlsPolicy::upstream(),
        streams: zuicity_transport::StreamPolicy::upstream(),
    });
    let listener = runtime
        .bind_mixed_listener_with_roots(([127, 0, 0, 1], 0).into(), &roots_pem)
        .await
        .context("bind mixed TCP benchmark listener")?;
    let mixed_addr = listener.local_addr()?;
    let listener_task = tokio::spawn(async move { listener.accept_one_tcp().await });

    let payload = match mode {
        MixedTcpBenchmarkMode::HttpConnect => b"benchmark mixed http connect".as_slice(),
        MixedTcpBenchmarkMode::Socks5Connect => b"benchmark mixed socks5 connect".as_slice(),
    };
    let echoed = tokio::time::timeout(LIVE_TIMEOUT, async {
        let mut stream = tokio::net::TcpStream::connect(mixed_addr)
            .await
            .context("connect mixed TCP listener")?;
        match mode {
            MixedTcpBenchmarkMode::HttpConnect => {
                let request = format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n");
                stream
                    .write_all(request.as_bytes())
                    .await
                    .context("write HTTP CONNECT request")?;
                read_http_connect_response(&mut stream).await?;
            }
            MixedTcpBenchmarkMode::Socks5Connect => {
                stream
                    .write_all(&[0x05, 0x01, 0x00])
                    .await
                    .context("write SOCKS5 greeting")?;
                let mut greeting_response = [0_u8; 2];
                stream
                    .read_exact(&mut greeting_response)
                    .await
                    .context("read SOCKS5 greeting response")?;
                ensure!(
                    greeting_response == [0x05, 0x00],
                    "unexpected SOCKS5 greeting response"
                );
                let mut request = Vec::with_capacity(10);
                request.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]);
                request.extend_from_slice(&echo_v4.ip().octets());
                request.extend_from_slice(&echo_v4.port().to_be_bytes());
                stream
                    .write_all(&request)
                    .await
                    .context("write SOCKS5 CONNECT request")?;
                let mut connect_response = [0_u8; 10];
                stream
                    .read_exact(&mut connect_response)
                    .await
                    .context("read SOCKS5 CONNECT response")?;
                ensure!(
                    &connect_response[..4] == &[0x05, 0x00, 0x00, 0x01],
                    "unexpected SOCKS5 CONNECT response"
                );
            }
        }

        stream
            .write_all(payload)
            .await
            .context("write mixed TCP payload")?;
        stream
            .shutdown()
            .await
            .context("shutdown mixed TCP write half")?;
        let mut echoed = vec![0_u8; payload.len()];
        stream
            .read_exact(&mut echoed)
            .await
            .context("read mixed TCP echo payload")?;
        Ok::<_, anyhow::Error>(echoed)
    })
    .await
    .context("mixed TCP client timed out")??;
    ensure!(echoed == payload, "mixed TCP echo mismatch");

    let listener_report = tokio::time::timeout(LIVE_TIMEOUT, listener_task)
        .await
        .context("mixed TCP listener relay timed out")??
        .context("mixed TCP listener relay failed")?;
    ensure!(
        listener_report.protocol
            == match mode {
                MixedTcpBenchmarkMode::HttpConnect => MixedProtocol::Http,
                MixedTcpBenchmarkMode::Socks5Connect => MixedProtocol::Socks5,
            },
        "mixed listener protocol mismatch"
    );
    let server_report = tokio::time::timeout(LIVE_TIMEOUT, server_task)
        .await
        .context("mixed TCP server relay timed out")??
        .context("mixed TCP server relay failed")?;
    ensure!(
        server_report.target == echo_addr,
        "mixed TCP server relay target mismatch"
    );
    echo.shutdown().await.context("shutdown mixed TCP echo")?;

    Ok(MixedTcpEchoSummary {
        mode,
        payload_bytes: payload.len(),
        echoed_bytes: echoed.len(),
        listener_protocol: listener_report.protocol,
        listener_accepted_connections: 1,
        listener_completed_tcp_relays: 1,
        server_accepted_connections: 1,
        server_completed_tcp_relays: 1,
    })
}

async fn read_http_connect_response(stream: &mut tokio::net::TcpStream) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;

    let mut response = Vec::with_capacity(64);
    let mut byte = [0_u8; 1];
    loop {
        ensure!(response.len() < 4096, "HTTP CONNECT response too large");
        stream
            .read_exact(&mut byte)
            .await
            .context("read HTTP CONNECT response byte")?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&response).context("HTTP CONNECT response is not UTF-8")?;
    ensure!(
        text.starts_with("HTTP/1.1 200"),
        "unexpected HTTP CONNECT response: {text:?}"
    );
    Ok(())
}

/// Timeout for one comparative TCP forward latency operation.
pub const COMPARATIVE_TCP_TIMEOUT: Duration = Duration::from_secs(5);
const COMPARATIVE_PROCESS_TERMINATE_TIMEOUT: Duration = Duration::from_secs(2);
const COMPARATIVE_READY_ATTEMPTS: usize = 80;
const COMPARATIVE_READY_DELAY: Duration = Duration::from_millis(50);

/// Upstream-vs-Rust end-to-end TCP forward latency summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamVsRustTcpComparison {
    /// Echo round-trips requested for each stack.
    pub iterations: usize,
    /// Echo round-trips completed through upstream `juicity-client` and `juicity-server`.
    pub upstream_completed: usize,
    /// Echo round-trips completed through Rust client and server runtimes.
    pub rust_completed: usize,
    /// Total echoed payload bytes observed through the upstream stack.
    pub upstream_total: usize,
    /// Total echoed payload bytes observed through the Rust stack.
    pub rust_total: usize,
    /// Minimum upstream round-trip latency.
    pub upstream_min: Duration,
    /// Mean upstream round-trip latency.
    pub upstream_mean: Duration,
    /// Maximum upstream round-trip latency.
    pub upstream_max: Duration,
    /// Minimum Rust round-trip latency.
    pub rust_min: Duration,
    /// Mean Rust round-trip latency.
    pub rust_mean: Duration,
    /// Maximum Rust round-trip latency.
    pub rust_max: Duration,
}

/// Upstream-vs-Rust end-to-end UDP forward latency summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamVsRustUdpComparison {
    /// Echo round-trips requested for each stack.
    pub iterations: usize,
    /// Echo round-trips completed through upstream `juicity-client` and `juicity-server`.
    pub upstream_completed: usize,
    /// Echo round-trips completed through Rust client and server runtimes.
    pub rust_completed: usize,
    /// Total echoed payload bytes observed through the upstream stack.
    pub upstream_total: usize,
    /// Total echoed payload bytes observed through the Rust stack.
    pub rust_total: usize,
    /// Minimum upstream round-trip latency.
    pub upstream_min: Duration,
    /// Mean upstream round-trip latency.
    pub upstream_mean: Duration,
    /// Maximum upstream round-trip latency.
    pub upstream_max: Duration,
    /// Minimum Rust round-trip latency.
    pub rust_min: Duration,
    /// Mean Rust round-trip latency.
    pub rust_mean: Duration,
    /// Maximum Rust round-trip latency.
    pub rust_max: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LatencyRun {
    completed: usize,
    total_bytes: usize,
    min: Duration,
    mean: Duration,
    max: Duration,
}

/// Runs real upstream and Rust TCP forward echo round-trips and compares latency aggregates.
pub async fn run_upstream_vs_rust_tcp_latency_comparison(
    iterations: usize,
) -> anyhow::Result<UpstreamVsRustTcpComparison> {
    ensure!(iterations > 0, "iteration count must be non-zero");

    let upstream = run_upstream_tcp_latency(iterations)
        .await
        .context("run upstream TCP latency comparison")?;
    let rust = run_rust_tcp_latency(iterations)
        .await
        .context("run Rust TCP latency comparison")?;

    Ok(UpstreamVsRustTcpComparison {
        iterations,
        upstream_completed: upstream.completed,
        rust_completed: rust.completed,
        upstream_total: upstream.total_bytes,
        rust_total: rust.total_bytes,
        upstream_min: upstream.min,
        upstream_mean: upstream.mean,
        upstream_max: upstream.max,
        rust_min: rust.min,
        rust_mean: rust.mean,
        rust_max: rust.max,
    })
}

/// Runs real upstream and Rust UDP forward echo round-trips and compares latency aggregates.
pub async fn run_upstream_vs_rust_udp_latency_comparison(
    iterations: usize,
) -> anyhow::Result<UpstreamVsRustUdpComparison> {
    ensure!(iterations > 0, "iteration count must be non-zero");

    let upstream = run_upstream_udp_latency(iterations)
        .await
        .context("run upstream UDP latency comparison")?;
    let rust = run_rust_udp_latency(iterations)
        .await
        .context("run Rust UDP latency comparison")?;

    Ok(UpstreamVsRustUdpComparison {
        iterations,
        upstream_completed: upstream.completed,
        rust_completed: rust.completed,
        upstream_total: upstream.total_bytes,
        rust_total: rust.total_bytes,
        upstream_min: upstream.min,
        upstream_mean: upstream.mean,
        upstream_max: upstream.max,
        rust_min: rust.min,
        rust_mean: rust.mean,
        rust_max: rust.max,
    })
}

async fn run_upstream_tcp_latency(iterations: usize) -> anyhow::Result<LatencyRun> {
    let artifact = zuicity_testkit::artifact_dir("upstream vs rust tcp latency")
        .create()
        .context("create comparative upstream artifact dir")?;
    let upstream_client = upstream_client_binary(artifact.path())?;
    let upstream_server = upstream_server_binary(artifact.path())?;
    ensure!(
        upstream_client.is_file(),
        "missing upstream juicity-client at {}",
        upstream_client.display()
    );
    ensure!(
        upstream_server.is_file(),
        "missing upstream juicity-server at {}",
        upstream_server.display()
    );

    let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
        .context("write upstream comparative cert fixture")?;
    let reserved_server = zuicity_testkit::reserve_udp_socket()
        .context("reserve upstream comparative server UDP port")?;
    let server_addr = reserved_server
        .local_addr()
        .context("read upstream comparative server addr")?;
    drop(reserved_server);
    let reserved_forward = zuicity_testkit::reserve_tcp_listener()
        .context("reserve upstream comparative forward TCP port")?;
    let forward_addr = reserved_forward
        .local_addr()
        .context("read upstream comparative forward addr")?;
    drop(reserved_forward);

    let uuid = uuid::Uuid::parse_str(BENCH_UUID_STR).context("parse comparative uuid")?;
    let password = "password";
    let server_config_path = artifact.path().join("upstream-server.json");
    std::fs::write(
        &server_config_path,
        format!(
            r#"{{"listen":"{server_addr}","users":{{"{uuid}":"{password}"}},"certificate":"{}","private_key":"{}","log_level":"debug"}}"#,
            cert.cert_path.display(),
            cert.key_path.display()
        ),
    )
    .context("write upstream comparative server config")?;
    let server_log_path = artifact.path().join("upstream-server.log");
    let mut server =
        zuicity_testkit::ManagedProcessBuilder::new(upstream_server.to_string_lossy().into_owned())
            .arg("run")
            .arg("-c")
            .arg(server_config_path.to_string_lossy().into_owned())
            .log_path(&server_log_path)
            .start()
            .context("spawn upstream juicity-server run")?;

    let roots_pem = std::fs::read(&cert.cert_path).context("read upstream comparative roots")?;
    let ready_connection =
        connect_managed_with_retry(server_addr, &roots_pem, uuid, password.as_bytes(), &server)
            .await
            .context("wait for upstream comparative server readiness")?;
    drop(ready_connection);

    let echo = zuicity_testkit::TcpEchoServer::start()
        .await
        .context("start upstream comparative TCP echo")?;
    let client_config_path = artifact.path().join("upstream-client.json");
    std::fs::write(
        &client_config_path,
        format!(
            r#"{{"server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"localhost","allow_insecure":true,"log_level":"debug","forward":{{"{forward_addr}/tcp":"{}"}}}}"#,
            echo.local_addr()
        ),
    )
    .context("write upstream comparative client config")?;
    let client_log_path = artifact.path().join("upstream-client.log");
    let mut client =
        zuicity_testkit::ManagedProcessBuilder::new(upstream_client.to_string_lossy().into_owned())
            .arg("run")
            .arg("-c")
            .arg(client_config_path.to_string_lossy().into_owned())
            .log_path(&client_log_path)
            .start()
            .context("spawn upstream juicity-client run")?;
    let ready_stream = connect_tcp_forward_with_retry(forward_addr, &client)
        .await
        .context("wait for upstream comparative forwarder readiness")?;
    drop(ready_stream);

    let result = tcp_forward_latency_round_trips(forward_addr, iterations, "upstream").await;
    let echo_shutdown = echo
        .shutdown()
        .await
        .context("shutdown upstream comparative TCP echo");
    let client_exit = client
        .terminate(COMPARATIVE_PROCESS_TERMINATE_TIMEOUT)
        .context("terminate upstream comparative juicity-client");
    let server_exit = server
        .terminate(COMPARATIVE_PROCESS_TERMINATE_TIMEOUT)
        .context("terminate upstream comparative juicity-server");

    echo_shutdown?;
    let client_exit = client_exit?;
    let server_exit = server_exit?;
    ensure!(
        !client_exit.forced,
        "upstream comparative client required SIGKILL; log={}",
        client_log_path.display()
    );
    ensure!(
        !server_exit.forced,
        "upstream comparative server required SIGKILL; log={}",
        server_log_path.display()
    );

    result
}

async fn run_upstream_udp_latency(iterations: usize) -> anyhow::Result<LatencyRun> {
    let artifact = zuicity_testkit::artifact_dir("upstream vs rust udp latency")
        .create()
        .context("create comparative upstream UDP artifact dir")?;
    let upstream_client = upstream_client_binary(artifact.path())?;
    let upstream_server = upstream_server_binary(artifact.path())?;
    ensure!(
        upstream_client.is_file(),
        "missing upstream juicity-client at {}",
        upstream_client.display()
    );
    ensure!(
        upstream_server.is_file(),
        "missing upstream juicity-server at {}",
        upstream_server.display()
    );

    let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
        .context("write upstream comparative UDP cert fixture")?;
    let reserved_server = zuicity_testkit::reserve_udp_socket()
        .context("reserve upstream comparative UDP server port")?;
    let server_addr = reserved_server
        .local_addr()
        .context("read upstream comparative UDP server addr")?;
    drop(reserved_server);
    let reserved_forward = zuicity_testkit::reserve_udp_socket()
        .context("reserve upstream comparative forward UDP port")?;
    let forward_addr = reserved_forward
        .local_addr()
        .context("read upstream comparative forward UDP addr")?;
    drop(reserved_forward);

    let uuid = uuid::Uuid::parse_str(BENCH_UUID_STR).context("parse comparative UDP uuid")?;
    let password = "password";
    let server_config_path = artifact.path().join("upstream-server-udp.json");
    std::fs::write(
        &server_config_path,
        format!(
            r#"{{"listen":"{server_addr}","users":{{"{uuid}":"{password}"}},"certificate":"{}","private_key":"{}","log_level":"debug"}}"#,
            cert.cert_path.display(),
            cert.key_path.display()
        ),
    )
    .context("write upstream comparative UDP server config")?;
    let server_log_path = artifact.path().join("upstream-server-udp.log");
    let mut server =
        zuicity_testkit::ManagedProcessBuilder::new(upstream_server.to_string_lossy().into_owned())
            .arg("run")
            .arg("-c")
            .arg(server_config_path.to_string_lossy().into_owned())
            .log_path(&server_log_path)
            .start()
            .context("spawn upstream juicity-server run for UDP comparison")?;

    let roots_pem =
        std::fs::read(&cert.cert_path).context("read upstream comparative UDP roots")?;
    let ready_connection =
        connect_managed_with_retry(server_addr, &roots_pem, uuid, password.as_bytes(), &server)
            .await
            .context("wait for upstream comparative UDP server readiness")?;
    drop(ready_connection);

    let echo = zuicity_testkit::UdpEchoServer::start()
        .await
        .context("start upstream comparative UDP echo")?;
    let client_config_path = artifact.path().join("upstream-client-udp.json");
    std::fs::write(
        &client_config_path,
        format!(
            r#"{{"server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"localhost","allow_insecure":true,"log_level":"debug","forward":{{"{forward_addr}/udp":"{}"}}}}"#,
            echo.local_addr()
        ),
    )
    .context("write upstream comparative UDP client config")?;
    let client_log_path = artifact.path().join("upstream-client-udp.log");
    let mut client =
        zuicity_testkit::ManagedProcessBuilder::new(upstream_client.to_string_lossy().into_owned())
            .arg("run")
            .arg("-c")
            .arg(client_config_path.to_string_lossy().into_owned())
            .log_path(&client_log_path)
            .start()
            .context("spawn upstream juicity-client run for UDP comparison")?;
    wait_for_udp_forward_ready(forward_addr, &client)
        .await
        .context("wait for upstream comparative UDP forwarder readiness")?;

    let result = udp_forward_latency_round_trips(forward_addr, iterations, "upstream").await;
    let echo_shutdown = echo
        .shutdown()
        .await
        .context("shutdown upstream comparative UDP echo");
    let client_exit = client
        .terminate(COMPARATIVE_PROCESS_TERMINATE_TIMEOUT)
        .context("terminate upstream comparative UDP juicity-client");
    let server_exit = server
        .terminate(COMPARATIVE_PROCESS_TERMINATE_TIMEOUT)
        .context("terminate upstream comparative UDP juicity-server");

    echo_shutdown?;
    let client_exit = client_exit?;
    let server_exit = server_exit?;
    ensure!(
        !client_exit.forced,
        "upstream comparative UDP client required SIGKILL; log={}",
        client_log_path.display()
    );
    ensure!(
        !server_exit.forced,
        "upstream comparative UDP server required SIGKILL; log={}",
        server_log_path.display()
    );

    result
}

async fn run_rust_udp_latency(iterations: usize) -> anyhow::Result<LatencyRun> {
    let mut latencies = Vec::with_capacity(iterations);
    let mut total_bytes = 0_usize;
    for iteration in 0..iterations {
        let (latency, bytes) = run_rust_udp_latency_iteration(iteration)
            .await
            .with_context(|| format!("run Rust UDP latency iteration {iteration}"))?;
        total_bytes += bytes;
        latencies.push(latency);
    }
    latency_run(iterations, total_bytes, &latencies)
}

async fn run_rust_udp_latency_iteration(iteration: usize) -> anyhow::Result<(Duration, usize)> {
    let echo = zuicity_testkit::UdpEchoServer::start()
        .await
        .context("start Rust comparative UDP echo")?;
    let echo_addr = echo.local_addr();
    let fixture =
        LiveServerFixture::start().context("start Rust comparative UDP server fixture")?;
    let server_addr = fixture.client.server_addr;
    let uuid = fixture.client.uuid;
    let password = String::from_utf8(fixture.client.password.clone())
        .context("benchmark password fixture is utf8")?;
    let roots_pem = fixture.client.cert_pem.clone();
    let bound = fixture.bound;
    let server_task = tokio::spawn(async move { bound.accept_one_udp_over_stream().await });

    let raw = load_json_str(&format!(
        r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"localhost"}}"#
    ))?;
    let runtime = ClientRuntime::new(ClientRuntimeConfig {
        config: zuicity_config::validate_client(raw)?,
        tls: zuicity_transport::TlsPolicy::upstream(),
        streams: zuicity_transport::StreamPolicy::upstream(),
    });
    let forwarder = runtime
        .bind_udp_forwarder_with_roots(([127, 0, 0, 1], 0).into(), echo_addr, &roots_pem)
        .await
        .context("bind Rust comparative UDP forwarder")?;
    let forward_addr = forwarder.local_addr()?;
    let forward_task = tokio::spawn(async move { forwarder.forward_one_datagram().await });

    let payload = format!("benchmark rust udp latency iteration {iteration}").into_bytes();
    let (latency, echoed_bytes) = udp_forward_latency_round_trip(forward_addr, payload, "rust")
        .await
        .context("drive Rust comparative UDP forward round-trip")?;

    let forward_report = tokio::time::timeout(COMPARATIVE_TCP_TIMEOUT, forward_task)
        .await
        .context("Rust comparative UDP forwarder relay timed out")??
        .context("Rust comparative UDP forwarder relay failed")?;
    let server_report = tokio::time::timeout(COMPARATIVE_TCP_TIMEOUT, server_task)
        .await
        .context("Rust comparative UDP server relay timed out")??
        .context("Rust comparative UDP server relay failed")?;
    echo.shutdown()
        .await
        .context("shutdown Rust comparative UDP echo")?;

    ensure!(
        forward_report.remote_target == echo_addr,
        "Rust comparative UDP forwarder target mismatch"
    );
    ensure!(
        server_report.target == echo_addr,
        "Rust comparative UDP server relay target mismatch"
    );
    ensure!(
        forward_report.bytes_from_client == echoed_bytes as u64,
        "Rust comparative UDP forwarder client byte count mismatch"
    );
    ensure!(
        forward_report.bytes_from_target == echoed_bytes as u64,
        "Rust comparative UDP forwarder target byte count mismatch"
    );
    ensure!(
        server_report.bytes_from_client == echoed_bytes as u64,
        "Rust comparative UDP server client byte count mismatch"
    );
    ensure!(
        server_report.bytes_from_target == echoed_bytes as u64,
        "Rust comparative UDP server target byte count mismatch"
    );

    Ok((latency, echoed_bytes))
}

async fn run_rust_tcp_latency(iterations: usize) -> anyhow::Result<LatencyRun> {
    let mut latencies = Vec::with_capacity(iterations);
    let mut total_bytes = 0_usize;
    for iteration in 0..iterations {
        let (latency, bytes) = run_rust_tcp_latency_iteration(iteration)
            .await
            .with_context(|| format!("run Rust TCP latency iteration {iteration}"))?;
        total_bytes += bytes;
        latencies.push(latency);
    }
    latency_run(iterations, total_bytes, &latencies)
}

async fn run_rust_tcp_latency_iteration(iteration: usize) -> anyhow::Result<(Duration, usize)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let echo = zuicity_testkit::TcpEchoServer::start()
        .await
        .context("start Rust comparative TCP echo")?;
    let echo_addr = echo.local_addr();
    let fixture = LiveServerFixture::start().context("start Rust comparative server fixture")?;
    let server_addr = fixture.client.server_addr;
    let uuid = fixture.client.uuid;
    let password = String::from_utf8(fixture.client.password.clone())
        .context("benchmark password fixture is utf8")?;
    let roots_pem = fixture.client.cert_pem.clone();
    let bound = fixture.bound;
    let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

    let raw = load_json_str(&format!(
        r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"localhost"}}"#
    ))?;
    let runtime = ClientRuntime::new(ClientRuntimeConfig {
        config: zuicity_config::validate_client(raw)?,
        tls: zuicity_transport::TlsPolicy::upstream(),
        streams: zuicity_transport::StreamPolicy::upstream(),
    });
    let forwarder = runtime
        .bind_tcp_forwarder_with_roots(([127, 0, 0, 1], 0).into(), echo_addr, &roots_pem)
        .await
        .context("bind Rust comparative TCP forwarder")?;
    let forward_addr = forwarder.local_addr()?;
    let forward_task = tokio::spawn(async move { forwarder.accept_one().await });

    let payload = format!("benchmark rust tcp latency iteration {iteration}").into_bytes();
    let started = Instant::now();
    let mut stream = tokio::net::TcpStream::connect(forward_addr)
        .await
        .context("connect Rust comparative TCP forwarder")?;
    stream
        .write_all(&payload)
        .await
        .context("write Rust comparative TCP latency payload")?;
    stream
        .shutdown()
        .await
        .context("shutdown Rust comparative TCP latency write half")?;
    // `read_to_end` matches the forwarder half-close (FIN) so a graceful close
    // cannot surface as a spurious `early eof` the way `read_exact` would.
    let mut echoed = Vec::with_capacity(payload.len());
    tokio::time::timeout(COMPARATIVE_TCP_TIMEOUT, stream.read_to_end(&mut echoed))
        .await
        .context("read Rust comparative TCP echo timed out")?
        .context("read Rust comparative TCP latency echo")?;
    let latency = started.elapsed();
    ensure!(
        echoed == payload,
        "Rust comparative TCP latency echo mismatch"
    );
    let echoed_bytes = echoed.len();
    // Join the relay tasks only after the client drained the echo, so joining
    // observes ordered FINs instead of racing a mid-copy `closed by peer: 0`.
    drop(stream);

    let forward_report = tokio::time::timeout(COMPARATIVE_TCP_TIMEOUT, forward_task)
        .await
        .context("Rust comparative TCP forwarder relay timed out")??
        .context("Rust comparative TCP forwarder relay failed")?;
    let server_report = tokio::time::timeout(COMPARATIVE_TCP_TIMEOUT, server_task)
        .await
        .context("Rust comparative TCP server relay timed out")??
        .context("Rust comparative TCP server relay failed")?;
    echo.shutdown()
        .await
        .context("shutdown Rust comparative TCP echo")?;

    ensure!(
        forward_report.remote_target == TcpForwardTarget::Ip(echo_addr),
        "Rust comparative forwarder target mismatch"
    );
    ensure!(
        server_report.target == echo_addr,
        "Rust comparative server relay target mismatch"
    );
    ensure!(
        forward_report.bytes_from_client == echoed_bytes as u64,
        "Rust comparative forwarder client byte count mismatch"
    );
    ensure!(
        forward_report.bytes_from_target == echoed_bytes as u64,
        "Rust comparative forwarder target byte count mismatch"
    );
    ensure!(
        server_report.bytes_from_client == echoed_bytes as u64,
        "Rust comparative server client byte count mismatch"
    );
    ensure!(
        server_report.bytes_from_target == echoed_bytes as u64,
        "Rust comparative server target byte count mismatch"
    );

    Ok((latency, echoed_bytes))
}

async fn tcp_forward_latency_round_trips(
    forward_addr: SocketAddr,
    iterations: usize,
    label: &str,
) -> anyhow::Result<LatencyRun> {
    let mut latencies = Vec::with_capacity(iterations);
    let mut total_bytes = 0_usize;
    for iteration in 0..iterations {
        let payload = format!("benchmark {label} tcp latency iteration {iteration}").into_bytes();
        let (latency, echoed_bytes) = tcp_forward_latency_round_trip(forward_addr, payload, label)
            .await
            .with_context(|| format!("drive {label} comparative TCP forward round-trip"))?;
        total_bytes += echoed_bytes;
        latencies.push(latency);
    }
    latency_run(iterations, total_bytes, &latencies)
}

async fn tcp_forward_latency_round_trip(
    forward_addr: SocketAddr,
    payload: Vec<u8>,
    label: &str,
) -> anyhow::Result<(Duration, usize)> {
    let started = Instant::now();
    let echoed = tokio::time::timeout(COMPARATIVE_TCP_TIMEOUT, async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(forward_addr)
            .await
            .with_context(|| format!("connect {label} TCP forwarder"))?;
        stream
            .write_all(&payload)
            .await
            .with_context(|| format!("write {label} TCP latency payload"))?;
        stream
            .shutdown()
            .await
            .with_context(|| format!("shutdown {label} TCP latency write half"))?;
        let mut echoed = vec![0_u8; payload.len()];
        stream
            .read_exact(&mut echoed)
            .await
            .with_context(|| format!("read {label} TCP latency echo"))?;
        Ok::<_, anyhow::Error>(echoed)
    })
    .await
    .with_context(|| format!("{label} TCP latency round-trip timed out"))??;
    let elapsed = started.elapsed();
    ensure!(echoed == payload, "{label} TCP latency echo mismatch");
    Ok((elapsed, echoed.len()))
}

async fn wait_for_udp_forward_ready(
    forward_addr: SocketAddr,
    process: &zuicity_testkit::ManagedProcess,
) -> anyhow::Result<()> {
    let mut last_error = String::new();
    for _ in 0..COMPARATIVE_READY_ATTEMPTS {
        ensure!(
            process.is_running()?,
            "UDP forwarder process exited before readiness; log_path={}",
            process.log_path().display()
        );
        match udp_forward_latency_round_trip(
            forward_addr,
            b"benchmark udp forward readiness".to_vec(),
            "readiness",
        )
        .await
        {
            Ok((_latency, _bytes)) => return Ok(()),
            Err(error) => last_error = error.to_string(),
        }
        tokio::time::sleep(COMPARATIVE_READY_DELAY).await;
    }
    anyhow::bail!(
        "UDP forwarder did not become ready at {forward_addr}: {last_error}; log_path={}",
        process.log_path().display()
    )
}

async fn udp_forward_latency_round_trips(
    forward_addr: SocketAddr,
    iterations: usize,
    label: &str,
) -> anyhow::Result<LatencyRun> {
    let mut latencies = Vec::with_capacity(iterations);
    let mut total_bytes = 0_usize;
    for iteration in 0..iterations {
        let payload = format!("benchmark {label} udp latency iteration {iteration}").into_bytes();
        let (latency, echoed_bytes) = udp_forward_latency_round_trip(forward_addr, payload, label)
            .await
            .with_context(|| format!("drive {label} comparative UDP forward round-trip"))?;
        total_bytes += echoed_bytes;
        latencies.push(latency);
    }
    latency_run(iterations, total_bytes, &latencies)
}

async fn udp_forward_latency_round_trip(
    forward_addr: SocketAddr,
    payload: Vec<u8>,
    label: &str,
) -> anyhow::Result<(Duration, usize)> {
    let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .with_context(|| format!("bind {label} UDP latency client"))?;
    let started = Instant::now();
    socket
        .send_to(&payload, forward_addr)
        .await
        .with_context(|| format!("send {label} UDP latency payload"))?;
    let mut response = vec![0_u8; payload.len() + 64];
    let (received, from) =
        tokio::time::timeout(COMPARATIVE_TCP_TIMEOUT, socket.recv_from(&mut response))
            .await
            .with_context(|| format!("{label} UDP latency round-trip timed out"))?
            .with_context(|| format!("receive {label} UDP latency echo"))?;
    let elapsed = started.elapsed();
    ensure!(
        from == forward_addr,
        "{label} UDP latency response peer mismatch"
    );
    ensure!(
        response[..received] == payload,
        "{label} UDP latency echo mismatch"
    );
    Ok((elapsed, received))
}

fn latency_run(
    completed: usize,
    total_bytes: usize,
    latencies: &[Duration],
) -> anyhow::Result<LatencyRun> {
    ensure!(
        !latencies.is_empty(),
        "latency sample set must be non-empty"
    );
    let mut min = latencies[0];
    let mut max = latencies[0];
    let mut total_nanos = 0_u128;
    for latency in latencies {
        min = min.min(*latency);
        max = max.max(*latency);
        total_nanos += latency.as_nanos();
    }
    let mean_nanos = total_nanos / latencies.len() as u128;
    let mean = Duration::from_nanos(
        u64::try_from(mean_nanos).context("mean latency exceeds u64 nanoseconds")?,
    );
    Ok(LatencyRun {
        completed,
        total_bytes,
        min,
        mean,
        max,
    })
}

fn upstream_client_binary(dir: &Path) -> anyhow::Result<PathBuf> {
    upstream_binary(
        dir,
        "juicity-client",
        "./cmd/client",
        "upstream-client-build.log",
    )
}

fn upstream_server_binary(dir: &Path) -> anyhow::Result<PathBuf> {
    upstream_binary(
        dir,
        "juicity-server",
        "./cmd/server",
        "upstream-server-build.log",
    )
}

fn upstream_binary(
    dir: &Path,
    binary_name: &str,
    package: &str,
    build_log_name: &str,
) -> anyhow::Result<PathBuf> {
    if let Some(prebuilt_dir) = std::env::var_os("UPSTREAM_JUICITY_BIN_DIR") {
        let binary = PathBuf::from(prebuilt_dir).join(binary_name);
        ensure!(
            binary.is_file(),
            "missing prebuilt upstream binary at {}",
            binary.display()
        );
        return Ok(binary);
    }

    let upstream_root = std::env::var_os("UPSTREAM_JUICITY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root/projects/juicity/juicity"));
    let bin_dir = dir.join("upstream-bin");
    std::fs::create_dir_all(&bin_dir).context("create comparative upstream bin dir")?;
    let binary = bin_dir.join(binary_name);
    let build_log = dir.join(build_log_name);
    let output = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&binary)
        .arg(package)
        .current_dir(&upstream_root)
        .output()
        .with_context(|| format!("build upstream {binary_name}"))?;
    std::fs::write(
        &build_log,
        format!(
            "status={}\nstdout={}\nstderr={}\n",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
    .with_context(|| format!("write upstream build log {}", build_log.display()))?;
    ensure!(
        output.status.success(),
        "upstream {binary_name} build failed; see {}",
        build_log.display()
    );
    Ok(binary)
}

async fn connect_tcp_forward_with_retry(
    addr: SocketAddr,
    process: &zuicity_testkit::ManagedProcess,
) -> anyhow::Result<tokio::net::TcpStream> {
    let mut last_error = String::new();
    for _ in 0..COMPARATIVE_READY_ATTEMPTS {
        ensure!(
            process.is_running()?,
            "TCP forwarder process exited before readiness; log_path={}",
            process.log_path().display()
        );
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = error.to_string(),
        }
        tokio::time::sleep(COMPARATIVE_READY_DELAY).await;
    }
    anyhow::bail!(
        "TCP forwarder did not become ready at {addr}: {last_error}; log_path={}",
        process.log_path().display()
    )
}

async fn connect_managed_with_retry(
    server_addr: SocketAddr,
    roots_pem: &[u8],
    uuid: uuid::Uuid,
    password: &[u8],
    process: &zuicity_testkit::ManagedProcess,
) -> anyhow::Result<AuthenticatedConnection> {
    let mut last_error = String::new();
    for _ in 0..COMPARATIVE_READY_ATTEMPTS {
        ensure!(
            process.is_running()?,
            "server process exited before readiness; log_path={}",
            process.log_path().display()
        );
        let client = JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        match tokio::time::timeout(
            COMPARATIVE_TCP_TIMEOUT,
            client.connect_with_roots(server_addr, "localhost", roots_pem, false, uuid, password),
        )
        .await
        {
            Ok(Ok(connection)) => return Ok(connection),
            Ok(Err(error)) => last_error = error.to_string(),
            Err(_) => last_error = "connect timed out".to_owned(),
        }
        tokio::time::sleep(COMPARATIVE_READY_DELAY).await;
    }
    anyhow::bail!(
        "server did not become ready at {server_addr}: {last_error}; log_path={}",
        process.log_path().display()
    )
}

/// Summary returned by one live client TCP forward benchmark helper run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientForwardTcpEchoSummary {
    /// Bytes written through the local TCP forwarder.
    pub payload_bytes: usize,
    /// Bytes echoed back through the local TCP forwarder.
    pub echoed_bytes: usize,
    /// TCP bytes reported by the client forwarder from local client to target.
    pub forwarder_bytes_from_client: u64,
    /// TCP bytes reported by the client forwarder from target back to local client.
    pub forwarder_bytes_from_target: u64,
    /// Server accepted Juicity connections.
    pub server_accepted_connections: u64,
    /// Server completed TCP relays.
    pub server_completed_tcp_relays: u64,
}

/// Summary returned by one live client UDP forward benchmark helper run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientForwardUdpEchoSummary {
    /// Bytes sent through the local UDP forwarder.
    pub payload_bytes: usize,
    /// Bytes echoed back through the local UDP forwarder.
    pub echoed_bytes: usize,
    /// UDP bytes reported by the client forwarder from local client to target.
    pub forwarder_bytes_from_client: u64,
    /// UDP bytes reported by the client forwarder from target back to local client.
    pub forwarder_bytes_from_target: u64,
    /// Server accepted Juicity connections.
    pub server_accepted_connections: u64,
    /// Server completed UDP relays.
    pub server_completed_udp_relays: u64,
}

/// Runs one live TCP echo through the embeddable client TCP forwarder and Rust server.
pub async fn run_client_forward_tcp_echo(
    fixture: LiveServerFixture,
) -> anyhow::Result<ClientForwardTcpEchoSummary> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let echo = zuicity_testkit::TcpEchoServer::start()
        .await
        .context("start client forward TCP echo")?;
    let echo_addr = echo.local_addr();
    let server_addr = fixture.client.server_addr;
    let uuid = fixture.client.uuid;
    let password = String::from_utf8(fixture.client.password.clone())
        .context("benchmark password fixture is utf8")?;
    let roots_pem = fixture.client.cert_pem.clone();
    let bound = fixture.bound;
    let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

    let raw = load_json_str(&format!(
        r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"localhost"}}"#
    ))?;
    let runtime = ClientRuntime::new(ClientRuntimeConfig {
        config: zuicity_config::validate_client(raw)?,
        tls: zuicity_transport::TlsPolicy::upstream(),
        streams: zuicity_transport::StreamPolicy::upstream(),
    });
    let forwarder = runtime
        .bind_tcp_forwarder_with_roots(([127, 0, 0, 1], 0).into(), echo_addr, &roots_pem)
        .await
        .context("bind client TCP forward benchmark listener")?;
    let forward_addr = forwarder.local_addr()?;
    let forward_task = tokio::spawn(async move { forwarder.accept_one().await });

    let payload = b"benchmark client tcp forward";
    let echoed = tokio::time::timeout(LIVE_TIMEOUT, async {
        let mut stream = tokio::net::TcpStream::connect(forward_addr)
            .await
            .context("connect client TCP forwarder")?;
        stream
            .write_all(payload)
            .await
            .context("write client TCP forward payload")?;
        stream
            .shutdown()
            .await
            .context("shutdown client TCP forward write half")?;
        let mut echoed = vec![0_u8; payload.len()];
        stream
            .read_exact(&mut echoed)
            .await
            .context("read client TCP forward echo payload")?;
        Ok::<_, anyhow::Error>(echoed)
    })
    .await
    .context("client TCP forward echo timed out")??;
    ensure!(echoed == payload, "client TCP forward echo mismatch");

    let forward_report = tokio::time::timeout(LIVE_TIMEOUT, forward_task)
        .await
        .context("client TCP forwarder relay timed out")??
        .context("client TCP forwarder relay failed")?;
    ensure!(
        forward_report.remote_target == TcpForwardTarget::Ip(echo_addr),
        "client TCP forward target mismatch"
    );
    let server_report = tokio::time::timeout(LIVE_TIMEOUT, server_task)
        .await
        .context("client TCP forward server relay timed out")??
        .context("client TCP forward server relay failed")?;
    ensure!(
        server_report.target == echo_addr,
        "client TCP forward server relay target mismatch"
    );
    echo.shutdown()
        .await
        .context("shutdown client forward TCP echo")?;

    Ok(ClientForwardTcpEchoSummary {
        payload_bytes: payload.len(),
        echoed_bytes: echoed.len(),
        forwarder_bytes_from_client: forward_report.bytes_from_client,
        forwarder_bytes_from_target: forward_report.bytes_from_target,
        server_accepted_connections: 1,
        server_completed_tcp_relays: 1,
    })
}

/// Runs one live UDP echo through the embeddable client UDP forwarder and Rust server.
pub async fn run_client_forward_udp_echo(
    fixture: LiveServerFixture,
) -> anyhow::Result<ClientForwardUdpEchoSummary> {
    let echo = zuicity_testkit::UdpEchoServer::start()
        .await
        .context("start client forward UDP echo")?;
    let echo_addr = echo.local_addr();
    let server_addr = fixture.client.server_addr;
    let uuid = fixture.client.uuid;
    let password = String::from_utf8(fixture.client.password.clone())
        .context("benchmark password fixture is utf8")?;
    let roots_pem = fixture.client.cert_pem.clone();
    let bound = fixture.bound;
    let server_task = tokio::spawn(async move { bound.accept_one_udp_over_stream().await });

    let raw = load_json_str(&format!(
        r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"localhost"}}"#
    ))?;
    let runtime = ClientRuntime::new(ClientRuntimeConfig {
        config: zuicity_config::validate_client(raw)?,
        tls: zuicity_transport::TlsPolicy::upstream(),
        streams: zuicity_transport::StreamPolicy::upstream(),
    });
    let forwarder = runtime
        .bind_udp_forwarder_with_roots(([127, 0, 0, 1], 0).into(), echo_addr, &roots_pem)
        .await
        .context("bind client UDP forward benchmark socket")?;
    let forward_addr = forwarder.local_addr()?;
    let forward_task = tokio::spawn(async move { forwarder.forward_one_datagram().await });

    let payload = b"benchmark client udp forward";
    let echoed = tokio::time::timeout(LIVE_TIMEOUT, async {
        let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .context("bind client UDP forward sender")?;
        socket
            .send_to(payload, forward_addr)
            .await
            .context("send client UDP forward payload")?;
        let mut response = [0_u8; 1024];
        let (received, from) = socket
            .recv_from(&mut response)
            .await
            .context("receive client UDP forward echo")?;
        ensure!(
            from == forward_addr,
            "client UDP forward response peer mismatch"
        );
        Ok::<_, anyhow::Error>(response[..received].to_vec())
    })
    .await
    .context("client UDP forward echo timed out")??;
    ensure!(echoed == payload, "client UDP forward echo mismatch");

    let forward_report = tokio::time::timeout(LIVE_TIMEOUT, forward_task)
        .await
        .context("client UDP forwarder relay timed out")??
        .context("client UDP forwarder relay failed")?;
    ensure!(
        forward_report.remote_target == echo_addr,
        "client UDP forward target mismatch"
    );
    let server_report = tokio::time::timeout(LIVE_TIMEOUT, server_task)
        .await
        .context("client UDP forward server relay timed out")??
        .context("client UDP forward server relay failed")?;
    ensure!(
        server_report.target == echo_addr,
        "client UDP forward server relay target mismatch"
    );
    echo.shutdown()
        .await
        .context("shutdown client forward UDP echo")?;

    Ok(ClientForwardUdpEchoSummary {
        payload_bytes: payload.len(),
        echoed_bytes: echoed.len(),
        forwarder_bytes_from_client: forward_report.bytes_from_client,
        forwarder_bytes_from_target: forward_report.bytes_from_target,
        server_accepted_connections: 1,
        server_completed_udp_relays: 1,
    })
}

/// Summary returned by live dae connector echo benchmark helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaeConnectorEchoSummary {
    /// Payload bytes sent through the dae connector.
    pub payload_bytes: usize,
    /// Echoed bytes received through the dae connector.
    pub echoed_bytes: usize,
    /// Server accepted Juicity connections.
    pub server_accepted_connections: u64,
    /// Server completed TCP relays.
    pub server_completed_tcp_relays: u64,
    /// Server completed UDP relays.
    pub server_completed_udp_relays: u64,
    /// dae connector metrics snapshot captured after connection shutdown.
    pub metrics: DaeMetricsSnapshot,
}

fn dae_connector_for_fixture(
    fixture: &LiveClientFixture,
) -> anyhow::Result<(DaeJuicityConnector, zuicity_dae::DaeMetrics)> {
    let password = String::from_utf8(fixture.password.clone())
        .context("benchmark password fixture is utf8")?;
    let raw = load_json_str(&format!(
        r#"{{"listen":"127.0.0.1:0","server":"{}","uuid":"{}","password":"{}","sni":"localhost"}}"#,
        fixture.server_addr, fixture.uuid, password
    ))?;
    let config = DaeOutboundConfig::from_client_config(zuicity_config::validate_client(raw)?);
    let metrics = zuicity_dae::DaeMetrics::default();
    let hooks =
        zuicity_dae::DaeRuntimeHooks::new(zuicity_dae::NoopConnectionLifecycle, metrics.clone());
    Ok((
        DaeJuicityConnector::with_hooks(config, fixture.cert_pem.clone(), hooks),
        metrics,
    ))
}

/// Runs one live TCP echo through the embeddable dae Juicity connector.
pub async fn run_dae_connector_tcp_echo(
    fixture: LiveServerFixture,
) -> anyhow::Result<DaeConnectorEchoSummary> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let echo = zuicity_testkit::TcpEchoServer::start()
        .await
        .context("start dae TCP echo")?;
    let echo_addr = echo.local_addr();
    let (connector, metrics) = dae_connector_for_fixture(&fixture.client)?;
    let bound = fixture.bound;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        bound
            .run_proxy_loop_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let payload = b"benchmark dae tcp connector";
    let mut stream =
        tokio::time::timeout(LIVE_TIMEOUT, connector.connect_tcp(&echo_addr.to_string()))
            .await
            .context("dae TCP connect timed out")??;
    stream
        .write_all(payload)
        .await
        .context("write dae TCP payload")?;
    stream
        .shutdown()
        .await
        .context("shutdown dae TCP write half")?;
    let mut echoed = Vec::with_capacity(payload.len());
    stream
        .read_to_end(&mut echoed)
        .await
        .context("read dae TCP echo")?;
    ensure!(echoed == payload, "dae TCP echo mismatch");
    drop(stream);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let _ = shutdown_tx.send(());
    let server_report = tokio::time::timeout(LIVE_TIMEOUT, server_task)
        .await
        .context("dae TCP server shutdown timed out")??
        .context("dae TCP server loop failed")?;
    echo.shutdown().await.context("shutdown dae TCP echo")?;

    Ok(DaeConnectorEchoSummary {
        payload_bytes: payload.len(),
        echoed_bytes: echoed.len(),
        server_accepted_connections: server_report.accepted_connections,
        server_completed_tcp_relays: server_report.completed_tcp_relays,
        server_completed_udp_relays: server_report.completed_udp_relays,
        metrics: metrics.snapshot(),
    })
}

/// Runs one live UDP echo through the embeddable dae Juicity connector.
pub async fn run_dae_connector_udp_echo(
    fixture: LiveServerFixture,
) -> anyhow::Result<DaeConnectorEchoSummary> {
    let echo = zuicity_testkit::UdpEchoServer::start()
        .await
        .context("start dae UDP echo")?;
    let echo_addr = echo.local_addr();
    let (connector, metrics) = dae_connector_for_fixture(&fixture.client)?;
    let bound = fixture.bound;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        bound
            .run_udp_over_stream_loop_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let payload = b"benchmark dae udp connector";
    let mut association =
        tokio::time::timeout(LIVE_TIMEOUT, connector.connect_udp(&echo_addr.to_string()))
            .await
            .context("dae UDP connect timed out")??;
    let sent = association
        .send(payload)
        .await
        .context("send dae UDP payload")?;
    ensure!(sent == payload.len(), "short dae UDP send");
    let mut buf = [0_u8; 1024];
    let received = tokio::time::timeout(LIVE_TIMEOUT, association.recv(&mut buf))
        .await
        .context("receive dae UDP echo timed out")??;
    ensure!(&buf[..received] == payload, "dae UDP echo mismatch");
    association.finish().context("finish dae UDP association")?;
    drop(association);

    let _ = shutdown_tx.send(());
    let server_report = tokio::time::timeout(LIVE_TIMEOUT, server_task)
        .await
        .context("dae UDP server shutdown timed out")??
        .context("dae UDP server loop failed")?;
    echo.shutdown().await.context("shutdown dae UDP echo")?;

    Ok(DaeConnectorEchoSummary {
        payload_bytes: payload.len(),
        echoed_bytes: received,
        server_accepted_connections: server_report.accepted_connections,
        server_completed_tcp_relays: 0,
        server_completed_udp_relays: server_report.completed_udp_relays,
        metrics: metrics.snapshot(),
    })
}

/// Probes whether the current host permits setting SO_MARK on TCP sockets.
#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
pub fn probe_socket_fwmark_support() -> std::io::Result<()> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket2::SockRef::from(&socket).set_mark(0x1234)
}

/// Server egress TCP relay path selected by the live benchmark helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerEgressTcpBenchmarkMode {
    /// Direct outbound target dial.
    Direct,
    /// Outbound target dial with `send_through` configured.
    SendThrough,
    /// Linux target socket mark via `fwmark`.
    Fwmark,
    /// Outbound target dial through an upstream-compatible SOCKS5 `dialer_link`.
    Socks5DialerLink,
    /// Outbound target dial through an upstream-compatible HTTP CONNECT `dialer_link`.
    HttpConnectDialerLink,
}

/// Server egress UDP relay path selected by the live benchmark helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerEgressUdpBenchmarkMode {
    /// Direct outbound target dial.
    Direct,
    /// Outbound target dial with `send_through` configured.
    SendThrough,
    /// Linux target socket mark via `fwmark`.
    Fwmark,
    /// Outbound target dial through an upstream-compatible SOCKS5 `dialer_link`.
    Socks5DialerLink,
}

/// Summary returned by one live server egress TCP benchmark helper run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerEgressTcpEchoSummary {
    /// Egress mode exercised by this helper run.
    pub mode: ServerEgressTcpBenchmarkMode,
    /// Bytes written to the proxied TCP target.
    pub payload_bytes: usize,
    /// Bytes echoed back from the proxied TCP target.
    pub echoed_bytes: usize,
    /// Server accepted Juicity connections.
    pub server_accepted_connections: u64,
    /// Server completed TCP relays.
    pub server_completed_tcp_relays: u64,
    /// SOCKS5 CONNECT requests observed by the local test proxy.
    pub socks5_connect_requests: u64,
    /// HTTP CONNECT requests observed by the local test proxy.
    pub http_connect_requests: u64,
}

/// Summary returned by one live server egress UDP benchmark helper run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerEgressUdpEchoSummary {
    /// Egress mode exercised by this helper run.
    pub mode: ServerEgressUdpBenchmarkMode,
    /// Bytes written to the proxied UDP target.
    pub payload_bytes: usize,
    /// Bytes echoed back from the proxied UDP target.
    pub echoed_bytes: usize,
    /// Server accepted Juicity connections.
    pub server_accepted_connections: u64,
    /// Server completed UDP relays.
    pub server_completed_udp_relays: u64,
    /// SOCKS5 UDP payloads observed by the local test proxy.
    pub socks5_udp_requests: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HttpConnectBenchmarkRequest {
    authority: String,
}

async fn start_http_connect_tcp_proxy() -> std::io::Result<(
    SocketAddr,
    tokio::sync::mpsc::Receiver<HttpConnectBenchmarkRequest>,
    tokio::task::JoinHandle<std::io::Result<()>>,
)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let local_addr = listener.local_addr()?;
    let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await?;
        let mut request = Vec::with_capacity(512);
        let mut byte = [0_u8; 1];
        loop {
            inbound.read_exact(&mut byte).await?;
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
            if request.len() > 8192 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP CONNECT request header too large",
                ));
            }
        }
        let request = String::from_utf8(request)
            .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidData, source))?;
        let request_line = request.lines().next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing HTTP request line")
        })?;
        let mut parts = request_line.split_whitespace();
        if parts.next() != Some("CONNECT") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid HTTP CONNECT method",
            ));
        }
        let authority = parts
            .next()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing CONNECT target")
            })?
            .to_owned();
        if parts.next() != Some("HTTP/1.1") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid HTTP CONNECT version",
            ));
        }
        request_tx
            .send(HttpConnectBenchmarkRequest {
                authority: authority.clone(),
            })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
            })?;
        let mut outbound = tokio::net::TcpStream::connect(authority.as_str()).await?;
        inbound
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
        Ok(())
    });
    Ok((local_addr, request_rx, task))
}

/// Runs one live TCP echo through the server runtime with the selected egress path.
pub async fn run_server_egress_tcp_echo(
    mode: ServerEgressTcpBenchmarkMode,
) -> anyhow::Result<ServerEgressTcpEchoSummary> {
    let echo = zuicity_testkit::TcpEchoServer::start()
        .await
        .context("start egress TCP echo")?;
    let echo_addr = echo.local_addr();
    let socks5_proxy = match mode {
        ServerEgressTcpBenchmarkMode::Socks5DialerLink => {
            Some(zuicity_testkit::start_socks5_tcp_connect_proxy().await?)
        }
        ServerEgressTcpBenchmarkMode::Direct
        | ServerEgressTcpBenchmarkMode::SendThrough
        | ServerEgressTcpBenchmarkMode::Fwmark
        | ServerEgressTcpBenchmarkMode::HttpConnectDialerLink => None,
    };
    let http_connect_proxy = match mode {
        ServerEgressTcpBenchmarkMode::HttpConnectDialerLink => {
            Some(start_http_connect_tcp_proxy().await?)
        }
        ServerEgressTcpBenchmarkMode::Direct
        | ServerEgressTcpBenchmarkMode::SendThrough
        | ServerEgressTcpBenchmarkMode::Fwmark
        | ServerEgressTcpBenchmarkMode::Socks5DialerLink => None,
    };
    let proxy_addr = socks5_proxy
        .as_ref()
        .map(|(addr, _, _)| *addr)
        .or_else(|| http_connect_proxy.as_ref().map(|(addr, _, _)| *addr));
    let expected_relay_target = proxy_addr.unwrap_or(echo_addr);
    let extra_fields = match (mode, proxy_addr) {
        (ServerEgressTcpBenchmarkMode::Direct, _) => String::new(),
        (ServerEgressTcpBenchmarkMode::SendThrough, _) => {
            r#","send_through":"127.0.0.1""#.to_owned()
        }
        (ServerEgressTcpBenchmarkMode::Fwmark, _) => r#","fwmark":"0x1234""#.to_owned(),
        (ServerEgressTcpBenchmarkMode::Socks5DialerLink, Some(proxy_addr)) => {
            format!(r#","dialer_link":"socks5://{proxy_addr}""#)
        }
        (ServerEgressTcpBenchmarkMode::HttpConnectDialerLink, Some(proxy_addr)) => {
            format!(r#","dialer_link":"http://{proxy_addr}""#)
        }
        (
            ServerEgressTcpBenchmarkMode::Socks5DialerLink
            | ServerEgressTcpBenchmarkMode::HttpConnectDialerLink,
            None,
        ) => unreachable!("proxy created above"),
    };
    let fixture = LiveServerFixture::start_with_server_extra_fields(&extra_fields)?;
    let client_fixture = fixture.client.clone();
    let bound = fixture.bound;
    let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });
    let connection = connect_client(&client_fixture).await?;
    let payload = match mode {
        ServerEgressTcpBenchmarkMode::Direct => b"benchmark server egress direct".as_slice(),
        ServerEgressTcpBenchmarkMode::SendThrough => {
            b"benchmark server egress send_through".as_slice()
        }
        ServerEgressTcpBenchmarkMode::Fwmark => b"benchmark server egress fwmark".as_slice(),
        ServerEgressTcpBenchmarkMode::Socks5DialerLink => {
            b"benchmark server egress socks5 dialer_link".as_slice()
        }
        ServerEgressTcpBenchmarkMode::HttpConnectDialerLink => {
            b"benchmark server egress http connect dialer_link".as_slice()
        }
    };
    let mut stream = connection
        .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
        .await
        .context("open egress TCP proxy stream")?;
    stream
        .write_all(payload)
        .await
        .context("write egress TCP payload")?;
    stream.finish().context("finish egress TCP stream")?;
    let echoed = stream
        .read_to_end(payload.len() + 64)
        .await
        .context("read egress TCP echo")?;
    ensure!(echoed == payload, "egress TCP echo mismatch");
    drop(stream);

    let relay = tokio::time::timeout(LIVE_TIMEOUT, server_task)
        .await
        .context("egress TCP server relay timed out")??
        .context("egress TCP server relay failed")?;
    ensure!(
        relay.target == expected_relay_target,
        "egress TCP relay target mismatch"
    );

    let mut socks5_connect_requests = 0;
    if let Some((_proxy_addr, mut requests, proxy_task)) = socks5_proxy {
        let request = tokio::time::timeout(LIVE_TIMEOUT, requests.recv())
            .await
            .context("SOCKS5 CONNECT request timed out")?
            .context("SOCKS5 CONNECT request channel closed")?;
        ensure!(
            request.target == echo_addr,
            "SOCKS5 CONNECT target mismatch"
        );
        socks5_connect_requests = 1;
        tokio::time::timeout(LIVE_TIMEOUT, proxy_task)
            .await
            .context("SOCKS5 proxy shutdown timed out")??
            .context("SOCKS5 proxy failed")?;
    }

    let mut http_connect_requests = 0;
    if let Some((_proxy_addr, mut requests, proxy_task)) = http_connect_proxy {
        let request = tokio::time::timeout(LIVE_TIMEOUT, requests.recv())
            .await
            .context("HTTP CONNECT request timed out")?
            .context("HTTP CONNECT request channel closed")?;
        ensure!(
            request.authority == echo_addr.to_string(),
            "HTTP CONNECT authority mismatch"
        );
        http_connect_requests = 1;
        tokio::time::timeout(LIVE_TIMEOUT, proxy_task)
            .await
            .context("HTTP CONNECT proxy shutdown timed out")??
            .context("HTTP CONNECT proxy failed")?;
    }

    echo.shutdown().await.context("shutdown egress TCP echo")?;
    Ok(ServerEgressTcpEchoSummary {
        mode,
        payload_bytes: payload.len(),
        echoed_bytes: echoed.len(),
        server_accepted_connections: 1,
        server_completed_tcp_relays: 1,
        socks5_connect_requests,
        http_connect_requests,
    })
}

/// Runs one live UDP echo through the server runtime with the selected egress path.
pub async fn run_server_egress_udp_echo(
    mode: ServerEgressUdpBenchmarkMode,
) -> anyhow::Result<ServerEgressUdpEchoSummary> {
    let echo = zuicity_testkit::UdpEchoServer::start()
        .await
        .context("start egress UDP echo")?;
    let echo_addr = echo.local_addr();
    let socks5_proxy = match mode {
        ServerEgressUdpBenchmarkMode::Socks5DialerLink => {
            Some(zuicity_testkit::start_socks5_udp_associate_proxy().await?)
        }
        ServerEgressUdpBenchmarkMode::Direct
        | ServerEgressUdpBenchmarkMode::SendThrough
        | ServerEgressUdpBenchmarkMode::Fwmark => None,
    };
    let proxy_addr = socks5_proxy.as_ref().map(|(addr, _, _)| *addr);
    let extra_fields = match (mode, proxy_addr) {
        (ServerEgressUdpBenchmarkMode::Direct, _) => String::new(),
        (ServerEgressUdpBenchmarkMode::SendThrough, _) => {
            r#","send_through":"127.0.0.1""#.to_owned()
        }
        (ServerEgressUdpBenchmarkMode::Fwmark, _) => r#","fwmark":"0x1234""#.to_owned(),
        (ServerEgressUdpBenchmarkMode::Socks5DialerLink, Some(proxy_addr)) => {
            format!(r#","dialer_link":"socks5://{proxy_addr}""#)
        }
        (ServerEgressUdpBenchmarkMode::Socks5DialerLink, None) => {
            unreachable!("proxy created above")
        }
    };
    let fixture = LiveServerFixture::start_with_server_extra_fields(&extra_fields)?;
    let client_fixture = fixture.client.clone();
    let bound = fixture.bound;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        bound
            .run_udp_over_stream_loop_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });
    let connection = connect_client(&client_fixture).await?;
    let payload = match mode {
        ServerEgressUdpBenchmarkMode::Direct => b"benchmark server egress udp direct".as_slice(),
        ServerEgressUdpBenchmarkMode::SendThrough => {
            b"benchmark server egress udp send_through".as_slice()
        }
        ServerEgressUdpBenchmarkMode::Fwmark => b"benchmark server egress udp fwmark".as_slice(),
        ServerEgressUdpBenchmarkMode::Socks5DialerLink => {
            b"benchmark server egress udp socks5 dialer_link".as_slice()
        }
    };
    let mut stream = connection
        .open_udp_over_stream(echo_addr.ip(), echo_addr.port())
        .await
        .context("open egress UDP stream")?;
    stream
        .send_datagram(payload)
        .await
        .context("send egress UDP payload")?;
    let echoed = stream
        .recv_datagram(payload.len() + 64)
        .await
        .context("read egress UDP echo")?;
    ensure!(
        echoed.target == echo_addr,
        "egress UDP response target mismatch"
    );
    ensure!(echoed.payload == payload, "egress UDP echo mismatch");
    stream.finish().context("finish egress UDP stream")?;
    drop(stream);
    drop(connection);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let _ = shutdown_tx.send(());
    let server_report = tokio::time::timeout(LIVE_TIMEOUT, server_task)
        .await
        .context("egress UDP server loop timed out")??
        .context("egress UDP server loop failed")?;

    let mut socks5_udp_requests = 0;
    if let Some((_proxy_addr, mut requests, proxy_task)) = socks5_proxy {
        let request = tokio::time::timeout(LIVE_TIMEOUT, requests.recv())
            .await
            .context("SOCKS5 UDP request timed out")?
            .context("SOCKS5 UDP request channel closed")?;
        ensure!(request.target == echo_addr, "SOCKS5 UDP target mismatch");
        socks5_udp_requests = 1;
        tokio::time::timeout(LIVE_TIMEOUT, proxy_task)
            .await
            .context("SOCKS5 UDP proxy shutdown timed out")??
            .context("SOCKS5 UDP proxy failed")?;
    }

    echo.shutdown().await.context("shutdown egress UDP echo")?;
    Ok(ServerEgressUdpEchoSummary {
        mode,
        payload_bytes: payload.len(),
        echoed_bytes: echoed.payload.len(),
        server_accepted_connections: server_report.accepted_connections,
        server_completed_udp_relays: server_report.completed_udp_relays,
        socks5_udp_requests,
    })
}

/// Environment variable selecting the relay soak duration, e.g. `10s`, `2m`, `30m`.
pub const SOAK_DURATION_ENV: &str = "ZUICITY_SOAK_DURATION";
/// Environment variable enabling per-wave resident-set/FD tracing during the soak.
pub const SOAK_TRACE_ENV: &str = "ZUICITY_SOAK_TRACE";
/// CI-safe default soak duration used when [`SOAK_DURATION_ENV`] is unset.
pub const SOAK_DEFAULT_DURATION: Duration = Duration::from_secs(10);
/// Concurrent TCP clients exercised in each soak churn wave.
pub const SOAK_WAVE_TCP_CLIENTS: usize = 4;
/// Concurrent UDP-over-stream clients exercised in each soak churn wave.
pub const SOAK_WAVE_UDP_CLIENTS: usize = 4;
/// Number of warmup waves whose memory/FD samples are discarded before measurement.
///
/// The allocator and async runtime retain memory through an initial ramp (~10
/// waves on Linux glibc) before resident-set size plateaus. Sampling the
/// baseline only after this ramp measures the genuinely stable operating window,
/// so the growth assertion detects real leaks rather than one-time warmup
/// retention.
pub const SOAK_WARMUP_WAVES: u32 = 12;
/// Maximum tolerated resident-set growth ratio across the measured soak window.
///
/// Allocators retain freed pages, so the soak asserts *stability* (no unbounded
/// growth) rather than a return to the baseline. A 30-minute / 4756-wave trace
/// showed resident-set size plateauing in a 108-126 MiB band (pinned at the same
/// value for hundreds of consecutive waves) after the glibc arena high-water mark
/// settled, while open descriptors stayed flat. This bound covers that settled
/// arena band; a genuine leak over thousands of waves would exceed it by
/// multiples rather than the observed ~1.28x warmup tail.
pub const SOAK_MAX_RSS_GROWTH_RATIO: f64 = 1.35;
/// Maximum tolerated open file-descriptor growth across the measured soak window.
///
/// Each fully drained churn wave must release its sockets; a steadily climbing
/// descriptor count indicates leaked sockets or unjoined tasks.
pub const SOAK_MAX_FD_GROWTH: i64 = 16;

/// Reads the current process open file-descriptor count for soak leak detection.
///
/// Linux exposes one entry per open descriptor under `/proc/self/fd`.
#[cfg(target_os = "linux")]
pub fn current_process_open_fd_count() -> anyhow::Result<u64> {
    let mut count = 0_u64;
    for entry in std::fs::read_dir("/proc/self/fd").context("read /proc/self/fd")? {
        let _ = entry.context("read /proc/self/fd entry")?;
        count += 1;
    }
    ensure!(count > 0, "process must have at least one open descriptor");
    Ok(count)
}

/// Reads the current process open file-descriptor count for soak leak detection.
#[cfg(not(target_os = "linux"))]
pub fn current_process_open_fd_count() -> anyhow::Result<u64> {
    anyhow::bail!("open file-descriptor count is only implemented on Linux")
}

/// Resolves the configured soak duration from the environment with a CI-safe default.
pub fn soak_duration_from_env() -> anyhow::Result<Duration> {
    match std::env::var(SOAK_DURATION_ENV) {
        Ok(raw) => parse_soak_duration(raw.trim()),
        Err(std::env::VarError::NotPresent) => Ok(SOAK_DEFAULT_DURATION),
        Err(error) => Err(anyhow::anyhow!("read {SOAK_DURATION_ENV}: {error}")),
    }
}

/// Parses a soak duration string such as `10s`, `90s`, `2m`, or `30m`.
pub fn parse_soak_duration(raw: &str) -> anyhow::Result<Duration> {
    ensure!(!raw.is_empty(), "soak duration must not be empty");
    let (value, unit_secs) = if let Some(rest) = raw.strip_suffix("ms") {
        (rest, 0.001_f64)
    } else if let Some(rest) = raw.strip_suffix('s') {
        (rest, 1.0_f64)
    } else if let Some(rest) = raw.strip_suffix('m') {
        (rest, 60.0_f64)
    } else if let Some(rest) = raw.strip_suffix('h') {
        (rest, 3600.0_f64)
    } else {
        (raw, 1.0_f64)
    };
    let parsed: f64 = value
        .trim()
        .parse()
        .with_context(|| format!("parse soak duration value from {raw:?}"))?;
    ensure!(
        parsed.is_finite() && parsed > 0.0,
        "soak duration must be positive: {raw:?}"
    );
    Ok(Duration::from_secs_f64(parsed * unit_secs))
}

/// Summary returned by a bounded relay soak run.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RelaySoakSummary {
    /// Requested soak duration.
    pub requested_duration: Duration,
    /// Total churn waves executed, including warmup waves.
    pub waves: u32,
    /// Warmup waves whose resource samples were discarded.
    pub warmup_waves: u32,
    /// Completed client-side TCP echo relays across all measured waves.
    pub completed_tcp_relays: u64,
    /// Completed client-side UDP echo relays across all measured waves.
    pub completed_udp_relays: u64,
    /// Total echoed payload bytes across all measured waves.
    pub bytes_echoed: u64,
    /// Resident set size sampled after warmup, in kibibytes.
    pub baseline_rss_kib: u64,
    /// Resident set size sampled at the end of the soak, in kibibytes.
    pub final_rss_kib: u64,
    /// Open file descriptors sampled after warmup.
    pub baseline_fd_count: u64,
    /// Open file descriptors sampled at the end of the soak.
    pub final_fd_count: u64,
}

impl RelaySoakSummary {
    /// Resident-set growth factor across the measured soak window.
    #[must_use]
    pub fn rss_growth_ratio(&self) -> f64 {
        if self.baseline_rss_kib == 0 {
            return f64::INFINITY;
        }
        self.final_rss_kib as f64 / self.baseline_rss_kib as f64
    }

    /// Open file-descriptor growth across the measured soak window.
    #[must_use]
    pub fn fd_growth(&self) -> i64 {
        self.final_fd_count as i64 - self.baseline_fd_count as i64
    }
}

/// Runs a bounded TCP+UDP relay soak with connection churn and leak detection.
///
/// The soak repeatedly drives full server-lifecycle churn waves until the
/// configured duration elapses, discarding the first [`SOAK_WARMUP_WAVES`] waves
/// before sampling resident-set size and open file descriptors. Every wave must
/// fully complete (zero errors); after warmup, resident-set growth must stay
/// within [`SOAK_MAX_RSS_GROWTH_RATIO`] and file-descriptor growth within
/// [`SOAK_MAX_FD_GROWTH`], proving no leaks, hangs, or descriptor exhaustion over
/// sustained operation.
pub async fn run_relay_soak(duration: Duration) -> anyhow::Result<RelaySoakSummary> {
    ensure!(
        duration >= Duration::from_millis(1),
        "soak duration must be positive"
    );

    let started = Instant::now();
    let mut waves = 0_u32;
    let mut completed_tcp_relays = 0_u64;
    let mut completed_udp_relays = 0_u64;
    let mut bytes_echoed = 0_u64;
    let mut baseline_rss_kib = 0_u64;
    let mut baseline_fd_count = 0_u64;
    let trace = std::env::var(SOAK_TRACE_ENV).is_ok();

    loop {
        let fixture = LiveServerFixture::start().context("start soak server fixture")?;
        let summary =
            run_server_lifecycle_churn(fixture, SOAK_WAVE_TCP_CLIENTS, SOAK_WAVE_UDP_CLIENTS)
                .await
                .with_context(|| format!("soak churn wave {waves} failed"))?;
        completed_tcp_relays += summary.completed_tcp_relays as u64;
        completed_udp_relays += summary.completed_udp_relays as u64;
        bytes_echoed += summary.bytes_echoed as u64;
        waves += 1;

        if waves == SOAK_WARMUP_WAVES {
            baseline_rss_kib = current_process_memory_snapshot()?.resident_set_kib;
            baseline_fd_count = current_process_open_fd_count()?;
        }

        if trace {
            let rss = current_process_memory_snapshot()?.resident_set_kib;
            let fd = current_process_open_fd_count()?;
            eprintln!("soak_wave={waves} rss_kib={rss} fd={fd}");
        }

        if started.elapsed() >= duration && waves > SOAK_WARMUP_WAVES {
            break;
        }
    }

    // Ensure a baseline exists even when the duration is shorter than warmup.
    if baseline_rss_kib == 0 {
        baseline_rss_kib = current_process_memory_snapshot()?.resident_set_kib;
        baseline_fd_count = current_process_open_fd_count()?;
    }

    let final_rss_kib = current_process_memory_snapshot()?.resident_set_kib;
    let final_fd_count = current_process_open_fd_count()?;

    let summary = RelaySoakSummary {
        requested_duration: duration,
        waves,
        warmup_waves: SOAK_WARMUP_WAVES,
        completed_tcp_relays,
        completed_udp_relays,
        bytes_echoed,
        baseline_rss_kib,
        final_rss_kib,
        baseline_fd_count,
        final_fd_count,
    };

    ensure!(
        summary.completed_tcp_relays > 0 && summary.completed_udp_relays > 0,
        "soak must complete TCP and UDP relays: {summary:?}"
    );
    ensure!(
        summary.bytes_echoed > 0,
        "soak must echo payload bytes: {summary:?}"
    );
    ensure!(
        summary.rss_growth_ratio() <= SOAK_MAX_RSS_GROWTH_RATIO,
        "soak resident-set growth {:.3}x exceeds {SOAK_MAX_RSS_GROWTH_RATIO}x: {summary:?}",
        summary.rss_growth_ratio()
    );
    ensure!(
        summary.fd_growth() <= SOAK_MAX_FD_GROWTH,
        "soak file-descriptor growth {} exceeds {SOAK_MAX_FD_GROWTH}: {summary:?}",
        summary.fd_growth()
    );

    Ok(summary)
}

/// Fixed payload sizes (bytes) covering latency-bound, nominal, and bandwidth-bound regimes.
pub const THROUGHPUT_MATRIX_PAYLOAD_SIZES: [usize; 3] = [64, 1024, 64 * 1024];
/// Fixed concurrency levels for the throughput matrix.
pub const THROUGHPUT_MATRIX_CONCURRENCY: [usize; 3] = [1, 16, 64];
/// Maximum concurrency accepted by the throughput-matrix cell helper.
pub const THROUGHPUT_MATRIX_CONCURRENCY_LIMIT: usize = 64;

/// One cell of the finite TCP throughput matrix.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ThroughputMatrixCell {
    /// Payload size in bytes for this cell.
    pub payload_size: usize,
    /// Concurrent client count for this cell.
    pub concurrency: usize,
    /// Completed TCP echo relays in this cell.
    pub completed_relays: usize,
    /// Total echoed payload bytes in this cell.
    pub bytes_echoed: usize,
    /// Wall-clock elapsed time for this cell.
    pub elapsed: Duration,
}

impl ThroughputMatrixCell {
    /// Approximate echoed throughput in mebibytes per second for this cell.
    #[must_use]
    pub fn mib_per_second(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs <= 0.0 {
            return 0.0;
        }
        (self.bytes_echoed as f64 / (1024.0 * 1024.0)) / secs
    }
}

/// Timeout for a single throughput-matrix cell.
///
/// Generous enough that the 64-concurrency cell still completes when the
/// benchmark suite runs it back-to-back with the resource-heavy soak under
/// `--test-threads=1`. A genuinely broken relay never completes regardless of
/// timeout, so this cannot mask a real failure.
pub const THROUGHPUT_MATRIX_CELL_TIMEOUT: Duration = Duration::from_secs(45);

/// Runs one finite TCP throughput-matrix cell through a live benchmark server.
///
/// Each of the `concurrency` clients performs a single proxied TCP echo of a
/// `payload_size`-byte payload. Concurrency is capped by
/// [`CONCURRENT_TCP_CLIENT_LIMIT`]; the published matrix concurrency levels stay
/// within that bound.
pub async fn run_tcp_throughput_cell(
    fixture: LiveServerFixture,
    payload_size: usize,
    concurrency: usize,
) -> anyhow::Result<ThroughputMatrixCell> {
    ensure!(payload_size > 0, "payload size must be non-zero");
    ensure!(concurrency > 0, "concurrency must be non-zero");
    ensure!(
        concurrency <= THROUGHPUT_MATRIX_CONCURRENCY_LIMIT,
        "concurrency {concurrency} exceeds throughput limit {THROUGHPUT_MATRIX_CONCURRENCY_LIMIT}"
    );

    let echo = zuicity_testkit::TcpEchoServer::start()
        .await
        .context("start throughput TCP echo")?;
    let echo_addr = echo.local_addr();
    let client_fixture = fixture.client.clone();
    let bound = fixture.bound;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        bound
            .run_proxy_loop_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let started = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for client_id in 0..concurrency {
        let client_fixture = client_fixture.clone();
        tasks.spawn(async move {
            tokio::time::timeout(THROUGHPUT_MATRIX_CELL_TIMEOUT, async move {
                let connection = connect_client(&client_fixture).await?;
                let mut payload = vec![0_u8; payload_size];
                for (index, byte) in payload.iter_mut().enumerate() {
                    *byte = (client_id as u8).wrapping_add(index as u8);
                }
                let mut stream = connection
                    .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
                    .await
                    .context("open throughput TCP proxy stream")?;
                stream
                    .write_all(&payload)
                    .await
                    .context("write throughput TCP payload")?;
                stream.finish().context("finish throughput TCP stream")?;
                let echoed = stream
                    .read_to_end(payload_size + 64)
                    .await
                    .context("read throughput TCP echo")?;
                ensure!(echoed == payload, "throughput TCP echo mismatch");
                Ok::<_, anyhow::Error>(echoed.len())
            })
            .await
            .context("throughput TCP client timed out")?
        });
    }

    let mut completed_relays = 0_usize;
    let mut bytes_echoed = 0_usize;
    let mut first_error = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(bytes)) => {
                completed_relays += 1;
                bytes_echoed += bytes;
            }
            Ok(Err(error)) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error.into());
                }
            }
        }
    }
    let elapsed = started.elapsed();

    let _ = shutdown_tx.send(());
    let _server_report = tokio::time::timeout(THROUGHPUT_MATRIX_CELL_TIMEOUT, server_task)
        .await
        .context("throughput server shutdown timed out")??
        .context("throughput server loop failed")?;
    echo.shutdown()
        .await
        .context("shutdown throughput TCP echo")?;

    if let Some(error) = first_error {
        return Err(error);
    }

    ensure!(
        completed_relays == concurrency,
        "throughput cell completed {completed_relays} of {concurrency} relays"
    );

    Ok(ThroughputMatrixCell {
        payload_size,
        concurrency,
        completed_relays,
        bytes_echoed,
        elapsed,
    })
}
