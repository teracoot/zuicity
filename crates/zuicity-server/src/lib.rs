//! Embeddable Zuicity server runtime boundaries.

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use zuicity_config::ServerConfig;
use zuicity_protocol::AtomicCounter64;
use zuicity_transport::{
    DEFAULT_NAT_TIMEOUT, JuicityQuicServer, ProxyEgressPolicy, ProxyProtocol, ProxyRelayReport,
    StreamPolicy, TcpProxyRelayReport, TlsPolicy, UdpOverStreamRelayReport,
    run_tuic_udp_datagram_relay,
};

const PROXY_SHUTDOWN_RELAY_DRAIN_TIMEOUT: Duration = Duration::from_millis(50);

/// Server runtime options independent from CLI parsing.
#[derive(Clone, Debug)]
pub struct ServerRuntimeConfig {
    /// Validated server config.
    pub config: ServerConfig,
    /// TLS policy.
    pub tls: TlsPolicy,
    /// QUIC stream policy.
    pub streams: StreamPolicy,
}

impl ServerRuntimeConfig {
    /// Builds runtime options from validated server config and upstream default policies.
    #[must_use]
    pub fn from_config(config: ServerConfig) -> Self {
        Self {
            config,
            tls: TlsPolicy::upstream(),
            streams: StreamPolicy::upstream(),
        }
    }

    /// Returns the server egress policy derived from upstream-compatible config.
    #[must_use]
    pub fn egress_policy(&self) -> ServerEgressPolicy {
        ServerEgressPolicy::from_config(&self.config)
    }
}

/// Server egress policy values that affect outbound dialing decisions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerEgressPolicy {
    /// Blocks underlay UDP flows whose target port is 443.
    pub block_underlay_udp443: bool,
    /// Optional source IP used for outbound target dials.
    pub send_through: Option<IpAddr>,
    /// Optional packet mark applied to outbound target sockets.
    pub fwmark: Option<u32>,
    /// Optional upstream-compatible outbound proxy link for target dials.
    pub dialer_link: Option<String>,
}

impl ServerEgressPolicy {
    /// Builds egress policy from validated server config.
    #[must_use]
    pub fn from_config(config: &ServerConfig) -> Self {
        Self {
            block_underlay_udp443: config.raw.disable_outbound_udp443,
            send_through: config.send_through,
            fwmark: config.fwmark,
            dialer_link: (!config.raw.dialer_link.is_empty())
                .then(|| config.raw.dialer_link.clone()),
        }
    }

    /// Returns true when upstream would reject this underlay UDP target port.
    #[must_use]
    pub const fn blocks_underlay_udp_target_port(&self, target_port: u16) -> bool {
        self.block_underlay_udp443 && target_port == 443
    }

    /// Returns the transport-level proxy egress policy.
    #[must_use]
    pub fn transport_policy(&self) -> Result<ProxyEgressPolicy, zuicity_transport::TransportError> {
        let dialer_link = self
            .dialer_link
            .as_deref()
            .map(zuicity_transport::ProxyDialerLink::parse)
            .transpose()?;
        Ok(ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
            self.send_through,
            self.fwmark,
            dialer_link,
        ))
    }
}

/// Embeddable server runtime handle.
#[derive(Clone, Debug)]
pub struct ServerRuntime {
    config: ServerRuntimeConfig,
}

impl ServerRuntime {
    /// Creates a server runtime handle without starting network IO.
    #[must_use]
    pub fn new(config: ServerRuntimeConfig) -> Self {
        Self { config }
    }

    /// Returns the runtime config.
    #[must_use]
    pub const fn config(&self) -> &ServerRuntimeConfig {
        &self.config
    }

    /// Binds a QUIC server endpoint from PEM certificate material.
    pub fn bind_with_pem(
        &self,
        addr: SocketAddr,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<BoundServerRuntime, ServerError> {
        let server = JuicityQuicServer::bind_with_pem(addr, cert_pem, key_pem)?;
        let local_addr = server.local_addr()?;
        tracing::info!(listen = %local_addr, "Listen at {local_addr}");
        let users = self
            .config
            .config
            .users
            .iter()
            .map(|(uuid, password)| (*uuid, password.clone()))
            .collect();
        Ok(BoundServerRuntime {
            server,
            users,
            egress: self.config.egress_policy().transport_policy()?,
        })
    }
}

/// Cloneable server metrics counters for embedders and runtime hooks.
#[derive(Clone, Debug, Default)]
pub struct ServerMetrics {
    inner: Arc<ServerMetricsInner>,
}

#[derive(Debug, Default)]
struct ServerMetricsInner {
    accepted_connections: AtomicCounter64,
    rejected_connections: AtomicCounter64,
    active_connections: AtomicCounter64,
    completed_tcp_relays: AtomicCounter64,
    completed_udp_relays: AtomicCounter64,
    failed_proxy_streams: AtomicCounter64,
    bytes_from_client: AtomicCounter64,
    bytes_from_target: AtomicCounter64,
}

impl ServerMetrics {
    /// Records an accepted authenticated QUIC connection.
    pub fn connection_accepted(&self) {
        self.inner
            .accepted_connections
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .active_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records a rejected authentication attempt.
    pub fn connection_rejected(&self) {
        self.inner
            .rejected_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records a completed authenticated QUIC connection lifecycle.
    pub fn connection_closed(&self) {
        self.inner
            .active_connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_sub(1)
            })
            .ok();
    }

    /// Records a completed TCP relay and its byte counters.
    pub fn tcp_relay_completed(&self, bytes_from_client: u64, bytes_from_target: u64) {
        self.inner
            .completed_tcp_relays
            .fetch_add(1, Ordering::Relaxed);
        self.bytes_from_client(bytes_from_client);
        self.bytes_from_target(bytes_from_target);
    }

    /// Records a completed UDP-over-stream relay and its byte counters.
    pub fn udp_relay_completed(&self, bytes_from_client: u64, bytes_from_target: u64) {
        self.inner
            .completed_udp_relays
            .fetch_add(1, Ordering::Relaxed);
        self.bytes_from_client(bytes_from_client);
        self.bytes_from_target(bytes_from_target);
    }

    /// Records a proxy stream failure isolated by the server loop.
    pub fn proxy_stream_failed(&self) {
        self.inner
            .failed_proxy_streams
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records bytes copied from Juicity clients to target endpoints.
    pub fn bytes_from_client(&self, bytes: u64) {
        self.inner
            .bytes_from_client
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Records bytes copied from target endpoints back to Juicity clients.
    pub fn bytes_from_target(&self, bytes: u64) {
        self.inner
            .bytes_from_target
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Returns a stable point-in-time server metrics snapshot.
    #[must_use]
    pub fn snapshot(&self) -> ServerMetricsSnapshot {
        ServerMetricsSnapshot {
            accepted_connections: self.inner.accepted_connections.load(Ordering::Relaxed),
            rejected_connections: self.inner.rejected_connections.load(Ordering::Relaxed),
            active_connections: self.inner.active_connections.load(Ordering::Relaxed),
            completed_tcp_relays: self.inner.completed_tcp_relays.load(Ordering::Relaxed),
            completed_udp_relays: self.inner.completed_udp_relays.load(Ordering::Relaxed),
            failed_proxy_streams: self.inner.failed_proxy_streams.load(Ordering::Relaxed),
            bytes_from_client: self.inner.bytes_from_client.load(Ordering::Relaxed),
            bytes_from_target: self.inner.bytes_from_target.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time server runtime metrics snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServerMetricsSnapshot {
    /// Authenticated QUIC connections accepted by server loops.
    pub accepted_connections: u64,
    /// QUIC connections rejected before proxy streams were accepted.
    pub rejected_connections: u64,
    /// Authenticated QUIC connections currently owned by server loops.
    pub active_connections: u64,
    /// TCP proxy streams relayed to completion.
    pub completed_tcp_relays: u64,
    /// UDP-over-stream relays completed by server loops.
    pub completed_udp_relays: u64,
    /// Proxy streams that failed before completing a relay.
    pub failed_proxy_streams: u64,
    /// Bytes copied from Juicity clients to targets.
    pub bytes_from_client: u64,
    /// Bytes copied from targets back to Juicity clients.
    pub bytes_from_target: u64,
}

/// Server runtime hooks shared by embedders, tests, and future metrics exporters.
#[derive(Clone, Debug, Default)]
pub struct ServerRuntimeHooks {
    metrics: ServerMetrics,
}

impl ServerRuntimeHooks {
    /// Creates runtime hooks backed by the provided metrics handle.
    #[must_use]
    pub fn new(metrics: ServerMetrics) -> Self {
        Self { metrics }
    }

    /// Returns the metrics handle used by these hooks.
    #[must_use]
    pub const fn metrics(&self) -> &ServerMetrics {
        &self.metrics
    }

    fn connection_accepted(&self) -> ServerConnectionGuard {
        self.metrics.connection_accepted();
        ServerConnectionGuard {
            hooks: self.clone(),
        }
    }

    fn connection_rejected(&self) {
        self.metrics.connection_rejected();
    }

    fn proxy_stream_failed(&self) {
        self.metrics.proxy_stream_failed();
    }

    fn proxy_relay_completed(&self, relay: &ProxyRelayReport) {
        match relay {
            ProxyRelayReport::Tcp(report) => self
                .metrics
                .tcp_relay_completed(report.bytes_from_client, report.bytes_from_target),
            ProxyRelayReport::Udp(report) => self
                .metrics
                .udp_relay_completed(report.bytes_from_client, report.bytes_from_target),
        }
    }

    fn tcp_relay_completed(&self, report: &TcpProxyRelayReport) {
        self.metrics
            .tcp_relay_completed(report.bytes_from_client, report.bytes_from_target);
    }

    fn udp_relay_completed(&self, report: &UdpOverStreamRelayReport) {
        self.metrics
            .udp_relay_completed(report.bytes_from_client, report.bytes_from_target);
    }
}

struct ServerConnectionGuard {
    hooks: ServerRuntimeHooks,
}

impl Drop for ServerConnectionGuard {
    fn drop(&mut self) {
        self.hooks.metrics.connection_closed();
    }
}

/// Bound embeddable server runtime.
#[derive(Debug)]
pub struct BoundServerRuntime {
    server: JuicityQuicServer,
    users: Vec<(uuid::Uuid, String)>,
    egress: ProxyEgressPolicy,
}

impl BoundServerRuntime {
    /// Returns the local QUIC UDP socket address.
    pub fn local_addr(&self) -> Result<SocketAddr, ServerError> {
        Ok(self.server.local_addr()?)
    }

    /// Accepts one authenticated connection and relays one TCP proxy stream.
    pub async fn accept_one_tcp_proxy(self) -> Result<TcpProxyRelayReport, ServerError> {
        self.accept_one_tcp_proxy_ref().await
    }

    /// Accepts one authenticated connection and relays one UDP-over-stream session.
    pub async fn accept_one_udp_over_stream(self) -> Result<UdpOverStreamRelayReport, ServerError> {
        self.accept_one_udp_over_stream_ref().await
    }

    /// Accepts one authenticated UDP-over-stream session with an explicit idle timeout.
    pub async fn accept_one_udp_over_stream_with_idle_timeout(
        self,
        idle_timeout: Duration,
    ) -> Result<UdpOverStreamRelayReport, ServerError> {
        self.accept_one_udp_over_stream_ref_with_idle_timeout(idle_timeout)
            .await
    }

    /// Runs a TCP proxy accept loop until the shutdown future resolves.
    pub async fn run_tcp_proxy_loop_until(
        self,
        shutdown: impl Future<Output = ()>,
    ) -> Result<ServerTcpLoopReport, ServerError> {
        self.run_tcp_proxy_loop_until_with_hooks(shutdown, ServerRuntimeHooks::default())
            .await
    }

    /// Runs a TCP proxy accept loop with metrics hooks until shutdown resolves.
    pub async fn run_tcp_proxy_loop_until_with_hooks(
        self,
        shutdown: impl Future<Output = ()>,
        hooks: ServerRuntimeHooks,
    ) -> Result<ServerTcpLoopReport, ServerError> {
        let mut shutdown = std::pin::pin!(shutdown);
        let users = std::sync::Arc::new(self.users.clone());
        let mut accept_task = spawn_authenticated_accept_task(&self.server, &users);
        let mut relay_tasks = tokio::task::JoinSet::new();
        let mut report = ServerTcpLoopReport::default();
        let mut accepting = true;

        loop {
            tokio::select! {
                biased;
                () = &mut shutdown, if accepting => {
                    accepting = false;
                    accept_task.abort();
                }
                accepted = &mut accept_task, if accepting => {
                    match accepted {
                        Ok(Ok(connection)) => {
                            report.accepted_connections += 1;
                            let connection_guard = hooks.connection_accepted();
                            let egress = self.egress.clone();
                            let relay_hooks = hooks.clone();
                            relay_tasks.spawn(async move {
                                let _connection_guard = connection_guard;
                                let relay = connection
                                    .accept_tcp_proxy_once_with_egress(egress)
                                    .await?;
                                relay_hooks.tcp_relay_completed(&relay);
                                Ok::<_, ServerError>(relay)
                            });
                        }
                        Ok(Err(ServerError::Transport(error))) if proxy_connection_closed(&error) => {}
                        Ok(Err(error)) => return Err(error),
                        Err(error) => return Err(error.into()),
                    }
                    accept_task = spawn_authenticated_accept_task(&self.server, &users);
                }
                joined = relay_tasks.join_next(), if !relay_tasks.is_empty() => {
                    if let Some(relay) = joined {
                        match relay {
                            Ok(Ok(relay)) => {
                                trace_tcp_proxy_relay(&relay);
                                report.completed_tcp_relays += 1;
                                report.bytes_from_client += relay.bytes_from_client;
                                report.bytes_from_target += relay.bytes_from_target;
                            }
                            Ok(Err(ServerError::Transport(error))) if proxy_connection_closed(&error) => {}
                            Ok(Err(error)) => return Err(error),
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
                else => {
                    if !accepting {
                        return Ok(report);
                    }
                }
            }
        }
    }

    /// Runs a UDP-over-stream accept loop until the shutdown future resolves.
    pub async fn run_udp_over_stream_loop_until(
        self,
        shutdown: impl Future<Output = ()>,
    ) -> Result<ServerUdpLoopReport, ServerError> {
        self.run_udp_over_stream_loop_until_with_hooks(shutdown, ServerRuntimeHooks::default())
            .await
    }

    /// Runs a UDP-over-stream accept loop with metrics hooks until shutdown resolves.
    pub async fn run_udp_over_stream_loop_until_with_hooks(
        self,
        shutdown: impl Future<Output = ()>,
        hooks: ServerRuntimeHooks,
    ) -> Result<ServerUdpLoopReport, ServerError> {
        let mut shutdown = std::pin::pin!(shutdown);
        let users = std::sync::Arc::new(self.users.clone());
        let mut accept_task = spawn_authenticated_accept_task(&self.server, &users);
        let mut relay_tasks = tokio::task::JoinSet::new();
        let mut report = ServerUdpLoopReport::default();
        let mut accepting = true;

        loop {
            tokio::select! {
                biased;
                () = &mut shutdown, if accepting => {
                    accepting = false;
                    accept_task.abort();
                }
                accepted = &mut accept_task, if accepting => {
                    match accepted {
                        Ok(Ok(connection)) => {
                            report.accepted_connections += 1;
                            let connection_guard = hooks.connection_accepted();
                            let egress = self.egress.clone();
                            let relay_hooks = hooks.clone();
                            relay_tasks.spawn(async move {
                                let _connection_guard = connection_guard;
                                run_udp_over_stream_connection(connection, egress, relay_hooks).await
                            });
                        }
                        Ok(Err(ServerError::Transport(error))) if proxy_connection_closed(&error) => {}
                        Ok(Err(error)) => return Err(error),
                        Err(error) => return Err(error.into()),
                    }
                    accept_task = spawn_authenticated_accept_task(&self.server, &users);
                }
                joined = relay_tasks.join_next(), if !relay_tasks.is_empty() => {
                    if let Some(relay) = joined {
                        match relay {
                            Ok(Ok(connection_report)) => {
                                report.completed_udp_relays += connection_report.completed_udp_relays;
                                report.bytes_from_client += connection_report.bytes_from_client;
                                report.bytes_from_target += connection_report.bytes_from_target;
                            }
                            Ok(Err(ServerError::Transport(error))) if proxy_connection_closed(&error) => {}
                            Ok(Err(error)) => return Err(error),
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
                else => {
                    if !accepting {
                        return Ok(report);
                    }
                }
            }
        }
    }

    /// Runs a classified TCP and UDP proxy accept loop until shutdown resolves.
    pub async fn run_proxy_loop_until(
        self,
        shutdown: impl Future<Output = ()>,
    ) -> Result<ServerProxyLoopReport, ServerError> {
        self.run_proxy_loop_until_with_hooks(shutdown, ServerRuntimeHooks::default())
            .await
    }

    /// Runs a classified TCP and UDP proxy accept loop with metrics hooks until shutdown resolves.
    pub async fn run_proxy_loop_until_with_hooks(
        self,
        shutdown: impl Future<Output = ()>,
        hooks: ServerRuntimeHooks,
    ) -> Result<ServerProxyLoopReport, ServerError> {
        let mut shutdown = std::pin::pin!(shutdown);
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let users = std::sync::Arc::new(self.users.clone());
        let mut accept_task = spawn_authenticated_accept_task(&self.server, &users);
        let mut tasks = tokio::task::JoinSet::new();
        let mut report = ServerProxyLoopReport::default();
        let mut accepting = true;

        loop {
            tokio::select! {
                biased;
                () = &mut shutdown, if accepting => {
                    accepting = false;
                    accept_task.abort();
                    let _ = shutdown_tx.send(true);
                }
                accepted = &mut accept_task, if accepting => {
                    match accepted {
                        Ok(Ok(connection)) => {
                            report.accepted_connections += 1;
                            let connection_guard = hooks.connection_accepted();
                            let shutdown_rx = shutdown_tx.subscribe();
                            let egress = self.egress.clone();
                            let connection_hooks = hooks.clone();
                            tasks.spawn(async move {
                                run_authenticated_proxy_connection_until(
                                    connection,
                                    shutdown_rx,
                                    egress,
                                    connection_hooks,
                                    connection_guard,
                                ).await
                            });
                        }
                        Ok(Err(ServerError::Transport(zuicity_transport::TransportError::AuthenticationRejected))) => {
                            hooks.connection_rejected();
                            report.rejected_connections += 1;
                        }
                        Ok(Err(ServerError::Transport(error))) if proxy_connection_closed(&error) => {}
                        Ok(Err(error)) => return Err(error),
                        Err(error) => return Err(error.into()),
                    }
                    accept_task = spawn_authenticated_accept_task(&self.server, &users);
                }
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(connection_report) = joined {
                        report.merge(connection_report??);
                    }
                }
                else => {
                    if !accepting {
                        return Ok(report);
                    }
                }
            }
        }
    }

    async fn accept_one_tcp_proxy_ref(&self) -> Result<TcpProxyRelayReport, ServerError> {
        let connection = self.accept_authenticated_connection().await?;
        let report = connection
            .accept_tcp_proxy_once_with_egress(self.egress.clone())
            .await?;
        trace_tcp_proxy_relay(&report);
        Ok(report)
    }

    async fn accept_one_udp_over_stream_ref(
        &self,
    ) -> Result<UdpOverStreamRelayReport, ServerError> {
        self.accept_one_udp_over_stream_ref_with_idle_timeout(DEFAULT_NAT_TIMEOUT)
            .await
    }

    async fn accept_one_udp_over_stream_ref_with_idle_timeout(
        &self,
        idle_timeout: Duration,
    ) -> Result<UdpOverStreamRelayReport, ServerError> {
        let connection = self.accept_authenticated_connection().await?;
        let report = connection
            .accept_udp_over_stream_with_idle_timeout_and_egress(idle_timeout, self.egress.clone())
            .await?;
        trace_udp_over_stream_relay(&report);
        Ok(report)
    }

    async fn accept_authenticated_connection(
        &self,
    ) -> Result<zuicity_transport::AuthenticatedConnection, ServerError> {
        if self.users.is_empty() {
            return Err(ServerError::NoUsersConfigured);
        }
        let accepted = self
            .server
            .accept_authenticated_with(
                self.users
                    .iter()
                    .map(|(uuid, password)| (*uuid, password.as_bytes())),
            )
            .await
            .map_err(ServerError::from);
        if let Err(error) = &accepted {
            trace_authenticated_accept_error(error);
        }
        accepted
    }
}

/// Aggregate report for a TCP proxy server loop.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServerTcpLoopReport {
    /// Authenticated QUIC connections accepted by the loop.
    pub accepted_connections: u64,
    /// TCP proxy streams relayed to completion.
    pub completed_tcp_relays: u64,
    /// Bytes copied from QUIC clients to TCP targets.
    pub bytes_from_client: u64,
    /// Bytes copied from TCP targets back to QUIC clients.
    pub bytes_from_target: u64,
}

/// Aggregate report for a UDP-over-stream server loop.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServerUdpLoopReport {
    /// Authenticated QUIC connections accepted by the loop.
    pub accepted_connections: u64,
    /// UDP-over-stream relays completed by the loop.
    pub completed_udp_relays: u64,
    /// Bytes copied from QUIC clients to UDP targets.
    pub bytes_from_client: u64,
    /// Bytes copied from UDP targets back to QUIC clients.
    pub bytes_from_target: u64,
}

/// Aggregate report for a classified TCP and UDP proxy server loop.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServerProxyLoopReport {
    /// Authenticated QUIC connections accepted by the loop.
    pub accepted_connections: u64,
    /// QUIC connections rejected before proxy streams were accepted.
    pub rejected_connections: u64,
    /// TCP proxy streams relayed to completion.
    pub completed_tcp_relays: u64,
    /// UDP-over-stream relays completed by the loop.
    pub completed_udp_relays: u64,
    /// Proxy streams that failed before completing a relay.
    pub failed_proxy_streams: u64,
    /// Bytes copied from QUIC clients to targets.
    pub bytes_from_client: u64,
    /// Bytes copied from targets back to QUIC clients.
    pub bytes_from_target: u64,
}

fn spawn_authenticated_accept_task(
    server: &JuicityQuicServer,
    users: &std::sync::Arc<Vec<(uuid::Uuid, String)>>,
) -> tokio::task::JoinHandle<Result<zuicity_transport::AuthenticatedConnection, ServerError>> {
    tokio::spawn(accept_authenticated_connection(
        server.clone(),
        std::sync::Arc::clone(users),
    ))
}

async fn accept_authenticated_connection(
    server: JuicityQuicServer,
    users: std::sync::Arc<Vec<(uuid::Uuid, String)>>,
) -> Result<zuicity_transport::AuthenticatedConnection, ServerError> {
    if users.is_empty() {
        return Err(ServerError::NoUsersConfigured);
    }
    let accepted = server
        .accept_authenticated_with(
            users
                .iter()
                .map(|(uuid, password)| (*uuid, password.as_bytes())),
        )
        .await
        .map_err(ServerError::from);
    if let Err(error) = &accepted {
        trace_authenticated_accept_error(error);
    }
    accepted
}

impl ServerProxyLoopReport {
    fn add_relay(&mut self, relay: ProxyRelayReport) {
        self.bytes_from_client += relay.bytes_from_client();
        self.bytes_from_target += relay.bytes_from_target();
        match relay {
            ProxyRelayReport::Tcp(_) => self.completed_tcp_relays += 1,
            ProxyRelayReport::Udp(_) => self.completed_udp_relays += 1,
        }
    }

    fn merge(&mut self, other: Self) {
        self.accepted_connections += other.accepted_connections;
        self.rejected_connections += other.rejected_connections;
        self.completed_tcp_relays += other.completed_tcp_relays;
        self.completed_udp_relays += other.completed_udp_relays;
        self.failed_proxy_streams += other.failed_proxy_streams;
        self.bytes_from_client += other.bytes_from_client;
        self.bytes_from_target += other.bytes_from_target;
    }
}

/// Per-connection UDP-over-stream relay totals aggregated across all streams
/// multiplexed on one authenticated QUIC connection.
#[derive(Default)]
struct UdpConnectionReport {
    completed_udp_relays: u64,
    bytes_from_client: u64,
    bytes_from_target: u64,
}

/// Accepts and relays every proxy stream a single authenticated connection opens
/// until it closes. Each stream is relayed on its own task, so one shared QUIC
/// connection serves many concurrent SOCKS5 UDP associations instead of only the
/// first one. Only UDP relay byte totals are aggregated into the report.
async fn run_udp_over_stream_connection(
    connection: zuicity_transport::AuthenticatedConnection,
    egress: ProxyEgressPolicy,
    hooks: ServerRuntimeHooks,
) -> Result<UdpConnectionReport, ServerError> {
    let mut relays = tokio::task::JoinSet::new();
    let mut report = UdpConnectionReport::default();
    loop {
        tokio::select! {
            accepted = connection.accept_proxy_stream() => {
                match accepted {
                    Ok(stream) => {
                        let relay_egress = egress.clone();
                        relays.spawn(async move {
                            stream
                                .relay_with_idle_timeout_and_egress(
                                    DEFAULT_NAT_TIMEOUT,
                                    relay_egress,
                                )
                                .await
                        });
                    }
                    Err(error) if proxy_connection_closed(&error) => break,
                    Err(error) => return Err(error.into()),
                }
            }
            joined = relays.join_next(), if !relays.is_empty() => {
                if let Some(joined) = joined {
                    accumulate_udp_relay(&mut report, &hooks, joined?);
                }
            }
        }
    }
    while let Some(joined) = relays.join_next().await {
        accumulate_udp_relay(&mut report, &hooks, joined?);
    }
    Ok(report)
}

fn accumulate_udp_relay(
    report: &mut UdpConnectionReport,
    hooks: &ServerRuntimeHooks,
    relay: Result<zuicity_transport::ProxyRelayReport, zuicity_transport::TransportError>,
) {
    match relay {
        Ok(zuicity_transport::ProxyRelayReport::Udp(relay)) => {
            hooks.udp_relay_completed(&relay);
            trace_udp_over_stream_relay(&relay);
            report.completed_udp_relays += 1;
            report.bytes_from_client += relay.bytes_from_client;
            report.bytes_from_target += relay.bytes_from_target;
        }
        Ok(zuicity_transport::ProxyRelayReport::Tcp(_)) => {}
        Err(error) if proxy_connection_closed(&error) => {}
        Err(error) => {
            tracing::warn!(error = %error, "handleUdpStream");
        }
    }
}

async fn run_authenticated_proxy_connection_until(
    connection: zuicity_transport::AuthenticatedConnection,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    egress: ProxyEgressPolicy,
    hooks: ServerRuntimeHooks,
    connection_guard: ServerConnectionGuard,
) -> Result<ServerProxyLoopReport, ServerError> {
    let _connection_guard = connection_guard;
    let mut report = ServerProxyLoopReport::default();
    let mut relays = tokio::task::JoinSet::new();

    let tuic_udp_relay = if connection.protocol() == ProxyProtocol::Tuic {
        let quic = connection.as_quinn().clone();
        let relay_egress = egress.clone();
        let mut relay_shutdown = shutdown.clone();
        Some(tokio::spawn(async move {
            let shutdown_signal = async move {
                while relay_shutdown.changed().await.is_ok() {
                    if *relay_shutdown.borrow() {
                        break;
                    }
                }
            };
            run_tuic_udp_datagram_relay(quic, relay_egress, shutdown_signal).await
        }))
    } else {
        None
    };

    let shutdown_requested = loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    break true;
                }
            }
            accepted = connection.accept_proxy_stream() => {
                match accepted {
                    Ok(stream) => {
                        let relay_egress = egress.clone();
                        relays.spawn(async move {
                            stream
                                .relay_with_idle_timeout_and_egress(
                                    DEFAULT_NAT_TIMEOUT,
                                    relay_egress,
                                )
                                .await
                        });
                    }
                    Err(error) if proxy_connection_closed(&error) => break false,
                    Err(error) => {
                        tracing::warn!(error = %error, "handleStream");
                        hooks.proxy_stream_failed();
                        report.failed_proxy_streams += 1;
                    }
                }
            }
            joined = relays.join_next(), if !relays.is_empty() => {
                if let Some(relay) = joined {
                    record_proxy_connection_result(&mut report, &hooks, relay?);
                }
            }
        }
    };

    if shutdown_requested {
        drain_proxy_relays(&mut relays, &mut report, &hooks).await?;
        connection.as_quinn().close(0u32.into(), b"server shutdown");
    } else {
        while let Some(relay) = relays.join_next().await {
            record_proxy_connection_result(&mut report, &hooks, relay?);
        }
    }
    if let Some(handle) = tuic_udp_relay {
        handle.abort();
    }
    Ok(report)
}

async fn drain_proxy_relays(
    relays: &mut tokio::task::JoinSet<Result<ProxyRelayReport, zuicity_transport::TransportError>>,
    report: &mut ServerProxyLoopReport,
    hooks: &ServerRuntimeHooks,
) -> Result<(), ServerError> {
    loop {
        match tokio::time::timeout(PROXY_SHUTDOWN_RELAY_DRAIN_TIMEOUT, relays.join_next()).await {
            Ok(Some(relay)) => record_proxy_connection_result(report, hooks, relay?),
            Ok(None) => return Ok(()),
            Err(_) => break,
        }
    }
    relays.abort_all();
    while let Some(relay) = relays.join_next().await {
        if let Ok(relay) = relay {
            record_proxy_connection_result(report, hooks, relay);
        }
    }
    Ok(())
}

fn record_proxy_connection_result(
    report: &mut ServerProxyLoopReport,
    hooks: &ServerRuntimeHooks,
    relay: Result<ProxyRelayReport, zuicity_transport::TransportError>,
) {
    match relay {
        Ok(relay) => {
            trace_proxy_relay(&relay);
            hooks.proxy_relay_completed(&relay);
            report.add_relay(relay);
        }
        Err(error) if proxy_connection_closed(&error) => {}
        Err(error) => {
            tracing::warn!(error = %error, "handleStream");
            hooks.proxy_stream_failed();
            report.failed_proxy_streams += 1;
        }
    }
}

fn trace_authenticated_accept_error(error: &ServerError) {
    match error {
        ServerError::Transport(zuicity_transport::TransportError::AuthenticationRejected) => {
            tracing::warn!(error = "authentication failed", "handleAuth");
        }
        ServerError::Transport(error) => {
            tracing::warn!(error = %error, "handleAuth");
        }
        _ => {}
    }
}

fn trace_proxy_relay(report: &ProxyRelayReport) {
    match report {
        ProxyRelayReport::Tcp(report) => trace_tcp_proxy_relay(report),
        ProxyRelayReport::Udp(report) => trace_udp_over_stream_relay(report),
    }
}

fn trace_tcp_proxy_relay(report: &TcpProxyRelayReport) {
    tracing::debug!(
        network = "tcp",
        target = %report.target,
        bytes_from_client = report.bytes_from_client,
        bytes_from_target = report.bytes_from_target,
        "zuicity received a [tcp] request"
    );
}

fn trace_udp_over_stream_relay(report: &UdpOverStreamRelayReport) {
    tracing::debug!(
        network = "udp",
        target = %report.target,
        bytes_from_client = report.bytes_from_client,
        bytes_from_target = report.bytes_from_target,
        "zuicity received a [udp] request"
    );
}

fn proxy_connection_closed(error: &zuicity_transport::TransportError) -> bool {
    use zuicity_transport::TransportError;
    matches!(
        error,
        TransportError::Connection(_)
            | TransportError::Stopped(zuicity_transport::StoppedError::ConnectionLost(_))
    )
}

/// Server runtime errors.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Server runtime has no configured users.
    #[error("server has no configured users")]
    NoUsersConfigured,
    /// Config parsing or validation failed.
    #[error(transparent)]
    Config(#[from] zuicity_config::ConfigError),
    /// Transport failed.
    #[error(transparent)]
    Transport(#[from] zuicity_transport::TransportError),
    /// Join failed while waiting for a runtime task.
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
}

#[cfg(test)]
mod tests {
    use aes_gcm::{
        Aes128Gcm, Nonce,
        aead::{Aead, KeyInit as AeadKeyInit, Payload},
    };
    use base64::{Engine as _, engine::general_purpose};
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    use sha3::{
        Shake128,
        digest::{ExtendableOutput, Update as Sha3Update, XofReader},
    };
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
        sync::{Arc, Mutex, Once, OnceLock},
        time::{Duration, Instant},
    };
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use zuicity_config::{ConfigError, load_json_str, validate_server};

    use super::*;

    fn server_config(json: &str) -> Result<ServerRuntimeConfig, ConfigError> {
        Ok(ServerRuntimeConfig::from_config(validate_server(
            load_json_str(json)?,
        )?))
    }

    async fn wait_for_server_metrics(
        metrics: &ServerMetrics,
        predicate: impl Fn(ServerMetricsSnapshot) -> bool,
    ) -> ServerMetricsSnapshot {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let snapshot = metrics.snapshot();
            if predicate(snapshot) {
                return snapshot;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for server metrics snapshot, last snapshot: {snapshot:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn server_runtime_proxy_loop_exports_live_metrics_hooks() -> Result<(), ServerError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "server metrics hook password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let metrics = ServerMetrics::default();
        let hooks = ServerRuntimeHooks::new(metrics.clone());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            bound
                .run_proxy_loop_until_with_hooks(
                    async {
                        let _ = shutdown_rx.await;
                    },
                    hooks,
                )
                .await
        });

        let target = echo.local_addr();
        let bad_client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let bad_connection = bad_client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                b"wrong password",
            )
            .await?;
        let _ = bad_connection
            .open_tcp_proxy_stream(target.ip(), target.port())
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let rejected =
            wait_for_server_metrics(&metrics, |snapshot| snapshot.rejected_connections == 1).await;
        drop(bad_connection);
        assert_eq!(rejected.accepted_connections, 0);
        assert_eq!(rejected.active_connections, 0);

        let good_client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let good_connection = tokio::time::timeout(
            Duration::from_secs(2),
            good_client.connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            ),
        )
        .await
        .expect("valid client timed out after bad auth")?;
        let payload = b"server metrics hook tcp";
        let mut stream = good_connection
            .open_tcp_proxy_stream(target.ip(), target.port())
            .await?;
        stream.write_all(payload).await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, payload);
        drop(stream);
        drop(good_connection);

        let snapshot = wait_for_server_metrics(&metrics, |snapshot| {
            snapshot.rejected_connections == 1
                && snapshot.completed_tcp_relays == 1
                && snapshot.active_connections == 0
        })
        .await;
        assert_eq!(snapshot.accepted_connections, 1);
        assert_eq!(snapshot.completed_udp_relays, 0);
        assert_eq!(snapshot.failed_proxy_streams, 0);
        assert_eq!(snapshot.bytes_from_client, payload.len() as u64);
        assert_eq!(snapshot.bytes_from_target, payload.len() as u64);

        shutdown_tx.send(()).expect("send shutdown");
        let report = server_task.await??;
        assert_eq!(report.accepted_connections, snapshot.accepted_connections);
        assert_eq!(report.rejected_connections, snapshot.rejected_connections);
        assert_eq!(report.completed_tcp_relays, snapshot.completed_tcp_relays);
        assert_eq!(report.completed_udp_relays, snapshot.completed_udp_relays);
        assert_eq!(report.failed_proxy_streams, snapshot.failed_proxy_streams);
        assert_eq!(report.bytes_from_client, snapshot.bytes_from_client);
        assert_eq!(report.bytes_from_target, snapshot.bytes_from_target);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_accepts_authenticated_tcp_proxy_stream() -> Result<(), ServerError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);

        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream.write_all(b"server runtime tcp").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime tcp");

        let report = server_task.await??;
        assert_eq!(report.target, echo_addr);
        assert_eq!(report.bytes_from_client, b"server runtime tcp".len() as u64);
        assert_eq!(report.bytes_from_target, b"server runtime tcp".len() as u64);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_accepts_authenticated_udp_over_stream() -> Result<(), ServerError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime udp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);

        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_udp_over_stream().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_udp_over_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream.send_datagram(b"server runtime udp").await?;
        let echoed = stream.recv_datagram(1024).await?;
        assert_eq!(echoed.payload, b"server runtime udp");
        assert_eq!(echoed.target, echo_addr);
        stream.finish()?;

        let report = server_task.await??;
        assert_eq!(report.target, echo_addr);
        assert_eq!(report.bytes_from_client, b"server runtime udp".len() as u64);
        assert_eq!(report.bytes_from_target, b"server runtime udp".len() as u64);
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    async fn start_tcp_peer_observer() -> std::io::Result<(
        SocketAddr,
        tokio::sync::oneshot::Receiver<SocketAddr>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let local_addr = listener.local_addr()?;
        let (peer_tx, peer_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut stream, peer) = listener.accept().await?;
            let _ = peer_tx.send(peer);
            let mut buf = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buf).await?;
                if read == 0 {
                    break;
                }
                stream.write_all(&buf[..read]).await?;
            }
            Ok(())
        });
        Ok((local_addr, peer_rx, task))
    }

    async fn start_udp_peer_observer() -> std::io::Result<(
        SocketAddr,
        tokio::sync::oneshot::Receiver<SocketAddr>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let local_addr = socket.local_addr()?;
        let (peer_tx, peer_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut buf = [0_u8; 1024];
            let (read, peer) = socket.recv_from(&mut buf).await?;
            let _ = peer_tx.send(peer);
            socket.send_to(&buf[..read], peer).await?;
            Ok(())
        });
        Ok((local_addr, peer_rx, task))
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct HttpConnectRequest {
        authority: String,
        proxy_authorization: Option<String>,
    }

    async fn start_http_connect_proxy() -> std::io::Result<(
        SocketAddr,
        tokio::sync::mpsc::Receiver<HttpConnectRequest>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let local_addr = listener.local_addr()?;
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async move {
            let (inbound, _) = listener.accept().await?;
            handle_http_connect_proxy_stream(inbound, request_tx).await
        });
        Ok((local_addr, request_rx, task))
    }

    async fn start_https_connect_proxy() -> std::io::Result<(
        SocketAddr,
        tokio::sync::mpsc::Receiver<HttpConnectRequest>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let local_addr = listener.local_addr()?;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .map_err(std::io::Error::other)?;
        let mut tls_config = zuicity_transport::build_server_crypto_config_from_pem(
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )
        .map_err(std::io::Error::other)?;
        tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls_config));
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async move {
            let (inbound, _) = listener.accept().await?;
            let mut inbound = acceptor
                .accept(inbound)
                .await
                .map_err(std::io::Error::other)?;
            handle_http_connect_proxy_stream(&mut inbound, request_tx).await
        });
        Ok((local_addr, request_rx, task))
    }

    async fn handle_http_connect_proxy_stream<S>(
        mut inbound: S,
        request_tx: tokio::sync::mpsc::Sender<HttpConnectRequest>,
    ) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
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
        let proxy_authorization = request
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("Proxy-Authorization")
                    .then(|| value.trim().to_owned())
            });
        request_tx
            .send(HttpConnectRequest {
                authority: authority.clone(),
                proxy_authorization,
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
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TrojanTcpRequest {
        target: SocketAddr,
        network: zuicity_protocol::Network,
        auth_hash: String,
    }

    async fn start_trojan_tcp_proxy(
        password: &str,
    ) -> std::io::Result<(
        SocketAddr,
        tokio::sync::mpsc::Receiver<TrojanTcpRequest>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let local_addr = listener.local_addr()?;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .map_err(std::io::Error::other)?;
        let tls_config = zuicity_transport::build_server_crypto_config_from_pem(
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )
        .map_err(std::io::Error::other)?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
        let expected_auth_hash = trojan_test_sha224_hex(password)?.to_owned();
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async move {
            let (inbound, _) = listener.accept().await?;
            let mut inbound = acceptor
                .accept(inbound)
                .await
                .map_err(std::io::Error::other)?;
            handle_trojan_tcp_proxy_stream(&mut inbound, expected_auth_hash, request_tx).await
        });
        Ok((local_addr, request_rx, task))
    }

    fn trojan_test_sha224_hex(password: &str) -> std::io::Result<&'static str> {
        match password {
            "server-runtime-trojan-dialer-password" => {
                Ok("25e3a13f6e707740a313273a6c3f4752a1479620582c9d071917e570")
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unexpected Trojan test password",
            )),
        }
    }

    async fn handle_trojan_tcp_proxy_stream<S>(
        mut inbound: S,
        expected_auth_hash: String,
        request_tx: tokio::sync::mpsc::Sender<TrojanTcpRequest>,
    ) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut auth = [0_u8; 56];
        inbound.read_exact(&mut auth).await?;
        let auth_hash = std::str::from_utf8(&auth)
            .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidData, source))?
            .to_owned();
        if auth_hash != expected_auth_hash {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invalid Trojan auth hash",
            ));
        }

        let mut crlf = [0_u8; 2];
        inbound.read_exact(&mut crlf).await?;
        if crlf != *b"\r\n" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing Trojan auth CRLF",
            ));
        }

        let mut network = [0_u8; 1];
        inbound.read_exact(&mut network).await?;
        let network = match network[0] {
            1 => zuicity_protocol::Network::Tcp,
            3 => zuicity_protocol::Network::Udp,
            value => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid Trojan network byte {value}"),
                ));
            }
        };
        if network != zuicity_protocol::Network::Tcp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Trojan fixture only supports TCP",
            ));
        }
        let target = read_trojan_target_metadata(&mut inbound).await?;
        inbound.read_exact(&mut crlf).await?;
        if crlf != *b"\r\n" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing Trojan target CRLF",
            ));
        }
        request_tx
            .send(TrojanTcpRequest {
                target,
                network,
                auth_hash,
            })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
            })?;
        let mut outbound = tokio::net::TcpStream::connect(target).await?;
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
        Ok(())
    }

    async fn read_trojan_target_metadata<S>(inbound: &mut S) -> std::io::Result<SocketAddr>
    where
        S: AsyncRead + Unpin,
    {
        let mut address_type = [0_u8; 1];
        inbound.read_exact(&mut address_type).await?;
        match address_type[0] {
            1 => {
                let mut address = [0_u8; 4];
                inbound.read_exact(&mut address).await?;
                let port = read_trojan_port(inbound).await?;
                Ok(SocketAddr::new(IpAddr::from(address), port))
            }
            4 => {
                let mut address = [0_u8; 16];
                inbound.read_exact(&mut address).await?;
                let port = read_trojan_port(inbound).await?;
                Ok(SocketAddr::new(IpAddr::from(address), port))
            }
            value => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported Trojan target type {value}"),
            )),
        }
    }

    async fn read_trojan_port<S>(inbound: &mut S) -> std::io::Result<u16>
    where
        S: AsyncRead + Unpin,
    {
        let mut port = [0_u8; 2];
        inbound.read_exact(&mut port).await?;
        Ok(u16::from_be_bytes(port))
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ShadowsocksTcpRequest {
        target: SocketAddr,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ShadowsocksUdpRequest {
        target: SocketAddr,
    }

    fn shadowsocksr_origin_plain_link(host: &str, port: u16, password: &str) -> String {
        let host = general_purpose::URL_SAFE_NO_PAD.encode(host);
        let password = general_purpose::URL_SAFE_NO_PAD.encode(password);
        format!(
            "ssr://{host}:{port}:origin:aes-128-gcm:plain:{password}/?remarks=&protoparam=&obfsparam="
        )
    }

    async fn start_shadowsocks_tcp_proxy(
        password: &'static str,
        method: shadowsocks::crypto::CipherKind,
    ) -> std::io::Result<(
        SocketAddr,
        tokio::sync::mpsc::Receiver<ShadowsocksTcpRequest>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let server_config = shadowsocks::config::ServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            password,
            method,
        )
        .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidInput, source))?;
        let context =
            shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Server);
        let listener = shadowsocks::ProxyListener::bind(context, &server_config).await?;
        let local_addr = listener.local_addr()?;
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async move {
            let (mut inbound, _) = listener.accept().await?;
            let target = inbound.handshake().await?;
            let target = match target {
                shadowsocks::relay::socks5::Address::SocketAddress(address) => address,
                shadowsocks::relay::socks5::Address::DomainNameAddress(domain, port) => {
                    tokio::net::lookup_host((domain.as_str(), port))
                        .await?
                        .next()
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                "Shadowsocks test target did not resolve",
                            )
                        })?
                }
            };
            request_tx
                .send(ShadowsocksTcpRequest { target })
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
                })?;
            let mut outbound = tokio::net::TcpStream::connect(target).await?;
            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
            Ok(())
        });
        Ok((local_addr, request_rx, task))
    }

    async fn start_shadowsocks_tcp_udp_proxy(
        password: &'static str,
        method: shadowsocks::crypto::CipherKind,
    ) -> std::io::Result<(
        SocketAddr,
        tokio::sync::mpsc::Receiver<ShadowsocksTcpRequest>,
        tokio::sync::mpsc::Receiver<ShadowsocksUdpRequest>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let udp_server_config = shadowsocks::config::ServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            password,
            method,
        )
        .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidInput, source))?;
        let udp_context =
            shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Server);
        let udp_socket = shadowsocks::ProxySocket::bind(udp_context, &udp_server_config).await?;
        let local_addr = udp_socket.local_addr()?;
        let tcp_server_config =
            shadowsocks::config::ServerConfig::new(local_addr, password, method)
                .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidInput, source))?;
        let tcp_context =
            shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Server);
        let tcp_listener =
            shadowsocks::ProxyListener::bind(tcp_context, &tcp_server_config).await?;
        let (tcp_request_tx, tcp_request_rx) = tokio::sync::mpsc::channel(1);
        let (udp_request_tx, udp_request_rx) = tokio::sync::mpsc::channel(1);
        let tcp_task = tokio::spawn(async move {
            let (mut inbound, _) = tcp_listener.accept().await?;
            let target = inbound.handshake().await?;
            let target = shadowsocks_test_socket_addr(target).await?;
            tcp_request_tx
                .send(ShadowsocksTcpRequest { target })
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
                })?;
            let mut outbound = tokio::net::TcpStream::connect(target).await?;
            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
            Ok::<_, std::io::Error>(())
        });
        let udp_task = tokio::spawn(async move {
            let mut request_payload = vec![0_u8; 65_535];
            let (received, peer, target, _packet_len) = udp_socket
                .recv_from(&mut request_payload)
                .await
                .map_err(std::io::Error::from)?;
            request_payload.truncate(received);
            let target = shadowsocks_test_socket_addr(target).await?;
            udp_request_tx
                .send(ShadowsocksUdpRequest { target })
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
                })?;
            let outbound =
                tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
            outbound.connect(target).await?;
            outbound.send(&request_payload).await?;
            let mut response = vec![0_u8; 65_535];
            let received = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                outbound.recv(&mut response),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Shadowsocks UDP proxy target did not respond",
                )
            })??;
            udp_socket
                .send_to(
                    peer,
                    &shadowsocks::relay::socks5::Address::SocketAddress(target),
                    &response[..received],
                )
                .await
                .map_err(std::io::Error::from)?;
            Ok::<_, std::io::Error>(())
        });
        let task = tokio::spawn(async move {
            tcp_task.await.map_err(std::io::Error::other)??;
            udp_task.await.map_err(std::io::Error::other)??;
            Ok::<_, std::io::Error>(())
        });
        Ok((local_addr, tcp_request_rx, udp_request_rx, task))
    }

    async fn start_shadowsocks_udp_proxy(
        password: &'static str,
        method: shadowsocks::crypto::CipherKind,
    ) -> std::io::Result<(
        SocketAddr,
        tokio::sync::mpsc::Receiver<ShadowsocksUdpRequest>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let server_config = shadowsocks::config::ServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            password,
            method,
        )
        .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidInput, source))?;
        let context =
            shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Server);
        let socket = shadowsocks::ProxySocket::bind(context, &server_config).await?;
        let local_addr = socket.local_addr()?;
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async move {
            let mut request_payload = vec![0_u8; 65_535];
            let (received, peer, target, _packet_len) = socket
                .recv_from(&mut request_payload)
                .await
                .map_err(std::io::Error::from)?;
            request_payload.truncate(received);
            let target = shadowsocks_test_socket_addr(target).await?;
            request_tx
                .send(ShadowsocksUdpRequest { target })
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
                })?;
            let outbound =
                tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
            outbound.connect(target).await?;
            outbound.send(&request_payload).await?;
            let mut response = vec![0_u8; 65_535];
            let received = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                outbound.recv(&mut response),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Shadowsocks UDP proxy target did not respond",
                )
            })??;
            socket
                .send_to(
                    peer,
                    &shadowsocks::relay::socks5::Address::SocketAddress(target),
                    &response[..received],
                )
                .await
                .map_err(std::io::Error::from)?;
            Ok::<_, std::io::Error>(())
        });
        Ok((local_addr, request_rx, task))
    }

    async fn shadowsocks_test_socket_addr(
        address: shadowsocks::relay::socks5::Address,
    ) -> std::io::Result<SocketAddr> {
        match address {
            shadowsocks::relay::socks5::Address::SocketAddress(address) => Ok(address),
            shadowsocks::relay::socks5::Address::DomainNameAddress(domain, port) => {
                tokio::net::lookup_host((domain.as_str(), port))
                    .await?
                    .next()
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "Shadowsocks UDP test target did not resolve",
                        )
                    })
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Socks5ConnectRequest {
        target: SocketAddr,
    }

    async fn start_socks5_tcp_connect_proxy() -> std::io::Result<(
        SocketAddr,
        tokio::sync::mpsc::Receiver<Socks5ConnectRequest>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let local_addr = listener.local_addr()?;
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async move {
            let (mut inbound, _) = listener.accept().await?;
            let mut greeting = [0_u8; 2];
            inbound.read_exact(&mut greeting).await?;
            if greeting[0] != 0x05 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid SOCKS version",
                ));
            }
            let mut methods = vec![0_u8; greeting[1] as usize];
            inbound.read_exact(&mut methods).await?;
            if !methods.contains(&0x00) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "SOCKS5 client did not offer no-auth",
                ));
            }
            inbound.write_all(&[0x05, 0x00]).await?;

            let mut request = [0_u8; 4];
            inbound.read_exact(&mut request).await?;
            if request[..3] != [0x05, 0x01, 0x00] {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid SOCKS5 CONNECT request",
                ));
            }
            let target = match request[3] {
                0x01 => {
                    let mut raw = [0_u8; 6];
                    inbound.read_exact(&mut raw).await?;
                    SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
                        u16::from_be_bytes([raw[4], raw[5]]),
                    )
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "test proxy only supports IPv4 CONNECT targets",
                    ));
                }
            };
            request_tx
                .send(Socks5ConnectRequest { target })
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
                })?;
            let mut outbound = tokio::net::TcpStream::connect(target).await?;
            inbound
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
            Ok(())
        });
        Ok((local_addr, request_rx, task))
    }

    const VMESS_MAX_CHUNK_SIZE: usize = 1 << 14;

    type HmacSha256 = Hmac<Sha256>;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct VmessTcpRequest {
        target: SocketAddr,
        network: zuicity_protocol::Network,
        key: [u8; 16],
    }

    struct VmessTestStreamContext {
        request_body_iv: [u8; 16],
        request_body_key: [u8; 16],
        response_body_iv: [u8; 16],
        response_body_key: [u8; 16],
        response_auth: u8,
        request_options: u8,
    }

    struct VmessTestBodyContext {
        cipher: Aes128Gcm,
        size_mask: VmessTestSizeMask,
        nonce_prefix: [u8; 16],
        nonce_counter: u16,
    }

    impl VmessTestBodyContext {
        fn request(context: &VmessTestStreamContext) -> std::io::Result<Self> {
            Self::new(
                &context.request_body_key,
                &context.request_body_iv,
                context.request_options,
            )
        }

        fn response(context: &VmessTestStreamContext) -> std::io::Result<Self> {
            Self::new(
                &context.response_body_key,
                &context.response_body_iv,
                context.request_options,
            )
        }

        fn new(key: &[u8; 16], iv: &[u8; 16], _request_options: u8) -> std::io::Result<Self> {
            Ok(Self {
                cipher: aes_gcm_from_key(key)?,
                size_mask: VmessTestSizeMask::new(iv),
                nonce_prefix: *iv,
                nonce_counter: 0,
            })
        }

        fn next_nonce(&mut self) -> [u8; 12] {
            let mut nonce = [0_u8; 12];
            nonce[..2].copy_from_slice(&self.nonce_counter.to_be_bytes());
            nonce[2..].copy_from_slice(&self.nonce_prefix[2..12]);
            self.nonce_counter = self.nonce_counter.wrapping_add(1);
            nonce
        }

        fn encode_chunk(&mut self, payload: &[u8]) -> std::io::Result<Vec<u8>> {
            let padding_len = self.size_mask.padding_len();
            let encrypted_len = payload.len() + 16;
            let total_len = encrypted_len + padding_len;
            let total_len = u16::try_from(total_len).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "VMess test payload chunk exceeds u16 framing limit",
                )
            })?;
            let nonce = self.next_nonce();
            let sealed = self
                .cipher
                .encrypt(Nonce::from_slice(&nonce), payload)
                .map_err(test_io_error)?;
            let mut chunk = Vec::with_capacity(2 + usize::from(total_len));
            chunk.extend_from_slice(&self.size_mask.encode_size(usize::from(total_len))?);
            chunk.extend_from_slice(&sealed);
            if padding_len != 0 {
                let start = chunk.len();
                chunk.resize(start + padding_len, 0);
            }
            Ok(chunk)
        }

        fn decode_chunk(
            &mut self,
            mut encrypted: Vec<u8>,
            padding_len: usize,
        ) -> std::io::Result<Vec<u8>> {
            if encrypted.len() < 16 + padding_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid VMess payload chunk length",
                ));
            }
            encrypted.truncate(encrypted.len() - padding_len);
            if encrypted.len() == 16 {
                return Ok(Vec::new());
            }
            let nonce = self.next_nonce();
            self.cipher
                .decrypt(Nonce::from_slice(&nonce), encrypted.as_slice())
                .map_err(test_io_error)
        }
    }

    struct VmessTestSizeMask {
        reader: Box<dyn XofReader + Send>,
    }

    impl VmessTestSizeMask {
        fn new(nonce: &[u8]) -> Self {
            let mut shake = Shake128::default();
            Sha3Update::update(&mut shake, nonce);
            Self {
                reader: Box::new(shake.finalize_xof()),
            }
        }

        fn next_mask(&mut self) -> u16 {
            let mut mask = [0_u8; 2];
            self.reader.read(&mut mask);
            u16::from_be_bytes(mask)
        }

        fn padding_len(&mut self) -> usize {
            usize::from(self.next_mask() % 64)
        }

        fn encode_size(&mut self, size: usize) -> std::io::Result<[u8; 2]> {
            let size = u16::try_from(size).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "VMess test chunk too large",
                )
            })?;
            Ok((size ^ self.next_mask()).to_be_bytes())
        }

        fn decode_size(&mut self, size: [u8; 2]) -> u16 {
            u16::from_be_bytes(size) ^ self.next_mask()
        }
    }

    async fn start_vmess_tcp_proxy(
        expected_key: [u8; 16],
    ) -> std::io::Result<(
        SocketAddr,
        tokio::sync::mpsc::Receiver<VmessTcpRequest>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let local_addr = listener.local_addr()?;
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async move {
            let (inbound, _) = listener.accept().await?;
            handle_vmess_tcp_proxy_stream(inbound, expected_key, request_tx).await
        });
        Ok((local_addr, request_rx, task))
    }

    async fn handle_vmess_tcp_proxy_stream<S>(
        mut inbound: S,
        expected_key: [u8; 16],
        request_tx: tokio::sync::mpsc::Sender<VmessTcpRequest>,
    ) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let cmd_key = vmess_cmd_key(&expected_key);
        let mut prefix = [0_u8; 42];
        inbound.read_exact(&mut prefix).await?;
        let mut eauth_id = [0_u8; 16];
        eauth_id.copy_from_slice(&prefix[..16]);
        let mut connection_nonce = [0_u8; 8];
        connection_nonce.copy_from_slice(&prefix[34..42]);
        let len_key = vmess_kdf(
            &cmd_key,
            &[
                b"VMess Header AEAD Key_Length".as_slice(),
                &eauth_id,
                &connection_nonce,
            ],
        );
        let len_iv = vmess_kdf(
            &cmd_key,
            &[
                b"VMess Header AEAD Nonce_Length".as_slice(),
                &eauth_id,
                &connection_nonce,
            ],
        );
        let len_cipher = aes_gcm_from_key(&len_key[..16])?;
        let len = len_cipher
            .decrypt(
                Nonce::from_slice(&len_iv[..12]),
                Payload {
                    msg: &prefix[16..34],
                    aad: &eauth_id,
                },
            )
            .map_err(test_io_error)?;
        if len.len() != 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid VMess request length",
            ));
        }
        let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        let mut sealed = vec![0_u8; len + 16];
        inbound.read_exact(&mut sealed).await?;
        let payload_key = vmess_kdf(
            &cmd_key,
            &[
                b"VMess Header AEAD Key".as_slice(),
                &eauth_id,
                &connection_nonce,
            ],
        );
        let payload_iv = vmess_kdf(
            &cmd_key,
            &[
                b"VMess Header AEAD Nonce".as_slice(),
                &eauth_id,
                &connection_nonce,
            ],
        );
        let payload_cipher = aes_gcm_from_key(&payload_key[..16])?;
        let instruction = payload_cipher
            .decrypt(
                Nonce::from_slice(&payload_iv[..12]),
                Payload {
                    msg: sealed.as_slice(),
                    aad: &eauth_id,
                },
            )
            .map_err(test_io_error)?;
        let (context, target) = parse_vmess_request_instruction(&instruction)?;
        request_tx
            .send(VmessTcpRequest {
                target,
                network: zuicity_protocol::Network::Tcp,
                key: expected_key,
            })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
            })?;
        let outbound = tokio::net::TcpStream::connect(target).await?;
        write_vmess_response_header(&mut inbound, &context).await?;
        let request = VmessTestBodyContext::request(&context)?;
        let response = VmessTestBodyContext::response(&context)?;
        let (mut inbound_read, mut inbound_write) = tokio::io::split(inbound);
        let (mut outbound_read, mut outbound_write) = tokio::io::split(outbound);
        let upload =
            async { copy_vmess_to_plain(&mut inbound_read, &mut outbound_write, request).await };
        let download =
            async { copy_plain_to_vmess(&mut outbound_read, &mut inbound_write, response).await };
        let _ = tokio::try_join!(upload, download)?;
        Ok(())
    }

    fn parse_vmess_request_instruction(
        instruction: &[u8],
    ) -> std::io::Result<(VmessTestStreamContext, SocketAddr)> {
        if instruction.len() < 45 || instruction[0] != 1 || instruction[37] != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid VMess instruction",
            ));
        }
        let expected = crc32fast::hash(&instruction[..instruction.len() - 4]).to_be_bytes();
        if instruction[instruction.len() - 4..] != expected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid VMess instruction checksum",
            ));
        }
        let mut request_body_iv = [0_u8; 16];
        request_body_iv.copy_from_slice(&instruction[1..17]);
        let mut request_body_key = [0_u8; 16];
        request_body_key.copy_from_slice(&instruction[17..33]);
        let response_auth = instruction[33];
        let request_options = instruction[34];
        let port = u16::from_be_bytes([instruction[38], instruction[39]]);
        let target = match instruction[40] {
            1 => {
                if instruction.len() < 49 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated VMess IPv4 target",
                    ));
                }
                SocketAddr::new(
                    IpAddr::from([
                        instruction[41],
                        instruction[42],
                        instruction[43],
                        instruction[44],
                    ]),
                    port,
                )
            }
            2 => {
                let len = usize::from(instruction[41]);
                if instruction.len() < 46 + len {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated VMess domain target",
                    ));
                }
                let domain = std::str::from_utf8(&instruction[42..42 + len]).map_err(|source| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, source)
                })?;
                ToSocketAddrs::to_socket_addrs(&(domain, port))?
                    .next()
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "VMess domain target did not resolve",
                        )
                    })?
            }
            3 => {
                if instruction.len() < 61 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated VMess IPv6 target",
                    ));
                }
                let mut address = [0_u8; 16];
                address.copy_from_slice(&instruction[41..57]);
                SocketAddr::new(IpAddr::from(address), port)
            }
            value => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unsupported VMess target type {value}"),
                ));
            }
        };
        let response_body_iv = Sha256::digest(request_body_iv)[..16]
            .try_into()
            .expect("sha256 prefix has fixed length");
        let response_body_key = Sha256::digest(request_body_key)[..16]
            .try_into()
            .expect("sha256 prefix has fixed length");
        Ok((
            VmessTestStreamContext {
                request_body_iv,
                request_body_key,
                response_body_iv,
                response_body_key,
                response_auth,
                request_options,
            },
            target,
        ))
    }

    async fn write_vmess_response_header<S>(
        stream: &mut S,
        context: &VmessTestStreamContext,
    ) -> std::io::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let header = [context.response_auth, 0, 0, 0];
        let len_key = vmess_kdf(
            &context.response_body_key,
            &[b"AEAD Resp Header Len Key".as_slice()],
        );
        let len_iv = vmess_kdf(
            &context.response_body_iv,
            &[b"AEAD Resp Header Len IV".as_slice()],
        );
        let len_cipher = aes_gcm_from_key(&len_key[..16])?;
        let sealed_len = len_cipher
            .encrypt(
                Nonce::from_slice(&len_iv[..12]),
                (header.len() as u16).to_be_bytes().as_slice(),
            )
            .map_err(test_io_error)?;
        let header_key = vmess_kdf(
            &context.response_body_key,
            &[b"AEAD Resp Header Key".as_slice()],
        );
        let header_iv = vmess_kdf(
            &context.response_body_iv,
            &[b"AEAD Resp Header IV".as_slice()],
        );
        let header_cipher = aes_gcm_from_key(&header_key[..16])?;
        let sealed_header = header_cipher
            .encrypt(Nonce::from_slice(&header_iv[..12]), header.as_slice())
            .map_err(test_io_error)?;
        stream.write_all(&sealed_len).await?;
        stream.write_all(&sealed_header).await?;
        Ok(())
    }

    async fn copy_plain_to_vmess<R, W>(
        reader: &mut R,
        writer: &mut W,
        mut context: VmessTestBodyContext,
    ) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut buffer = vec![0_u8; VMESS_MAX_CHUNK_SIZE];
        loop {
            let read = reader.read(&mut buffer).await?;
            let chunk = context.encode_chunk(&buffer[..read])?;
            writer.write_all(&chunk).await?;
            if read == 0 {
                writer.shutdown().await?;
                return Ok(());
            }
        }
    }

    async fn copy_vmess_to_plain<R, W>(
        reader: &mut R,
        writer: &mut W,
        mut context: VmessTestBodyContext,
    ) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            let mut size = [0_u8; 2];
            match reader.read_exact(&mut size).await {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    writer.shutdown().await?;
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
            let padding_len = context.size_mask.padding_len();
            let size = usize::from(context.size_mask.decode_size(size));
            let mut encrypted = vec![0_u8; size];
            reader.read_exact(&mut encrypted).await?;
            let payload = context.decode_chunk(encrypted, padding_len)?;
            if payload.is_empty() {
                writer.shutdown().await?;
                return Ok(());
            }
            writer.write_all(&payload).await?;
        }
    }

    fn vmess_uuid_key(user: &str) -> std::io::Result<[u8; 16]> {
        let compact = user.replace('-', "");
        if compact.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "VMess fixture user must be a UUID",
            ));
        }
        let mut key = [0_u8; 16];
        for index in 0..16 {
            let start = index * 2;
            key[index] = u8::from_str_radix(&compact[start..start + 2], 16)
                .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidInput, source))?;
        }
        Ok(key)
    }

    fn vmess_cmd_key(key: &[u8; 16]) -> [u8; 16] {
        let mut hasher = md5::Md5::new();
        Digest::update(&mut hasher, key);
        Digest::update(&mut hasher, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        hasher.finalize().into()
    }

    fn vmess_kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
        fn hmac_at(key: &[u8], path: &[&[u8]], index: usize, data: &[u8]) -> [u8; 32] {
            let mut mac = if index == 0 {
                <HmacSha256 as Mac>::new_from_slice(b"VMess AEAD KDF")
                    .expect("HMAC accepts any key length")
            } else {
                <HmacSha256 as Mac>::new_from_slice(&hmac_at(key, path, index - 1, path[index - 1]))
                    .expect("HMAC accepts any key length")
            };
            hmac::Mac::update(&mut mac, data);
            mac.finalize().into_bytes().into()
        }
        hmac_at(key, path, path.len(), key)
    }

    fn aes_gcm_from_key(key: &[u8]) -> std::io::Result<Aes128Gcm> {
        Aes128Gcm::new_from_slice(key).map_err(test_io_error)
    }

    fn test_io_error(error: impl std::fmt::Display) -> std::io::Error {
        std::io::Error::other(error.to_string())
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct VlessTcpRequest {
        target: SocketAddr,
        network: zuicity_protocol::Network,
        uuid: uuid::Uuid,
    }

    async fn start_vless_tcp_proxy(
        expected_uuid: uuid::Uuid,
    ) -> std::io::Result<(
        SocketAddr,
        tokio::sync::mpsc::Receiver<VlessTcpRequest>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let local_addr = listener.local_addr()?;
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async move {
            let (inbound, _) = listener.accept().await?;
            handle_vless_tcp_proxy_stream(inbound, expected_uuid, request_tx).await
        });
        Ok((local_addr, request_rx, task))
    }

    async fn handle_vless_tcp_proxy_stream<S>(
        mut inbound: S,
        expected_uuid: uuid::Uuid,
        request_tx: tokio::sync::mpsc::Sender<VlessTcpRequest>,
    ) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut version = [0_u8; 1];
        inbound.read_exact(&mut version).await?;
        if version[0] != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid VLESS request version {}", version[0]),
            ));
        }
        let mut uuid = [0_u8; 16];
        inbound.read_exact(&mut uuid).await?;
        if uuid != *expected_uuid.as_bytes() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invalid VLESS UUID",
            ));
        }
        let mut addons_len = [0_u8; 1];
        inbound.read_exact(&mut addons_len).await?;
        if addons_len[0] != 0 {
            let mut ignored = vec![0_u8; addons_len[0] as usize];
            inbound.read_exact(&mut ignored).await?;
        }
        let mut network = [0_u8; 1];
        inbound.read_exact(&mut network).await?;
        let network = match network[0] {
            1 => zuicity_protocol::Network::Tcp,
            2 => zuicity_protocol::Network::Udp,
            value => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid VLESS network byte {value}"),
                ));
            }
        };
        if network != zuicity_protocol::Network::Tcp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VLESS fixture only supports TCP",
            ));
        }
        let target = read_vless_target_metadata(&mut inbound).await?;
        request_tx
            .send(VlessTcpRequest {
                target,
                network,
                uuid: expected_uuid,
            })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
            })?;
        let mut outbound = tokio::net::TcpStream::connect(target).await?;
        inbound.write_all(&[0_u8, 0_u8]).await?;
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
        Ok(())
    }

    async fn read_vless_target_metadata<S>(inbound: &mut S) -> std::io::Result<SocketAddr>
    where
        S: AsyncRead + Unpin,
    {
        let mut port = [0_u8; 2];
        inbound.read_exact(&mut port).await?;
        let port = u16::from_be_bytes(port);
        let mut address_type = [0_u8; 1];
        inbound.read_exact(&mut address_type).await?;
        match address_type[0] {
            1 => {
                let mut address = [0_u8; 4];
                inbound.read_exact(&mut address).await?;
                Ok(SocketAddr::new(IpAddr::from(address), port))
            }
            2 => {
                let mut len = [0_u8; 1];
                inbound.read_exact(&mut len).await?;
                let mut domain = vec![0_u8; len[0] as usize];
                inbound.read_exact(&mut domain).await?;
                let domain = std::str::from_utf8(&domain).map_err(|source| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, source)
                })?;
                tokio::net::lookup_host((domain, port))
                    .await?
                    .next()
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "VLESS domain target did not resolve",
                        )
                    })
            }
            3 => {
                let mut address = [0_u8; 16];
                inbound.read_exact(&mut address).await?;
                Ok(SocketAddr::new(IpAddr::from(address), port))
            }
            value => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported VLESS target type {value}"),
            )),
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Socks5UdpAssociateRequest {
        target: SocketAddr,
    }

    async fn start_socks5_udp_associate_proxy() -> std::io::Result<(
        SocketAddr,
        tokio::sync::mpsc::Receiver<Socks5UdpAssociateRequest>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let local_addr = listener.local_addr()?;
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await?;
            let mut greeting = [0_u8; 2];
            control.read_exact(&mut greeting).await?;
            if greeting[0] != 0x05 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid SOCKS version",
                ));
            }
            let mut methods = vec![0_u8; greeting[1] as usize];
            control.read_exact(&mut methods).await?;
            if !methods.contains(&0x00) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "SOCKS5 client did not offer no-auth",
                ));
            }
            control.write_all(&[0x05, 0x00]).await?;

            let mut request = [0_u8; 4];
            control.read_exact(&mut request).await?;
            if request[..3] != [0x05, 0x03, 0x00] {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid SOCKS5 UDP ASSOCIATE request",
                ));
            }
            match request[3] {
                0x01 => {
                    let mut raw = [0_u8; 6];
                    control.read_exact(&mut raw).await?;
                }
                0x03 => {
                    let mut len = [0_u8; 1];
                    control.read_exact(&mut len).await?;
                    let mut raw = vec![0_u8; len[0] as usize + 2];
                    control.read_exact(&mut raw).await?;
                }
                0x04 => {
                    let mut raw = [0_u8; 18];
                    control.read_exact(&mut raw).await?;
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unsupported UDP ASSOCIATE address type",
                    ));
                }
            }

            let udp = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
            let relay_addr = udp.local_addr()?;
            let relay_port = relay_addr.port().to_be_bytes();
            control
                .write_all(&[
                    0x05,
                    0x00,
                    0x00,
                    0x01,
                    127,
                    0,
                    0,
                    1,
                    relay_port[0],
                    relay_port[1],
                ])
                .await?;

            let mut datagram = vec![0_u8; 65_535];
            let (received, client_udp_addr) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                udp.recv_from(&mut datagram),
            )
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "no UDP packet"))??;
            if received < 10 || datagram[..4] != [0x00, 0x00, 0x00, 0x01] {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid SOCKS5 UDP datagram header",
                ));
            }
            let target = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    datagram[4],
                    datagram[5],
                    datagram[6],
                    datagram[7],
                )),
                u16::from_be_bytes([datagram[8], datagram[9]]),
            );
            let payload = datagram[10..received].to_vec();
            request_tx
                .send(Socks5UdpAssociateRequest { target })
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
                })?;

            udp.send_to(&payload, target).await?;
            let (response_len, response_peer) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                udp.recv_from(&mut datagram),
            )
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "no UDP response"))??;
            let IpAddr::V4(peer_ip) = response_peer.ip() else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "test proxy only supports IPv4 UDP responses",
                ));
            };
            let peer_port = response_peer.port().to_be_bytes();
            let mut encoded = Vec::with_capacity(10 + response_len);
            encoded.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
            encoded.extend_from_slice(&peer_ip.octets());
            encoded.extend_from_slice(&peer_port);
            encoded.extend_from_slice(&datagram[..response_len]);
            udp.send_to(&encoded, client_udp_addr).await?;
            let mut drain = [0_u8; 1];
            let _ = control.read(&mut drain).await;
            Ok(())
        });
        Ok((local_addr, request_rx, task))
    }

    #[tokio::test]
    async fn server_send_through_binds_tcp_target_source_ip()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "send-through tcp password";
        let source_ip = Ipv4Addr::new(127, 0, 0, 2);
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let (target_addr, peer_rx, peer_task) = start_tcp_peer_observer().await?;
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","send_through":"{source_ip}","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let mut stream = connection
            .open_tcp_proxy_stream(target_addr.ip(), target_addr.port())
            .await?;
        stream.write_all(b"send-through tcp").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"send-through tcp");

        let observed_peer = peer_rx.await?;
        assert_eq!(observed_peer.ip(), IpAddr::V4(source_ip));
        peer_task.await??;
        let report = server_task.await??;
        assert_eq!(report.target, target_addr);
        Ok(())
    }

    #[tokio::test]
    async fn server_send_through_binds_udp_target_source_ip()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "send-through udp password";
        let source_ip = Ipv4Addr::new(127, 0, 0, 2);
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let (target_addr, peer_rx, peer_task) = start_udp_peer_observer().await?;
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","send_through":"{source_ip}","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_udp_over_stream().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let mut stream = connection
            .open_udp_over_stream(target_addr.ip(), target_addr.port())
            .await?;
        stream.send_datagram(b"send-through udp").await?;
        let echoed = stream.recv_datagram(1024).await?;
        assert_eq!(echoed.payload, b"send-through udp");
        stream.finish()?;

        let observed_peer = peer_rx.await?;
        assert_eq!(observed_peer.ip(), IpAddr::V4(source_ip));
        peer_task.await??;
        let report = server_task.await??;
        assert_eq!(report.target, target_addr);
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_tcp_target_through_socks_alias_dialer_link()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime socks alias tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let (proxy_addr, mut requests, proxy_task) = start_socks5_tcp_connect_proxy().await?;
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"socks://{proxy_addr}","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream.write_all(b"server runtime socks alias tcp").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime socks alias tcp");

        let request = tokio::time::timeout(std::time::Duration::from_secs(2), requests.recv())
            .await
            .expect("SOCKS alias proxy did not receive server-runtime CONNECT")
            .expect("SOCKS alias proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        let report = server_task.await??;
        assert_eq!(report.target, proxy_addr);
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_tcp_target_through_socks5_dialer_link()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime socks5 tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let (proxy_addr, mut requests, proxy_task) = start_socks5_tcp_connect_proxy().await?;
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"socks5://{proxy_addr}","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream.write_all(b"server runtime socks5 tcp").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime socks5 tcp");

        let request = tokio::time::timeout(std::time::Duration::from_secs(2), requests.recv())
            .await
            .expect("SOCKS5 proxy did not receive server-runtime CONNECT")
            .expect("SOCKS5 proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        let report = server_task.await??;
        assert_eq!(report.target, proxy_addr);
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_tcp_target_through_shadowsocks_dialer_link()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime shadowsocks tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let ss_password = "server runtime shadowsocks dialer password";
        let (proxy_addr, mut requests, proxy_task) =
            start_shadowsocks_tcp_proxy(ss_password, shadowsocks::crypto::CipherKind::AES_128_GCM)
                .await?;
        let userinfo =
            general_purpose::URL_SAFE_NO_PAD.encode(format!("aes-128-gcm:{ss_password}"));
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"ss://{userinfo}@{proxy_addr}","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream.write_all(b"server runtime shadowsocks tcp").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime shadowsocks tcp");

        let request = tokio::time::timeout(std::time::Duration::from_secs(2), requests.recv())
            .await
            .expect("Shadowsocks proxy did not receive server-runtime TCP request")
            .expect("Shadowsocks proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        let report = server_task.await??;
        assert_eq!(report.target, proxy_addr);
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_tcp_target_through_shadowsocksr_origin_plain_dialer_link()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime shadowsocksr tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let ss_password = "server runtime shadowsocksr dialer password";
        let (proxy_addr, mut requests, proxy_task) =
            start_shadowsocks_tcp_proxy(ss_password, shadowsocks::crypto::CipherKind::AES_128_GCM)
                .await?;
        let raw_link = shadowsocksr_origin_plain_link(
            &proxy_addr.ip().to_string(),
            proxy_addr.port(),
            ss_password,
        );
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"{raw_link}","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream
            .write_all(b"server runtime shadowsocksr origin plain tcp")
            .await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime shadowsocksr origin plain tcp");

        let request = tokio::time::timeout(std::time::Duration::from_secs(2), requests.recv())
            .await
            .expect("ShadowsocksR origin/plain proxy did not receive server-runtime TCP request")
            .expect("ShadowsocksR origin/plain proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        let report = server_task.await??;
        assert_eq!(report.target, proxy_addr);
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_tcp_target_through_trojan_dialer_link()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime trojan tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let trojan_password = "server-runtime-trojan-dialer-password";
        let (proxy_addr, mut requests, proxy_task) =
            start_trojan_tcp_proxy(trojan_password).await?;
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"trojan://{trojan_password}@localhost:{port}?sni=localhost&allowInsecure=true","users":{{"{uuid}":"{password}"}}}}"#,
            port = proxy_addr.port()
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream.write_all(b"server runtime trojan tcp").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime trojan tcp");

        let request = tokio::time::timeout(std::time::Duration::from_secs(2), requests.recv())
            .await
            .expect("Trojan proxy did not receive server-runtime TCP request")
            .expect("Trojan proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        assert_eq!(request.network, zuicity_protocol::Network::Tcp);
        assert_eq!(
            request.auth_hash,
            "25e3a13f6e707740a313273a6c3f4752a1479620582c9d071917e570"
        );
        let report = server_task.await??;
        assert_eq!(report.target, proxy_addr);
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_tcp_target_through_juicity_dialer_link()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime juicity tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let proxy_uuid = uuid::Uuid::new_v4();
        let proxy_password = "server-runtime-juicity-dialer-password";
        let proxy_cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let proxy = zuicity_transport::JuicityQuicServer::bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            proxy_cert.cert.pem().as_bytes(),
            proxy_cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let proxy_addr = proxy.local_addr()?;
        let proxy_task = tokio::spawn(async move {
            let authenticated = proxy
                .accept_authenticated(proxy_uuid, proxy_password.as_bytes())
                .await?;
            authenticated.accept_tcp_proxy_once().await
        });
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"juicity://{proxy_uuid}:{proxy_password}@localhost:{port}?sni=localhost&allowInsecure=true&congestion_control=bbr","users":{{"{uuid}":"{password}"}}}}"#,
            port = proxy_addr.port()
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream.write_all(b"server runtime juicity tcp").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime juicity tcp");

        let report = server_task.await??;
        assert_eq!(report.target, proxy_addr);
        let proxy_report = proxy_task.await??;
        assert_eq!(proxy_report.target, echo_addr);
        assert_eq!(
            proxy_report.bytes_from_client,
            b"server runtime juicity tcp".len() as u64
        );
        assert_eq!(
            proxy_report.bytes_from_target,
            b"server runtime juicity tcp".len() as u64
        );
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_tcp_target_through_vmess_dialer_link()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime vmess tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let vmess_uuid = "00000000-0000-0000-0000-000000000001";
        let vmess_key = vmess_uuid_key(vmess_uuid)?;
        let (proxy_addr, mut requests, proxy_task) = start_vmess_tcp_proxy(vmess_key).await?;
        let link = general_purpose::STANDARD.encode(format!(
            r#"{{"add":"127.0.0.1","port":"{}","id":"{vmess_uuid}","aid":"0","net":"tcp","type":"none","tls":""}}"#,
            proxy_addr.port()
        ));
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"vmess://{link}","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream.write_all(b"server runtime vmess tcp").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime vmess tcp");

        let request = tokio::time::timeout(std::time::Duration::from_secs(2), requests.recv())
            .await
            .expect("VMess proxy did not receive server-runtime TCP request")
            .expect("VMess proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        assert_eq!(request.network, zuicity_protocol::Network::Tcp);
        assert_eq!(request.key, vmess_key);
        let report = server_task.await??;
        assert_eq!(report.target, proxy_addr);
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_tcp_target_through_vless_dialer_link()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime vless tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let vless_uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")?;
        let (proxy_addr, mut requests, proxy_task) = start_vless_tcp_proxy(vless_uuid).await?;
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"vless://{vless_uuid}@127.0.0.1:{port}?type=tcp&security=none&headerType=none","users":{{"{uuid}":"{password}"}}}}"#,
            port = proxy_addr.port()
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream.write_all(b"server runtime vless tcp").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime vless tcp");

        let request = tokio::time::timeout(std::time::Duration::from_secs(2), requests.recv())
            .await
            .expect("VLESS proxy did not receive server-runtime TCP request")
            .expect("VLESS proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        assert_eq!(request.network, zuicity_protocol::Network::Tcp);
        assert_eq!(request.uuid, vless_uuid);
        let report = server_task.await??;
        assert_eq!(report.target, proxy_addr);
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_tcp_target_through_http_dialer_link()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime http tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let (proxy_addr, mut requests, proxy_task) = start_http_connect_proxy().await?;
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"http://{proxy_addr}","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream.write_all(b"server runtime http tcp").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime http tcp");

        let request = tokio::time::timeout(std::time::Duration::from_secs(2), requests.recv())
            .await
            .expect("HTTP proxy did not receive server-runtime CONNECT")
            .expect("HTTP proxy request channel closed");
        assert_eq!(request.authority, echo_addr.to_string());
        let report = server_task.await??;
        assert_eq!(report.target, proxy_addr);
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_tcp_target_through_http_dialer_link_with_basic_auth()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime http auth tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let (proxy_addr, mut requests, proxy_task) = start_http_connect_proxy().await?;
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"http://proxy-user:proxy-pass@{proxy_addr}","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream.write_all(b"server runtime http auth tcp").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime http auth tcp");

        let request = tokio::time::timeout(std::time::Duration::from_secs(2), requests.recv())
            .await
            .expect("HTTP proxy did not receive authenticated server-runtime CONNECT")
            .expect("HTTP proxy request channel closed");
        assert_eq!(request.authority, echo_addr.to_string());
        assert_eq!(
            request.proxy_authorization,
            Some("Basic cHJveHktdXNlcjpwcm94eS1wYXNz".to_owned())
        );
        let report = server_task.await??;
        assert_eq!(report.target, proxy_addr);
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_tcp_target_through_https_dialer_link()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime https tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let (proxy_addr, mut requests, proxy_task) = start_https_connect_proxy().await?;
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"https://localhost:{port}?allowInsecure=true","users":{{"{uuid}":"{password}"}}}}"#,
            port = proxy_addr.port()
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream.write_all(b"server runtime https tcp").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime https tcp");

        let request = tokio::time::timeout(std::time::Duration::from_secs(2), requests.recv())
            .await
            .expect("HTTPS proxy did not receive server-runtime CONNECT")
            .expect("HTTPS proxy request channel closed");
        assert_eq!(request.authority, echo_addr.to_string());
        let report = server_task.await??;
        assert_eq!(report.target, proxy_addr);
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_tcp_target_through_https_dialer_link_with_basic_auth()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime https auth tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let (proxy_addr, mut requests, proxy_task) = start_https_connect_proxy().await?;
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"https://proxy-user:proxy-pass@localhost:{port}?allowInsecure=true","users":{{"{uuid}":"{password}"}}}}"#,
            port = proxy_addr.port()
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream.write_all(b"server runtime https auth tcp").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime https auth tcp");

        let request = tokio::time::timeout(std::time::Duration::from_secs(2), requests.recv())
            .await
            .expect("HTTPS proxy did not receive authenticated server-runtime CONNECT")
            .expect("HTTPS proxy request channel closed");
        assert_eq!(request.authority, echo_addr.to_string());
        assert_eq!(
            request.proxy_authorization,
            Some("Basic cHJveHktdXNlcjpwcm94eS1wYXNz".to_owned())
        );
        let report = server_task.await??;
        assert_eq!(report.target, proxy_addr);
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_tcp_target_through_socks5_https_dialer_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime socks5 https chain tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let (https_proxy_addr, mut https_requests, https_proxy_task) =
            start_https_connect_proxy().await?;
        let (socks_proxy_addr, mut socks_requests, socks_proxy_task) =
            start_socks5_tcp_connect_proxy().await?;
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"socks5://{socks_proxy_addr} -> https://localhost:{port}?allowInsecure=true","users":{{"{uuid}":"{password}"}}}}"#,
            port = https_proxy_addr.port()
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream
            .write_all(b"server runtime socks5 https chain tcp")
            .await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime socks5 https chain tcp");

        let https_request =
            tokio::time::timeout(std::time::Duration::from_secs(2), https_requests.recv())
                .await
                .expect("HTTPS proxy did not receive server-runtime outer CONNECT")
                .expect("HTTPS proxy request channel closed");
        assert_eq!(https_request.authority, socks_proxy_addr.to_string());
        let socks_request =
            tokio::time::timeout(std::time::Duration::from_secs(2), socks_requests.recv())
                .await
                .expect("SOCKS5 proxy did not receive server-runtime inner CONNECT")
                .expect("SOCKS5 proxy request channel closed");
        assert_eq!(socks_request.target, echo_addr);
        let report = server_task.await??;
        assert_eq!(report.target.port(), https_proxy_addr.port());
        drop(stream);
        socks_proxy_task.await??;
        https_proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_tcp_target_through_socks5_http_dialer_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime socks5 http chain tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let (http_proxy_addr, mut http_requests, http_proxy_task) =
            start_http_connect_proxy().await?;
        let (socks_proxy_addr, mut socks_requests, socks_proxy_task) =
            start_socks5_tcp_connect_proxy().await?;
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"socks5://{socks_proxy_addr} -> http://{http_proxy_addr}","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream
            .write_all(b"server runtime socks5 http chain tcp")
            .await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime socks5 http chain tcp");

        let http_request =
            tokio::time::timeout(std::time::Duration::from_secs(2), http_requests.recv())
                .await
                .expect("HTTP proxy did not receive server-runtime outer CONNECT")
                .expect("HTTP proxy request channel closed");
        assert_eq!(http_request.authority, socks_proxy_addr.to_string());
        let socks_request =
            tokio::time::timeout(std::time::Duration::from_secs(2), socks_requests.recv())
                .await
                .expect("SOCKS5 proxy did not receive server-runtime inner CONNECT")
                .expect("SOCKS5 proxy request channel closed");
        assert_eq!(socks_request.target, echo_addr);
        let report = server_task.await??;
        assert_eq!(report.target, http_proxy_addr);
        drop(stream);
        socks_proxy_task.await??;
        http_proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_tcp_target_through_vless_http_dialer_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime vless http chain tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let (http_proxy_addr, mut http_requests, http_proxy_task) =
            start_http_connect_proxy().await?;
        let vless_uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")?;
        let (vless_proxy_addr, mut vless_requests, vless_proxy_task) =
            start_vless_tcp_proxy(vless_uuid).await?;
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"vless://{vless_uuid}@127.0.0.1:{vless_port}?type=tcp&security=none&headerType=none -> http://{http_proxy_addr}","users":{{"{uuid}":"{password}"}}}}"#,
            vless_port = vless_proxy_addr.port()
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream
            .write_all(b"server runtime vless http chain tcp")
            .await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime vless http chain tcp");

        let http_request =
            tokio::time::timeout(std::time::Duration::from_secs(2), http_requests.recv())
                .await
                .expect("HTTP proxy did not receive server-runtime outer CONNECT")
                .expect("HTTP proxy request channel closed");
        assert_eq!(http_request.authority, vless_proxy_addr.to_string());
        let vless_request =
            tokio::time::timeout(std::time::Duration::from_secs(2), vless_requests.recv())
                .await
                .expect("VLESS proxy did not receive server-runtime inner request")
                .expect("VLESS proxy request channel closed");
        assert_eq!(vless_request.target, echo_addr);
        assert_eq!(vless_request.network, zuicity_protocol::Network::Tcp);
        assert_eq!(vless_request.uuid, vless_uuid);
        let report = server_task.await??;
        assert_eq!(report.target, http_proxy_addr);
        drop(stream);
        vless_proxy_task.await??;
        http_proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_tcp_target_through_vmess_http_dialer_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime vmess http chain tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let (http_proxy_addr, mut http_requests, http_proxy_task) =
            start_http_connect_proxy().await?;
        let vmess_uuid = "00000000-0000-0000-0000-000000000001";
        let vmess_key = vmess_uuid_key(vmess_uuid)?;
        let (vmess_proxy_addr, mut vmess_requests, vmess_proxy_task) =
            start_vmess_tcp_proxy(vmess_key).await?;
        let link = general_purpose::STANDARD.encode(format!(
            r#"{{"add":"127.0.0.1","port":"{}","id":"{vmess_uuid}","aid":"0","net":"tcp","type":"none","tls":""}}"#,
            vmess_proxy_addr.port()
        ));
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"vmess://{link} -> http://{http_proxy_addr}","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream
            .write_all(b"server runtime vmess http chain tcp")
            .await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"server runtime vmess http chain tcp");

        let http_request =
            tokio::time::timeout(std::time::Duration::from_secs(2), http_requests.recv())
                .await
                .expect("HTTP proxy did not receive server-runtime outer CONNECT")
                .expect("HTTP proxy request channel closed");
        assert_eq!(http_request.authority, vmess_proxy_addr.to_string());
        let vmess_request =
            tokio::time::timeout(std::time::Duration::from_secs(2), vmess_requests.recv())
                .await
                .expect("VMess proxy did not receive server-runtime inner request")
                .expect("VMess proxy request channel closed");
        assert_eq!(vmess_request.target, echo_addr);
        assert_eq!(vmess_request.network, zuicity_protocol::Network::Tcp);
        assert_eq!(vmess_request.key, vmess_key);
        let report = server_task.await??;
        assert_eq!(report.target, http_proxy_addr);
        drop(stream);
        vmess_proxy_task.await??;
        http_proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_udp_target_through_socks5_dialer_link()
    -> Result<(), Box<dyn std::error::Error>> {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime socks5 udp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::UdpEchoServer::start().await?;
        let (proxy_addr, mut requests, proxy_task) = start_socks5_udp_associate_proxy().await?;
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"socks5://{proxy_addr}","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_udp_over_stream().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_udp_over_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream.send_datagram(b"server runtime socks5 udp").await?;
        let echoed = stream.recv_datagram(1024).await?;
        assert_eq!(echoed.target, echo_addr);
        assert_eq!(echoed.payload, b"server runtime socks5 udp");
        stream.finish()?;

        let request = tokio::time::timeout(std::time::Duration::from_secs(2), requests.recv())
            .await
            .expect("SOCKS5 proxy did not receive server-runtime UDP ASSOCIATE payload")
            .expect("SOCKS5 proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        let report = server_task.await??;
        assert_eq!(report.target, echo_addr);
        proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_routes_udp_target_through_socks5_shadowsocks_dialer_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        zuicity_testkit::retry_on_addr_in_use(|| async {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime socks5 shadowsocks udp chain password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::UdpEchoServer::start().await?;
        let (socks_proxy_addr, mut socks_requests, socks_proxy_task) =
            start_socks5_udp_associate_proxy().await?;
        let shadowsocks_password = "server runtime socks5 shadowsocks udp chain proxy password";
        let (
            shadowsocks_proxy_addr,
            mut shadowsocks_tcp_requests,
            mut shadowsocks_udp_requests,
            shadowsocks_proxy_task,
        ) = start_shadowsocks_tcp_udp_proxy(
            shadowsocks_password,
            shadowsocks::crypto::CipherKind::AES_128_GCM,
        )
        .await?;
        let userinfo =
            general_purpose::URL_SAFE_NO_PAD.encode(format!("aes-128-gcm:{shadowsocks_password}"));
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"socks5://{socks_proxy_addr} -> ss://{userinfo}@{shadowsocks_proxy_addr}","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_udp_over_stream().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_udp_over_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream
            .send_datagram(b"server runtime socks5 shadowsocks udp chain")
            .await?;
        let echoed = stream.recv_datagram(1024).await?;
        assert_eq!(echoed.target, echo_addr);
        assert_eq!(
            echoed.payload,
            b"server runtime socks5 shadowsocks udp chain"
        );
        stream.finish()?;

        let shadowsocks_tcp_request = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            shadowsocks_tcp_requests.recv(),
        )
        .await
        .expect("Shadowsocks proxy did not receive server-runtime SOCKS5 control request")
        .expect("Shadowsocks TCP request channel closed");
        assert_eq!(shadowsocks_tcp_request.target, socks_proxy_addr);
        let shadowsocks_udp_request = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            shadowsocks_udp_requests.recv(),
        )
        .await
        .expect("Shadowsocks proxy did not receive server-runtime SOCKS5 UDP relay datagram")
        .expect("Shadowsocks UDP request channel closed");
        assert_eq!(shadowsocks_udp_request.target.ip(), socks_proxy_addr.ip());
        let socks_request =
            tokio::time::timeout(std::time::Duration::from_secs(2), socks_requests.recv())
                .await
                .expect("SOCKS5 proxy did not receive server-runtime chain UDP payload")
                .expect("SOCKS5 proxy request channel closed");
        assert_eq!(socks_request.target, echo_addr);
        let report = server_task.await??;
        assert_eq!(report.target, echo_addr);
        socks_proxy_task.await??;
        shadowsocks_proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn server_runtime_routes_udp_target_through_shadowsocks_socks5_dialer_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        zuicity_testkit::retry_on_addr_in_use(|| async {
        let uuid = uuid::Uuid::new_v4();
        let password = "runtime shadowsocks socks5 udp chain password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::UdpEchoServer::start().await?;
        let (socks_proxy_addr, mut socks_requests, socks_proxy_task) =
            start_socks5_udp_associate_proxy().await?;
        let shadowsocks_password = "server runtime shadowsocks socks5 udp chain proxy password";
        let (shadowsocks_proxy_addr, mut shadowsocks_requests, shadowsocks_proxy_task) =
            start_shadowsocks_udp_proxy(
                shadowsocks_password,
                shadowsocks::crypto::CipherKind::AES_128_GCM,
            )
            .await?;
        let userinfo =
            general_purpose::URL_SAFE_NO_PAD.encode(format!("aes-128-gcm:{shadowsocks_password}"));
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","dialer_link":"ss://{userinfo}@{shadowsocks_proxy_addr} -> socks5://{socks_proxy_addr}","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_udp_over_stream().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_udp_over_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream
            .send_datagram(b"server runtime shadowsocks socks5 udp chain")
            .await?;
        let echoed = stream.recv_datagram(1024).await?;
        assert_eq!(echoed.target, echo_addr);
        assert_eq!(
            echoed.payload,
            b"server runtime shadowsocks socks5 udp chain"
        );
        stream.finish()?;

        let socks_request =
            tokio::time::timeout(std::time::Duration::from_secs(2), socks_requests.recv())
                .await
                .expect("SOCKS5 proxy did not receive server-runtime Shadowsocks UDP relay")
                .expect("SOCKS5 proxy request channel closed");
        assert_eq!(socks_request.target, shadowsocks_proxy_addr);
        let shadowsocks_request = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            shadowsocks_requests.recv(),
        )
        .await
        .expect("Shadowsocks proxy did not receive server-runtime final UDP payload")
        .expect("Shadowsocks UDP request channel closed");
        assert_eq!(shadowsocks_request.target, echo_addr);
        let report = server_task.await??;
        assert_eq!(report.target, echo_addr);
        shadowsocks_proxy_task.await??;
        socks_proxy_task.await??;
        echo.shutdown().await?;
        Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn server_runtime_authenticates_second_configured_user() -> Result<(), ServerError> {
        let first_uuid = uuid::Uuid::new_v4();
        let second_uuid = uuid::Uuid::new_v4();
        let first_password = "first password";
        let second_password = "second password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{first_uuid}":"{first_password}","{second_uuid}":"{second_password}"}}}}"#
        ))?);

        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                second_uuid,
                second_password.as_bytes(),
            )
            .await?;
        let echo_addr = echo.local_addr();
        let mut stream = connection
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;
        stream.write_all(b"second user tcp").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"second user tcp");

        let report = server_task.await??;
        assert_eq!(report.target, echo_addr);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_tcp_loop_handles_multiple_connections_until_shutdown()
    -> Result<(), ServerError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "loop password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            bound
                .run_tcp_proxy_loop_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let mut expected_bytes = 0_u64;
        for payload in [b"first loop tcp".as_slice(), b"second loop tcp".as_slice()] {
            let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
            let connection = client
                .connect_with_roots(
                    server_addr,
                    "server.local",
                    cert.cert.pem().as_bytes(),
                    false,
                    uuid,
                    password.as_bytes(),
                )
                .await?;
            let mut stream = connection
                .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
                .await?;
            stream.write_all(payload).await?;
            stream.finish()?;
            let echoed = stream.read_to_end(1024).await?;
            assert_eq!(echoed, payload);
            expected_bytes += payload.len() as u64;
        }

        shutdown_tx.send(()).expect("send shutdown");
        let report = server_task.await??;
        assert_eq!(report.accepted_connections, 2);
        assert_eq!(report.completed_tcp_relays, 2);
        assert_eq!(report.bytes_from_client, expected_bytes);
        assert_eq!(report.bytes_from_target, expected_bytes);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_udp_loop_handles_multiple_connections_until_shutdown()
    -> Result<(), ServerError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "udp loop password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            bound
                .run_udp_over_stream_loop_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let mut expected_bytes = 0_u64;
        for payload in [b"first udp loop".as_slice(), b"second udp loop".as_slice()] {
            let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
            let connection = client
                .connect_with_roots(
                    server_addr,
                    "server.local",
                    cert.cert.pem().as_bytes(),
                    false,
                    uuid,
                    password.as_bytes(),
                )
                .await?;
            {
                let mut stream = connection
                    .open_udp_over_stream(echo_addr.ip(), echo_addr.port())
                    .await?;
                stream.send_datagram(payload).await?;
                let echoed = stream.recv_datagram(1024).await?;
                assert_eq!(echoed.payload, payload);
                assert_eq!(echoed.target, echo_addr);
                stream.finish()?;
            }
            drop(connection);
            expected_bytes += payload.len() as u64;
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        shutdown_tx.send(()).expect("send shutdown");
        let report = server_task.await??;
        assert_eq!(report.accepted_connections, 2);
        assert_eq!(report.completed_udp_relays, 2);
        assert_eq!(report.bytes_from_client, expected_bytes);
        assert_eq!(report.bytes_from_target, expected_bytes);
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_proxy_loop_handles_tcp_and_udp_until_shutdown()
    -> Result<(), ServerError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "proxy loop password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let tcp_echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let udp_echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            bound
                .run_proxy_loop_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let tcp_addr = tcp_echo.local_addr();
        let mut tcp_stream = connection
            .open_tcp_proxy_stream(tcp_addr.ip(), tcp_addr.port())
            .await?;
        tcp_stream.write_all(b"classified tcp").await?;
        tcp_stream.finish()?;
        let echoed_tcp = tcp_stream.read_to_end(1024).await?;
        assert_eq!(echoed_tcp, b"classified tcp");

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let udp_addr = udp_echo.local_addr();
        let mut udp_stream = connection
            .open_udp_over_stream(udp_addr.ip(), udp_addr.port())
            .await?;
        udp_stream.send_datagram(b"classified udp").await?;
        let echoed_udp = udp_stream.recv_datagram(1024).await?;
        assert_eq!(echoed_udp.target, udp_addr);
        assert_eq!(echoed_udp.payload, b"classified udp");
        udp_stream.finish()?;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        shutdown_tx.send(()).expect("send shutdown");
        let report = server_task.await??;
        assert_eq!(report.accepted_connections, 2);
        assert_eq!(report.completed_tcp_relays, 1);
        assert_eq!(report.completed_udp_relays, 1);
        assert_eq!(
            report.bytes_from_client,
            b"classified tcp".len() as u64 + b"classified udp".len() as u64
        );
        assert_eq!(report.bytes_from_client, report.bytes_from_target);
        tcp_echo
            .shutdown()
            .await
            .expect("shutdown TCP echo fixture");
        udp_echo
            .shutdown()
            .await
            .expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_proxy_loop_handles_tcp_and_udp_on_same_connection_until_shutdown()
    -> Result<(), ServerError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "same connection password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let tcp_echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let udp_echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            bound
                .run_proxy_loop_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let tcp_addr = tcp_echo.local_addr();
        let mut tcp_stream = connection
            .open_tcp_proxy_stream(tcp_addr.ip(), tcp_addr.port())
            .await?;
        tcp_stream.write_all(b"same connection tcp").await?;
        tcp_stream.finish()?;
        let echoed_tcp = tcp_stream.read_to_end(1024).await?;
        assert_eq!(echoed_tcp, b"same connection tcp");

        let udp_addr = udp_echo.local_addr();
        let mut udp_stream = connection
            .open_udp_over_stream(udp_addr.ip(), udp_addr.port())
            .await?;
        udp_stream.send_datagram(b"same connection udp").await?;
        let echoed_udp = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            udp_stream.recv_datagram(1024),
        )
        .await
        .expect("same-connection UDP relay timed out")?;
        assert_eq!(echoed_udp.target, udp_addr);
        assert_eq!(echoed_udp.payload, b"same connection udp");
        udp_stream.finish()?;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        shutdown_tx.send(()).expect("send shutdown");
        let report = server_task.await??;
        assert_eq!(report.accepted_connections, 1);
        assert_eq!(report.completed_tcp_relays, 1);
        assert_eq!(report.completed_udp_relays, 1);
        assert_eq!(
            report.bytes_from_client,
            b"same connection tcp".len() as u64 + b"same connection udp".len() as u64
        );
        assert_eq!(report.bytes_from_client, report.bytes_from_target);
        tcp_echo
            .shutdown()
            .await
            .expect("shutdown TCP echo fixture");
        udp_echo
            .shutdown()
            .await
            .expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_proxy_loop_handles_concurrent_tcp_udp_churn_until_shutdown()
    -> Result<(), ServerError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "concurrent churn password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let tcp_echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let udp_echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert_pem.as_bytes(),
            key_pem.as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            bound
                .run_proxy_loop_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let tcp_addr = tcp_echo.local_addr();
        let udp_addr = udp_echo.local_addr();
        let mut client_tasks = tokio::task::JoinSet::new();
        for i in 0..4 {
            let cert_pem = cert_pem.clone();
            let password = password.to_owned();
            let payload = format!("concurrent tcp churn {i}").into_bytes();
            client_tasks.spawn(async move {
                let client =
                    zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
                let connection = client
                    .connect_with_roots(
                        server_addr,
                        "server.local",
                        cert_pem.as_bytes(),
                        false,
                        uuid,
                        password.as_bytes(),
                    )
                    .await?;
                let mut stream = connection
                    .open_tcp_proxy_stream(tcp_addr.ip(), tcp_addr.port())
                    .await?;
                stream.write_all(&payload).await?;
                stream.finish()?;
                let echoed = stream.read_to_end(1024).await?;
                assert_eq!(echoed, payload);
                Ok::<_, ServerError>((true, payload.len() as u64))
            });
        }
        for i in 0..4 {
            let cert_pem = cert_pem.clone();
            let password = password.to_owned();
            let payload = format!("concurrent udp churn {i}").into_bytes();
            client_tasks.spawn(async move {
                let client =
                    zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
                let connection = client
                    .connect_with_roots(
                        server_addr,
                        "server.local",
                        cert_pem.as_bytes(),
                        false,
                        uuid,
                        password.as_bytes(),
                    )
                    .await?;
                let mut stream = connection
                    .open_udp_over_stream(udp_addr.ip(), udp_addr.port())
                    .await?;
                stream.send_datagram(&payload).await?;
                let echoed = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    stream.recv_datagram(1024),
                )
                .await
                .expect("concurrent UDP relay timed out")?;
                assert_eq!(echoed.target, udp_addr);
                assert_eq!(echoed.payload, payload);
                stream.finish()?;
                Ok::<_, ServerError>((false, payload.len() as u64))
            });
        }

        let mut tcp_relays = 0_u64;
        let mut udp_relays = 0_u64;
        let mut expected_bytes = 0_u64;
        while let Some(joined) = client_tasks.join_next().await {
            let (is_tcp, bytes) = joined??;
            if is_tcp {
                tcp_relays += 1;
            } else {
                udp_relays += 1;
            }
            expected_bytes += bytes;
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        shutdown_tx.send(()).expect("send shutdown");
        let report = server_task.await??;
        assert_eq!(tcp_relays, 4);
        assert_eq!(udp_relays, 4);
        assert_eq!(report.accepted_connections, 8);
        assert_eq!(report.completed_tcp_relays, 4);
        assert_eq!(report.completed_udp_relays, 4);
        assert_eq!(report.bytes_from_client, expected_bytes);
        assert_eq!(report.bytes_from_target, expected_bytes);
        tcp_echo
            .shutdown()
            .await
            .expect("shutdown TCP echo fixture");
        udp_echo
            .shutdown()
            .await
            .expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[derive(Clone, Debug, Default)]
    struct RecordedServerTraceEvents {
        events: Arc<Mutex<Vec<RecordedServerTraceEvent>>>,
    }

    impl RecordedServerTraceEvents {
        fn layer(&self) -> RecordingServerTraceLayer {
            RecordingServerTraceLayer {
                events: Arc::clone(&self.events),
            }
        }

        fn clear(&self) {
            self.events.lock().expect("trace events lock").clear();
        }

        fn snapshot(&self) -> Vec<RecordedServerTraceEvent> {
            self.events.lock().expect("trace events lock").clone()
        }
    }

    fn install_server_trace_recorder() -> RecordedServerTraceEvents {
        use tracing_subscriber::prelude::*;

        static EVENTS: OnceLock<RecordedServerTraceEvents> = OnceLock::new();
        static INIT: Once = Once::new();

        let events = EVENTS
            .get_or_init(RecordedServerTraceEvents::default)
            .clone();
        INIT.call_once(|| {
            let subscriber = tracing_subscriber::registry().with(events.layer());
            tracing::subscriber::set_global_default(subscriber)
                .expect("install server trace recorder");
        });
        tracing::callsite::rebuild_interest_cache();
        events.clear();
        events
    }

    fn recorded_field_matches(
        event: &RecordedServerTraceEvent,
        field: &str,
        expected: &str,
    ) -> bool {
        event.fields.iter().any(|(name, value)| {
            name == field
                && (value == expected
                    || value
                        .strip_prefix('"')
                        .and_then(|value| value.strip_suffix('"'))
                        == Some(expected))
        })
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct RecordedServerTraceEvent {
        level: tracing::Level,
        message: String,
        fields: Vec<(String, String)>,
    }

    #[derive(Debug)]
    struct RecordingServerTraceLayer {
        events: Arc<Mutex<Vec<RecordedServerTraceEvent>>>,
    }

    impl<S> tracing_subscriber::Layer<S> for RecordingServerTraceLayer
    where
        S: tracing::Subscriber,
    {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if !event.metadata().target().starts_with("zuicity_server") {
                return;
            }
            let mut visitor = RecordingServerTraceVisitor::default();
            event.record(&mut visitor);
            self.events
                .lock()
                .expect("trace events lock")
                .push(RecordedServerTraceEvent {
                    level: *event.metadata().level(),
                    message: visitor.message.unwrap_or_default(),
                    fields: visitor.fields,
                });
        }
    }

    #[derive(Default)]
    struct RecordingServerTraceVisitor {
        message: Option<String>,
        fields: Vec<(String, String)>,
    }

    impl tracing::field::Visit for RecordingServerTraceVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.message = Some(format!("{value:?}"));
            } else {
                self.fields
                    .push((field.name().to_owned(), format!("{value:?}")));
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_runtime_emits_lifecycle_tracing_events() -> Result<(), ServerError> {
        let traces = install_server_trace_recorder();

        let uuid = uuid::Uuid::new_v4();
        let password = "observability password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let root_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            root_pem.as_bytes(),
            key_pem.as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let target = echo.local_addr();

        let bad_client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let bad_root_pem = root_pem.clone();
        let bad_client_task = tokio::spawn(async move {
            let bad_connection = bad_client
                .connect_with_roots(
                    server_addr,
                    "server.local",
                    bad_root_pem.as_bytes(),
                    false,
                    uuid,
                    b"wrong password",
                )
                .await?;
            let _ = bad_connection
                .open_tcp_proxy_stream(target.ip(), target.port())
                .await;
            Ok::<_, zuicity_transport::TransportError>(())
        });
        let rejected = bound.accept_authenticated_connection().await;
        assert!(
            rejected.is_err(),
            "expected auth rejection, got {rejected:?}"
        );
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), bad_client_task)
            .await
            .expect("bad client task timed out")
            .expect("bad client join");

        let good_client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let good_client_task = tokio::spawn(async move {
            let good_connection = good_client
                .connect_with_roots(
                    server_addr,
                    "server.local",
                    root_pem.as_bytes(),
                    false,
                    uuid,
                    password.as_bytes(),
                )
                .await?;
            let mut stream = good_connection
                .open_tcp_proxy_stream(target.ip(), target.port())
                .await?;
            stream.write_all(b"observed tcp").await?;
            stream.finish()?;
            let echoed = stream.read_to_end(1024).await?;
            assert_eq!(echoed, b"observed tcp");
            Ok::<_, ServerError>(())
        });
        let report = bound.accept_one_tcp_proxy_ref().await?;
        assert_eq!(report.target, target);
        assert_eq!(report.bytes_from_client, b"observed tcp".len() as u64);
        assert_eq!(report.bytes_from_target, b"observed tcp".len() as u64);
        good_client_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");

        let events = traces.snapshot();
        let server_addr = server_addr.to_string();
        assert!(
            events.iter().any(|event| {
                event.message.starts_with("Listen at 127.0.0.1:")
                    && recorded_field_matches(event, "listen", &server_addr)
            }),
            "missing listen trace events={events:#?}"
        );
        assert!(
            events
                .iter()
                .any(|event| event.level == tracing::Level::WARN && event.message == "handleAuth"),
            "missing auth rejection trace events={events:#?}"
        );
        let target = target.to_string();
        assert!(
            events.iter().any(|event| {
                event.message == "zuicity received a [tcp] request"
                    && recorded_field_matches(event, "network", "tcp")
                    && recorded_field_matches(event, "target", &target)
            }),
            "missing TCP request trace events={events:#?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_proxy_loop_isolates_bad_auth_and_accepts_next_client()
    -> Result<(), ServerError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "auth isolation password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            bound
                .run_proxy_loop_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let bad_client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let bad_connection = bad_client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                b"wrong password",
            )
            .await?;
        let target = echo.local_addr();
        let _ = bad_connection
            .open_tcp_proxy_stream(target.ip(), target.port())
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let good_client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let good_connection = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            good_client.connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            ),
        )
        .await
        .expect("valid client timed out after bad auth")?;
        let mut stream = good_connection
            .open_tcp_proxy_stream(target.ip(), target.port())
            .await?;
        stream.write_all(b"after bad auth").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"after bad auth");

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        shutdown_tx.send(()).expect("send shutdown");
        let report = server_task.await??;
        assert_eq!(report.accepted_connections, 1);
        assert_eq!(report.completed_tcp_relays, 1);
        assert_eq!(report.rejected_connections, 1);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_proxy_loop_isolates_failed_stream_and_accepts_next_client()
    -> Result<(), ServerError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "stream isolation password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let dead_listener = zuicity_testkit::reserve_tcp_listener().expect("reserve dead target");
        let dead_target = dead_listener.local_addr().expect("dead target addr");
        drop(dead_listener);
        let runtime = ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let bound = runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = bound.local_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            bound
                .run_proxy_loop_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let failing_client =
            zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let failing_connection = failing_client
            .connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            )
            .await?;
        let mut failing_stream = failing_connection
            .open_tcp_proxy_stream(dead_target.ip(), dead_target.port())
            .await?;
        let _ = failing_stream.write_all(b"no target").await;
        let _ = failing_stream.finish();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let good_client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let good_connection = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            good_client.connect_with_roots(
                server_addr,
                "server.local",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password.as_bytes(),
            ),
        )
        .await
        .expect("valid client timed out after failed stream")?;
        let target = echo.local_addr();
        let mut stream = good_connection
            .open_tcp_proxy_stream(target.ip(), target.port())
            .await?;
        stream.write_all(b"after failed stream").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"after failed stream");

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        shutdown_tx.send(()).expect("send shutdown");
        let report = server_task.await??;
        assert_eq!(report.accepted_connections, 2);
        assert_eq!(report.completed_tcp_relays, 1);
        assert_eq!(report.failed_proxy_streams, 1);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[test]
    fn egress_policy_blocks_underlay_udp443_only_when_upstream_flag_is_enabled()
    -> Result<(), ConfigError> {
        let runtime = server_config(
            r#"{
              "listen": ":23182",
              "disable_outbound_udp443": true
            }"#,
        )?;
        let policy = runtime.egress_policy();

        assert!(policy.blocks_underlay_udp_target_port(443));
        assert!(!policy.blocks_underlay_udp_target_port(53));
        assert!(!policy.blocks_underlay_udp_target_port(8443));
        Ok(())
    }

    #[test]
    fn egress_policy_allows_underlay_udp443_when_upstream_flag_is_absent() -> Result<(), ConfigError>
    {
        let runtime = server_config(r#"{"listen":":23182"}"#)?;
        assert!(!runtime.egress_policy().blocks_underlay_udp_target_port(443));
        Ok(())
    }

    #[test]
    fn egress_policy_maps_fwmark_to_transport_policy() -> Result<(), ServerError> {
        let runtime = server_config(r#"{"listen":":23182","fwmark":"0x1234"}"#)?;
        let policy = runtime.egress_policy();
        assert_eq!(policy.fwmark, Some(0x1234));
        let transport_policy = policy.transport_policy()?;
        assert_eq!(transport_policy.fwmark, Some(0x1234));
        assert_eq!(transport_policy.send_through, None);
        Ok(())
    }

    #[test]
    fn egress_policy_maps_http_dialer_link_to_transport_policy() -> Result<(), ServerError> {
        let runtime =
            server_config(r#"{"listen":":23182","dialer_link":"http://127.0.0.1:8080"}"#)?;
        let policy = runtime.egress_policy();
        assert_eq!(policy.dialer_link.as_deref(), Some("http://127.0.0.1:8080"));
        let transport_policy = policy.transport_policy()?;
        assert!(matches!(
            transport_policy.dialer_link,
            Some(zuicity_transport::ProxyDialerLink::HttpConnect(_))
        ));
        Ok(())
    }

    #[test]
    fn egress_policy_maps_https_dialer_link_to_transport_policy() -> Result<(), ServerError> {
        let runtime = server_config(
            r#"{"listen":":23182","dialer_link":"https://proxy.local:8443?allowInsecure=true"}"#,
        )?;
        let policy = runtime.egress_policy();
        assert_eq!(
            policy.dialer_link.as_deref(),
            Some("https://proxy.local:8443?allowInsecure=true")
        );
        let transport_policy = policy.transport_policy()?;
        assert!(matches!(
            transport_policy.dialer_link,
            Some(zuicity_transport::ProxyDialerLink::HttpConnect(_))
        ));
        Ok(())
    }

    #[test]
    fn egress_policy_maps_https_dialer_link_chain_to_transport_policy() -> Result<(), ServerError> {
        let runtime = server_config(
            r#"{"listen":":23182","dialer_link":"socks5://127.0.0.1:1080 -> https://proxy.local:8443?allowInsecure=true"}"#,
        )?;
        let policy = runtime.egress_policy();
        assert_eq!(
            policy.dialer_link.as_deref(),
            Some("socks5://127.0.0.1:1080 -> https://proxy.local:8443?allowInsecure=true")
        );
        let transport_policy = policy.transport_policy()?;
        let Some(zuicity_transport::ProxyDialerLink::Chain(links)) = transport_policy.dialer_link
        else {
            panic!("expected parsed HTTPS dialer-link chain");
        };
        assert_eq!(links.len(), 2);
        assert!(matches!(
            links[0],
            zuicity_transport::ProxyDialerLink::Socks5(_)
        ));
        assert!(matches!(
            links[1],
            zuicity_transport::ProxyDialerLink::HttpConnect(_)
        ));
        Ok(())
    }

    #[test]
    fn egress_policy_maps_dialer_link_chain_to_transport_policy() -> Result<(), ServerError> {
        let runtime = server_config(
            r#"{"listen":":23182","dialer_link":"socks5://127.0.0.1:1080 -> http://127.0.0.1:8080"}"#,
        )?;
        let policy = runtime.egress_policy();
        assert_eq!(
            policy.dialer_link.as_deref(),
            Some("socks5://127.0.0.1:1080 -> http://127.0.0.1:8080")
        );
        let transport_policy = policy.transport_policy()?;
        let Some(zuicity_transport::ProxyDialerLink::Chain(links)) = transport_policy.dialer_link
        else {
            panic!("expected parsed dialer-link chain");
        };
        assert_eq!(links.len(), 2);
        assert!(matches!(
            links[0],
            zuicity_transport::ProxyDialerLink::Socks5(_)
        ));
        assert!(matches!(
            links[1],
            zuicity_transport::ProxyDialerLink::HttpConnect(_)
        ));
        Ok(())
    }

    #[test]
    fn egress_policy_maps_socks_alias_dialer_link_to_transport_policy() -> Result<(), ServerError> {
        let runtime =
            server_config(r#"{"listen":":23182","dialer_link":"socks://127.0.0.1:1080"}"#)?;
        let policy = runtime.egress_policy();
        assert_eq!(
            policy.dialer_link.as_deref(),
            Some("socks://127.0.0.1:1080")
        );
        let transport_policy = policy.transport_policy()?;
        assert!(matches!(
            transport_policy.dialer_link,
            Some(zuicity_transport::ProxyDialerLink::Socks5(_))
        ));
        Ok(())
    }

    #[test]
    fn egress_policy_maps_socks5_dialer_link_to_transport_policy() -> Result<(), ServerError> {
        let runtime =
            server_config(r#"{"listen":":23182","dialer_link":"socks5://127.0.0.1:1080"}"#)?;
        let policy = runtime.egress_policy();
        assert_eq!(
            policy.dialer_link.as_deref(),
            Some("socks5://127.0.0.1:1080")
        );
        let transport_policy = policy.transport_policy()?;
        assert!(matches!(
            transport_policy.dialer_link,
            Some(zuicity_transport::ProxyDialerLink::Socks5(_))
        ));
        Ok(())
    }

    #[test]
    fn egress_policy_maps_trojan_dialer_link_to_transport_policy() -> Result<(), ServerError> {
        let raw_link =
            "trojan://server-runtime-trojan-dialer-password@proxy.local:443?allowInsecure=true";
        let runtime = server_config(&format!(
            r#"{{"listen":":23182","dialer_link":"{raw_link}"}}"#
        ))?;
        let policy = runtime.egress_policy();
        assert_eq!(policy.dialer_link.as_deref(), Some(raw_link));
        let transport_policy = policy.transport_policy()?;
        assert!(matches!(
            transport_policy.dialer_link,
            Some(zuicity_transport::ProxyDialerLink::Trojan(_))
        ));
        Ok(())
    }

    #[test]
    fn egress_policy_maps_juicity_dialer_link_to_transport_policy() -> Result<(), ServerError> {
        let raw_link = "juicity://00000000-0000-0000-0000-000000000001:password@proxy.local:443?allowInsecure=true&congestion_control=bbr";
        let runtime = server_config(&format!(
            r#"{{"listen":":23182","dialer_link":"{raw_link}"}}"#
        ))?;
        let policy = runtime.egress_policy();
        assert_eq!(policy.dialer_link.as_deref(), Some(raw_link));
        let transport_policy = policy.transport_policy()?;
        assert!(matches!(
            transport_policy.dialer_link,
            Some(zuicity_transport::ProxyDialerLink::Juicity(_))
        ));
        Ok(())
    }

    #[test]
    fn egress_policy_maps_hysteria2_dialer_link_to_transport_policy() -> Result<(), ServerError> {
        let raw_link = "hysteria2://user:pass@proxy.local:443?sni=sni.example&insecure=true&pinSHA256=abcd&maxTx=100&maxRx=200";
        let runtime = server_config(&format!(
            r#"{{"listen":":23182","dialer_link":"{raw_link}"}}"#
        ))?;
        let policy = runtime.egress_policy();
        assert_eq!(policy.dialer_link.as_deref(), Some(raw_link));
        let transport_policy = policy.transport_policy()?;
        assert!(matches!(
            transport_policy.dialer_link,
            Some(zuicity_transport::ProxyDialerLink::Hysteria2(_))
        ));
        Ok(())
    }

    #[test]
    fn egress_policy_maps_tuic_dialer_link_to_transport_policy() -> Result<(), ServerError> {
        let raw_link = "tuic://00000000-0000-0000-0000-000000000001:password@proxy.local:443?peer=peer.example&allowInsecure=true&congestion_control=bbr&alpn=h3&udp_relay_mode=native";
        let runtime = server_config(&format!(
            r#"{{"listen":":23182","dialer_link":"{raw_link}"}}"#
        ))?;
        let policy = runtime.egress_policy();
        assert_eq!(policy.dialer_link.as_deref(), Some(raw_link));
        let transport_policy = policy.transport_policy()?;
        assert!(matches!(
            transport_policy.dialer_link,
            Some(zuicity_transport::ProxyDialerLink::Tuic(_))
        ));
        Ok(())
    }

    #[test]
    fn egress_policy_maps_vmess_dialer_link_to_transport_policy() -> Result<(), ServerError> {
        let raw_link = general_purpose::STANDARD.encode(
            r#"{"add":"proxy.local","port":"443","id":"00000000-0000-0000-0000-000000000001","aid":"0","net":"tcp","type":"none","tls":""}"#,
        );
        let raw_link = format!("vmess://{raw_link}");
        let runtime = server_config(&format!(
            r#"{{"listen":":23182","dialer_link":"{raw_link}"}}"#
        ))?;
        let policy = runtime.egress_policy();
        assert_eq!(policy.dialer_link.as_deref(), Some(raw_link.as_str()));
        let transport_policy = policy.transport_policy()?;
        assert!(matches!(
            transport_policy.dialer_link,
            Some(zuicity_transport::ProxyDialerLink::Vmess(_))
        ));
        Ok(())
    }

    #[test]
    fn egress_policy_maps_vless_dialer_link_to_transport_policy() -> Result<(), ServerError> {
        let raw_link = "vless://00000000-0000-0000-0000-000000000001@proxy.local:443?type=tcp&security=none&headerType=none";
        let runtime = server_config(&format!(
            r#"{{"listen":":23182","dialer_link":"{raw_link}"}}"#
        ))?;
        let policy = runtime.egress_policy();
        assert_eq!(policy.dialer_link.as_deref(), Some(raw_link));
        let transport_policy = policy.transport_policy()?;
        assert!(matches!(
            transport_policy.dialer_link,
            Some(zuicity_transport::ProxyDialerLink::Vless(_))
        ));
        Ok(())
    }

    #[test]
    fn egress_policy_maps_shadowsocks_dialer_link_to_transport_policy() -> Result<(), ServerError> {
        let password = "server config shadowsocks password";
        let userinfo = general_purpose::URL_SAFE_NO_PAD.encode(format!("aes-128-gcm:{password}"));
        let raw_link = format!("ss://{userinfo}@127.0.0.1:8388");
        let runtime = server_config(&format!(
            r#"{{"listen":":23182","dialer_link":"{raw_link}"}}"#
        ))?;
        let policy = runtime.egress_policy();
        assert_eq!(policy.dialer_link.as_deref(), Some(raw_link.as_str()));
        let transport_policy = policy.transport_policy()?;
        assert!(matches!(
            transport_policy.dialer_link,
            Some(zuicity_transport::ProxyDialerLink::Shadowsocks(_))
        ));
        Ok(())
    }

    #[test]
    fn egress_policy_maps_shadowsocksr_origin_plain_dialer_link_to_transport_policy()
    -> Result<(), ServerError> {
        let password = "server config shadowsocksr password";
        let raw_link = shadowsocksr_origin_plain_link("127.0.0.1", 8388, password);
        let runtime = server_config(&format!(
            r#"{{"listen":":23182","dialer_link":"{raw_link}"}}"#
        ))?;
        let policy = runtime.egress_policy();
        assert_eq!(policy.dialer_link.as_deref(), Some(raw_link.as_str()));
        let transport_policy = policy.transport_policy()?;
        assert!(matches!(
            transport_policy.dialer_link,
            Some(zuicity_transport::ProxyDialerLink::ShadowsocksR(_))
        ));
        Ok(())
    }
}
