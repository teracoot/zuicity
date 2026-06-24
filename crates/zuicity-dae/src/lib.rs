//! zae facing Zuicity adapter boundaries.

use std::{
    borrow::Cow,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
};
use zuicity_config::{ClientConfig, CongestionControl, ForwardRule};
use zuicity_protocol::AtomicCounter64;
use zuicity_transport::{
    AuthenticatedConnection, JuicityQuicClient, TcpProxyStream, UdpOverStream,
};

/// zae outbound-facing Juicity configuration.
#[derive(Clone, Debug)]
pub struct DaeOutboundConfig {
    /// Validated Juicity client config.
    pub client: ClientConfig,
}

impl DaeOutboundConfig {
    /// Creates an outbound adapter config from a validated Juicity client config.
    #[must_use]
    pub fn from_client_config(client: ClientConfig) -> Self {
        Self { client }
    }

    /// Returns the dae outbound protocol classification.
    #[must_use]
    pub const fn protocol(&self) -> DaeOutboundProtocol {
        DaeOutboundProtocol::Juicity
    }

    /// Returns the upstream Juicity server address.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.client.raw.server
    }

    /// Returns the parsed user UUID.
    #[must_use]
    pub fn uuid(&self) -> uuid::Uuid {
        self.client.uuid
    }

    /// Returns the client password.
    #[must_use]
    pub fn password(&self) -> &str {
        &self.client.raw.password
    }

    /// Returns the TLS SNI dae should pass into transport construction.
    #[must_use]
    pub fn tls_server_name(&self) -> Cow<'_, str> {
        self.client.tls_server_name()
    }

    /// Returns whether upstream-compatible insecure TLS verification is enabled.
    #[must_use]
    pub fn allow_insecure(&self) -> bool {
        self.client.raw.allow_insecure
    }

    /// Returns the configured congestion control, if any.
    #[must_use]
    pub fn congestion_control(&self) -> Option<CongestionControl> {
        self.client.congestion_control
    }

    /// Returns the decoded pinned certificate-chain hash, if configured.
    #[must_use]
    pub fn pinned_certchain_sha256(&self) -> Option<&[u8]> {
        self.client.pinned_certchain_sha256.as_deref()
    }

    /// Returns the TCP/UDP capabilities this outbound exposes to dae.
    #[must_use]
    pub const fn capabilities(&self) -> DaeOutboundCapabilities {
        DaeOutboundCapabilities {
            tcp: true,
            udp: true,
        }
    }

    /// Returns upstream-compatible local forward rules for CLI/local listener use.
    pub fn forward_rules(&self) -> impl Iterator<Item = ForwardRule<'_>> {
        self.client.forward_rules()
    }
}

/// dae outbound protocol discriminant for Juicity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaeOutboundProtocol {
    /// Juicity outbound.
    Juicity,
}

impl DaeOutboundProtocol {
    /// Returns the dae config/runtime protocol spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Juicity => "juicity",
        }
    }
}

/// TCP/UDP capabilities advertised to dae runtime/routing layers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaeOutboundCapabilities {
    /// TCP connect support.
    pub tcp: bool,
    /// UDP association/datagram support.
    pub udp: bool,
}

/// Network kind for dae lifecycle and metrics events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaeNetwork {
    /// TCP stream connection.
    Tcp,
    /// UDP association/datagram flow.
    Udp,
}

/// Logical connection lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaeConnectionState {
    /// Logical connection opened.
    Open,
    /// Logical connection closed.
    Closed,
    /// Logical connection failed before opening.
    Failed,
}

/// Borrowed connection lifecycle event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaeConnectionEvent<'a> {
    /// Event state.
    pub state: DaeConnectionState,
    /// Event network.
    pub network: DaeNetwork,
    /// Destination or association target.
    pub target: &'a str,
}

/// Connection lifecycle hooks expected by an embeddable zae adapter.
pub trait ConnectionLifecycle {
    /// Called when a logical outbound connection event occurs.
    fn on_connection_event(&self, _event: &DaeConnectionEvent<'_>) {}

    /// Called when a logical outbound connection starts.
    fn on_open(&self) {}

    /// Called when a logical outbound connection closes.
    fn on_close(&self) {}
}

/// No-op lifecycle hook implementation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoopConnectionLifecycle;

impl ConnectionLifecycle for NoopConnectionLifecycle {}

/// Thread-safe dae metrics counters for adapter/runtime embedding.
#[derive(Clone, Debug, Default)]
pub struct DaeMetrics {
    inner: Arc<DaeMetricsInner>,
}

#[derive(Debug, Default)]
struct DaeMetricsInner {
    opened_connections: AtomicCounter64,
    closed_connections: AtomicCounter64,
    failed_connections: AtomicCounter64,
    open_connections: AtomicCounter64,
    bytes_sent: AtomicCounter64,
    bytes_received: AtomicCounter64,
}

impl DaeMetrics {
    /// Records an opened connection.
    pub fn connection_opened(&self) {
        self.inner
            .opened_connections
            .fetch_add(1, Ordering::Relaxed);
        self.inner.open_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a closed connection.
    pub fn connection_closed(&self) {
        self.inner
            .closed_connections
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .open_connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_sub(1)
            })
            .ok();
    }

    /// Records a failed connection.
    pub fn connection_failed(&self) {
        self.inner
            .failed_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records bytes sent through the adapter.
    pub fn bytes_sent(&self, bytes: u64) {
        self.inner.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Records bytes received through the adapter.
    pub fn bytes_received(&self, bytes: u64) {
        self.inner
            .bytes_received
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Returns a stable metrics snapshot.
    #[must_use]
    pub fn snapshot(&self) -> DaeMetricsSnapshot {
        DaeMetricsSnapshot {
            opened_connections: self.inner.opened_connections.load(Ordering::Relaxed),
            closed_connections: self.inner.closed_connections.load(Ordering::Relaxed),
            failed_connections: self.inner.failed_connections.load(Ordering::Relaxed),
            open_connections: self.inner.open_connections.load(Ordering::Relaxed),
            bytes_sent: self.inner.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.inner.bytes_received.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of adapter metrics counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DaeMetricsSnapshot {
    /// Total opened logical connections.
    pub opened_connections: u64,
    /// Total closed logical connections.
    pub closed_connections: u64,
    /// Total failed logical connection attempts.
    pub failed_connections: u64,
    /// Current open logical connections.
    pub open_connections: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_received: u64,
}

/// Runtime hooks shared by CLI, tests, and future zae embedding.
#[derive(Clone, Debug)]
pub struct DaeRuntimeHooks<L = NoopConnectionLifecycle> {
    lifecycle: L,
    metrics: DaeMetrics,
}

impl<L> DaeRuntimeHooks<L>
where
    L: ConnectionLifecycle,
{
    /// Creates hooks from lifecycle and metrics implementations.
    #[must_use]
    pub fn new(lifecycle: L, metrics: DaeMetrics) -> Self {
        Self { lifecycle, metrics }
    }

    /// Returns the lifecycle hook object.
    #[must_use]
    pub const fn lifecycle(&self) -> &L {
        &self.lifecycle
    }

    /// Returns the metrics handle.
    #[must_use]
    pub const fn metrics(&self) -> &DaeMetrics {
        &self.metrics
    }

    /// Records and emits an opened connection event.
    pub fn connection_opened(&self, network: DaeNetwork, target: &str) {
        self.metrics.connection_opened();
        self.lifecycle.on_open();
        self.lifecycle.on_connection_event(&DaeConnectionEvent {
            state: DaeConnectionState::Open,
            network,
            target,
        });
    }

    /// Records and emits a closed connection event.
    pub fn connection_closed(&self, network: DaeNetwork, target: &str) {
        self.metrics.connection_closed();
        self.lifecycle.on_close();
        self.lifecycle.on_connection_event(&DaeConnectionEvent {
            state: DaeConnectionState::Closed,
            network,
            target,
        });
    }

    /// Records and emits a failed connection event.
    pub fn connection_failed(&self, network: DaeNetwork, target: &str) {
        self.metrics.connection_failed();
        self.lifecycle.on_connection_event(&DaeConnectionEvent {
            state: DaeConnectionState::Failed,
            network,
            target,
        });
    }

    /// Records sent bytes.
    pub fn bytes_sent(&self, bytes: u64) {
        self.metrics.bytes_sent(bytes);
    }

    /// Records received bytes.
    pub fn bytes_received(&self, bytes: u64) {
        self.metrics.bytes_received(bytes);
    }
}

impl Default for DaeRuntimeHooks<NoopConnectionLifecycle> {
    fn default() -> Self {
        Self::new(NoopConnectionLifecycle, DaeMetrics::default())
    }
}

/// Embeddable zae Juicity outbound connector.
#[derive(Clone, Debug)]
pub struct DaeJuicityConnector<L = NoopConnectionLifecycle>
where
    L: ConnectionLifecycle,
{
    config: DaeOutboundConfig,
    roots_pem: Vec<u8>,
    hooks: DaeRuntimeHooks<L>,
}

impl DaeJuicityConnector<NoopConnectionLifecycle> {
    /// Creates a Juicity dae connector with no-op lifecycle hooks.
    #[must_use]
    pub fn new(config: DaeOutboundConfig, roots_pem: Vec<u8>) -> Self {
        Self::with_hooks(config, roots_pem, DaeRuntimeHooks::default())
    }
}

impl<L> DaeJuicityConnector<L>
where
    L: ConnectionLifecycle,
{
    /// Creates a Juicity dae connector with explicit runtime hooks.
    #[must_use]
    pub fn with_hooks(
        config: DaeOutboundConfig,
        roots_pem: Vec<u8>,
        hooks: DaeRuntimeHooks<L>,
    ) -> Self {
        Self {
            config,
            roots_pem,
            hooks,
        }
    }

    /// Returns the validated outbound config.
    #[must_use]
    pub const fn config(&self) -> &DaeOutboundConfig {
        &self.config
    }

    /// Returns the root PEM bundle used for root-based TLS verification.
    #[must_use]
    pub fn roots_pem(&self) -> &[u8] {
        &self.roots_pem
    }

    /// Returns the runtime hooks used by this connector.
    #[must_use]
    pub const fn hooks(&self) -> &DaeRuntimeHooks<L> {
        &self.hooks
    }
}

impl<L> DaeJuicityConnector<L>
where
    L: ConnectionLifecycle + Clone,
{
    /// Opens an upstream-compatible TCP proxy stream to `target` through Juicity.
    pub async fn connect_tcp(
        &self,
        target: &str,
    ) -> Result<DaeJuicityTcpStream<L>, DaeAdapterError> {
        let result = async {
            let target = DaeProxyTarget::parse(target)?;
            let connection = self.connect_authenticated().await?;
            let stream = match &target {
                DaeProxyTarget::Ip(addr) => {
                    connection
                        .open_tcp_proxy_stream(addr.ip(), addr.port())
                        .await?
                }
                DaeProxyTarget::Domain { host, port } => {
                    connection.open_tcp_proxy_domain_stream(host, *port).await?
                }
            };
            Ok::<_, DaeAdapterError>((target, stream))
        }
        .await;

        match result {
            Ok((target, stream)) => {
                let target = target.to_string();
                tracing::debug!(network = "tcp", target = %target, "dae Juicity connector opened");
                self.hooks.connection_opened(DaeNetwork::Tcp, &target);
                Ok(DaeJuicityTcpStream::new(stream, target, self.hooks.clone()))
            }
            Err(error) => {
                tracing::warn!(network = "tcp", target, error = %error, "dae Juicity connector failed");
                self.hooks.connection_failed(DaeNetwork::Tcp, target);
                Err(error)
            }
        }
    }

    /// Opens an upstream-compatible UDP-over-stream association to `target` through Juicity.
    pub async fn connect_udp(
        &self,
        target: &str,
    ) -> Result<DaeJuicityUdpAssociation<L>, DaeAdapterError> {
        let result = async {
            let target = DaeProxyTarget::parse(target)?;
            let connection = self.connect_authenticated().await?;
            let stream = match &target {
                DaeProxyTarget::Ip(addr) => {
                    connection
                        .open_udp_over_stream(addr.ip(), addr.port())
                        .await?
                }
                DaeProxyTarget::Domain { host, port } => {
                    connection.open_udp_over_domain_stream(host, *port).await?
                }
            };
            Ok::<_, DaeAdapterError>((target, stream))
        }
        .await;

        match result {
            Ok((target, stream)) => {
                let target = target.to_string();
                tracing::debug!(network = "udp", target = %target, "dae Juicity connector opened");
                self.hooks.connection_opened(DaeNetwork::Udp, &target);
                Ok(DaeJuicityUdpAssociation::new(
                    stream,
                    target,
                    self.hooks.clone(),
                ))
            }
            Err(error) => {
                tracing::warn!(network = "udp", target, error = %error, "dae Juicity connector failed");
                self.hooks.connection_failed(DaeNetwork::Udp, target);
                Err(error)
            }
        }
    }

    async fn connect_authenticated(&self) -> Result<AuthenticatedConnection, DaeAdapterError> {
        let server_addr = resolve_server_addr(self.config.server()).await?;
        let client = JuicityQuicClient::bind(local_client_bind_addr(server_addr))?;
        let server_name = self.config.tls_server_name();
        if let Some(pin) = self.config.pinned_certchain_sha256() {
            return Ok(client
                .connect_with_cert_chain_pin(
                    server_addr,
                    server_name.as_ref(),
                    pin,
                    self.config.uuid(),
                    self.config.password().as_bytes(),
                )
                .await?);
        }
        Ok(client
            .connect_with_roots(
                server_addr,
                server_name.as_ref(),
                &self.roots_pem,
                self.config.allow_insecure(),
                self.config.uuid(),
                self.config.password().as_bytes(),
            )
            .await?)
    }
}

/// TCP proxy stream opened by [`DaeJuicityConnector`].
pub struct DaeJuicityTcpStream<L = NoopConnectionLifecycle>
where
    L: ConnectionLifecycle,
{
    send: Pin<Box<dyn AsyncWrite + Send>>,
    recv: Pin<Box<dyn AsyncRead + Send>>,
    target: String,
    hooks: DaeRuntimeHooks<L>,
    closed: bool,
}

impl<L> DaeJuicityTcpStream<L>
where
    L: ConnectionLifecycle,
{
    fn new(stream: TcpProxyStream, target: String, hooks: DaeRuntimeHooks<L>) -> Self {
        let (send, recv) = stream.into_split();
        Self {
            send: Box::pin(send),
            recv: Box::pin(recv),
            target,
            hooks,
            closed: false,
        }
    }

    /// Returns the proxied target string.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    fn close_once(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        tracing::debug!(network = "tcp", target = %self.target, "dae Juicity connector closed");
        self.hooks.connection_closed(DaeNetwork::Tcp, &self.target);
    }
}

impl<L> AsyncRead for DaeJuicityTcpStream<L>
where
    L: ConnectionLifecycle + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match self.recv.as_mut().poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = buf.filled().len().saturating_sub(before);
                if read > 0 {
                    self.hooks.bytes_received(read as u64);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<L> AsyncWrite for DaeJuicityTcpStream<L>
where
    L: ConnectionLifecycle + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.send.as_mut().poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    self.hooks.bytes_sent(written as u64);
                }
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send.as_mut().poll_shutdown(cx)
    }
}

impl<L> Drop for DaeJuicityTcpStream<L>
where
    L: ConnectionLifecycle,
{
    fn drop(&mut self) {
        self.close_once();
    }
}

/// UDP-over-stream association opened by [`DaeJuicityConnector`].
pub struct DaeJuicityUdpAssociation<L = NoopConnectionLifecycle>
where
    L: ConnectionLifecycle,
{
    stream: UdpOverStream,
    target: String,
    hooks: DaeRuntimeHooks<L>,
    closed: bool,
}

impl<L> DaeJuicityUdpAssociation<L>
where
    L: ConnectionLifecycle,
{
    fn new(stream: UdpOverStream, target: String, hooks: DaeRuntimeHooks<L>) -> Self {
        Self {
            stream,
            target,
            hooks,
            closed: false,
        }
    }

    /// Returns the proxied target string.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Sends one datagram payload to the proxied target.
    pub async fn send(&mut self, payload: &[u8]) -> Result<usize, DaeAdapterError> {
        self.stream.send_datagram(payload).await?;
        self.hooks.bytes_sent(payload.len() as u64);
        Ok(payload.len())
    }

    /// Receives one datagram payload from the proxied target.
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, DaeAdapterError> {
        let datagram = self.stream.recv_datagram(buf.len()).await?;
        let len = datagram.payload.len();
        buf[..len].copy_from_slice(&datagram.payload);
        self.hooks.bytes_received(len as u64);
        Ok(len)
    }

    /// Finishes the client-to-server half of this UDP association.
    pub fn finish(&mut self) -> Result<(), DaeAdapterError> {
        Ok(self.stream.finish()?)
    }

    fn close_once(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        tracing::debug!(network = "udp", target = %self.target, "dae Juicity connector closed");
        self.hooks.connection_closed(DaeNetwork::Udp, &self.target);
    }
}

impl<L> Drop for DaeJuicityUdpAssociation<L>
where
    L: ConnectionLifecycle,
{
    fn drop(&mut self) {
        self.close_once();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DaeProxyTarget {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

impl DaeProxyTarget {
    fn parse(value: &str) -> Result<Self, DaeAdapterError> {
        if let Ok(addr) = value.parse::<SocketAddr>() {
            return Ok(Self::Ip(addr));
        }
        let Some((host, port)) = value.rsplit_once(':') else {
            return Err(DaeAdapterError::InvalidTarget {
                value: value.to_owned(),
            });
        };
        if host.is_empty() || port.is_empty() || host.starts_with('[') || host.ends_with(']') {
            return Err(DaeAdapterError::InvalidTarget {
                value: value.to_owned(),
            });
        }
        let port = port
            .parse::<u16>()
            .map_err(|source| DaeAdapterError::InvalidTargetPort {
                value: value.to_owned(),
                source,
            })?;
        Ok(Self::Domain {
            host: host.to_owned(),
            port,
        })
    }
}

impl std::fmt::Display for DaeProxyTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Domain { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

async fn resolve_server_addr(value: &str) -> Result<SocketAddr, DaeAdapterError> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let mut addrs = tokio::net::lookup_host(value).await.map_err(|source| {
        DaeAdapterError::ResolveServerAddr {
            value: value.to_owned(),
            source,
        }
    })?;
    addrs.next().ok_or_else(|| DaeAdapterError::NoServerAddr {
        value: value.to_owned(),
    })
}

fn local_client_bind_addr(server_addr: SocketAddr) -> SocketAddr {
    if server_addr.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    }
}

/// Cloneable shutdown signal for embeddable runtime cancellation.
#[derive(Clone, Debug, Default)]
pub struct DaeShutdownSignal {
    inner: Arc<DaeShutdownInner>,
}

#[derive(Debug, Default)]
struct DaeShutdownInner {
    requested: AtomicBool,
    notify: Notify,
}

impl DaeShutdownSignal {
    /// Creates a shutdown signal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests shutdown and wakes waiters.
    pub fn request_shutdown(&self) {
        self.inner.requested.store(true, Ordering::Release);
        self.inner.notify.notify_waiters();
    }

    /// Returns whether shutdown has been requested.
    #[must_use]
    pub fn is_shutdown_requested(&self) -> bool {
        self.inner.requested.load(Ordering::Acquire)
    }

    /// Waits until shutdown is requested.
    pub async fn wait(&self) {
        if self.is_shutdown_requested() {
            return;
        }
        loop {
            self.inner.notify.notified().await;
            if self.is_shutdown_requested() {
                return;
            }
        }
    }
}

/// Adapter runtime errors.
#[derive(Debug, thiserror::Error)]
pub enum DaeAdapterError {
    /// Server address resolution failed.
    #[error("resolve Juicity server address {value:?}: {source}")]
    ResolveServerAddr {
        /// Configured server address.
        value: String,
        /// Underlying resolver error.
        source: io::Error,
    },
    /// Server address resolved to no socket addresses.
    #[error("Juicity server address {value:?} resolved to no socket addresses")]
    NoServerAddr {
        /// Configured server address.
        value: String,
    },
    /// Proxy target did not have a supported host:port shape.
    #[error("parse dae proxy target {value:?}")]
    InvalidTarget {
        /// Target string supplied by dae.
        value: String,
    },
    /// Proxy target port was invalid.
    #[error("parse dae proxy target port in {value:?}: {source}")]
    InvalidTargetPort {
        /// Target string supplied by dae.
        value: String,
        /// Underlying port parse error.
        source: std::num::ParseIntError,
    },
    /// Juicity transport operation failed.
    #[error(transparent)]
    Transport(#[from] zuicity_transport::TransportError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zuicity_config::{
        ConfigError, CongestionControl, ForwardRule, load_json_str, validate_client,
        validate_server,
    };

    #[derive(Clone, Default)]
    struct RecordingLifecycle {
        events: Arc<Mutex<Vec<(DaeConnectionState, DaeNetwork, String)>>>,
    }

    impl ConnectionLifecycle for RecordingLifecycle {
        fn on_connection_event(&self, event: &DaeConnectionEvent<'_>) {
            self.events
                .lock()
                .unwrap()
                .push((event.state, event.network, event.target.to_owned()));
        }
    }

    fn client_config(json: &str) -> Result<DaeOutboundConfig, ConfigError> {
        Ok(DaeOutboundConfig::from_client_config(validate_client(
            load_json_str(json)?,
        )?))
    }

    fn server_config(
        json: &str,
    ) -> Result<zuicity_server::ServerRuntimeConfig, zuicity_config::ConfigError> {
        Ok(zuicity_server::ServerRuntimeConfig::from_config(
            validate_server(load_json_str(json)?)?,
        ))
    }

    #[test]
    fn outbound_config_maps_client_config_into_dae_ready_node_plan() -> anyhow::Result<()> {
        let raw = load_json_str(
            r#"{
              "server": "example.com:23182",
              "uuid": "00000000-0000-0000-0000-000000000000",
              "password": "my_password",
              "allow_insecure": true,
              "congestion_control": "bbr",
              "pinned_certchain_sha256": "AQIDBA==",
              "forward": {
                "127.0.0.1:5201/tcp": "127.0.0.1:5201"
              }
            }"#,
        )?;
        let client = validate_client(raw)?;
        let outbound = DaeOutboundConfig::from_client_config(client);

        assert_eq!(outbound.protocol(), DaeOutboundProtocol::Juicity);
        assert_eq!(outbound.protocol().as_str(), "juicity");
        assert_eq!(outbound.server(), "example.com:23182");
        assert_eq!(
            outbound.uuid().to_string(),
            "00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(outbound.password(), "my_password");
        assert_eq!(outbound.tls_server_name().as_ref(), "example.com");
        assert!(outbound.allow_insecure());
        assert_eq!(outbound.congestion_control(), Some(CongestionControl::Bbr));
        assert_eq!(outbound.pinned_certchain_sha256(), Some(&[1, 2, 3, 4][..]));
        assert_eq!(
            outbound.capabilities(),
            DaeOutboundCapabilities {
                tcp: true,
                udp: true,
            }
        );
        assert_eq!(
            outbound.forward_rules().collect::<Vec<_>>(),
            vec![ForwardRule {
                local_addr: "127.0.0.1:5201",
                remote_addr: "127.0.0.1:5201",
                relay_tcp: true,
                relay_udp: false,
            }]
        );
        Ok(())
    }

    #[test]
    fn runtime_hooks_record_lifecycle_events_and_metrics() {
        let metrics = DaeMetrics::default();
        let hooks = DaeRuntimeHooks::new(RecordingLifecycle::default(), metrics.clone());
        hooks.connection_opened(DaeNetwork::Tcp, "example.com:443");
        hooks.bytes_sent(11);
        hooks.bytes_received(7);
        hooks.connection_closed(DaeNetwork::Tcp, "example.com:443");

        assert_eq!(
            hooks.lifecycle().events.lock().unwrap().as_slice(),
            &[
                (
                    DaeConnectionState::Open,
                    DaeNetwork::Tcp,
                    "example.com:443".to_owned(),
                ),
                (
                    DaeConnectionState::Closed,
                    DaeNetwork::Tcp,
                    "example.com:443".to_owned(),
                ),
            ]
        );
        assert_eq!(
            metrics.snapshot(),
            DaeMetricsSnapshot {
                opened_connections: 1,
                closed_connections: 1,
                failed_connections: 0,
                open_connections: 0,
                bytes_sent: 11,
                bytes_received: 7,
            }
        );
    }

    #[tokio::test]
    async fn dae_connector_tcp_reaches_rust_server_and_records_hooks() -> anyhow::Result<()> {
        let uuid = uuid::Uuid::new_v4();
        let password = "dae tcp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::TcpEchoServer::start().await?;
        let server_runtime = zuicity_server::ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let server = server_runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .run_proxy_loop_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let metrics = DaeMetrics::default();
        let lifecycle = RecordingLifecycle::default();
        let connector = DaeJuicityConnector::with_hooks(
            client_config(&format!(
                r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
            ))?,
            cert.cert.pem().as_bytes().to_vec(),
            DaeRuntimeHooks::new(lifecycle.clone(), metrics.clone()),
        );

        let payload = b"dae tcp connector";
        let mut stream = connector.connect_tcp(&echo_addr.to_string()).await?;
        stream.write_all(payload).await?;
        stream.shutdown().await?;
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await?;
        assert_eq!(echoed, payload);
        drop(stream);

        shutdown_tx.send(()).expect("send server shutdown");
        let server_report = server_task.await??;
        assert_eq!(server_report.completed_tcp_relays, 1);
        echo.shutdown().await?;
        assert_eq!(
            metrics.snapshot(),
            DaeMetricsSnapshot {
                opened_connections: 1,
                closed_connections: 1,
                failed_connections: 0,
                open_connections: 0,
                bytes_sent: payload.len() as u64,
                bytes_received: payload.len() as u64,
            }
        );
        assert_eq!(
            lifecycle.events.lock().unwrap().as_slice(),
            &[
                (
                    DaeConnectionState::Open,
                    DaeNetwork::Tcp,
                    echo_addr.to_string()
                ),
                (
                    DaeConnectionState::Closed,
                    DaeNetwork::Tcp,
                    echo_addr.to_string(),
                ),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn dae_connector_udp_reaches_rust_server_and_records_hooks() -> anyhow::Result<()> {
        let uuid = uuid::Uuid::new_v4();
        let password = "dae udp password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])?;
        let echo = zuicity_testkit::UdpEchoServer::start().await?;
        let server_runtime = zuicity_server::ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let server = server_runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move { server.accept_one_udp_over_stream().await });

        let echo_addr = echo.local_addr();
        let metrics = DaeMetrics::default();
        let lifecycle = RecordingLifecycle::default();
        let connector = DaeJuicityConnector::with_hooks(
            client_config(&format!(
                r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
            ))?,
            cert.cert.pem().as_bytes().to_vec(),
            DaeRuntimeHooks::new(lifecycle.clone(), metrics.clone()),
        );

        let payload = b"dae udp connector";
        let mut association = connector.connect_udp(&echo_addr.to_string()).await?;
        assert_eq!(association.send(payload).await?, payload.len());
        let mut buf = [0_u8; 1024];
        let received =
            tokio::time::timeout(Duration::from_secs(2), association.recv(&mut buf)).await??;
        assert_eq!(&buf[..received], payload);
        association.finish()?;
        drop(association);

        let server_report = server_task.await??;
        assert_eq!(server_report.target, echo_addr);
        echo.shutdown().await?;
        assert_eq!(
            metrics.snapshot(),
            DaeMetricsSnapshot {
                opened_connections: 1,
                closed_connections: 1,
                failed_connections: 0,
                open_connections: 0,
                bytes_sent: payload.len() as u64,
                bytes_received: payload.len() as u64,
            }
        );
        assert_eq!(
            lifecycle.events.lock().unwrap().as_slice(),
            &[
                (
                    DaeConnectionState::Open,
                    DaeNetwork::Udp,
                    echo_addr.to_string()
                ),
                (
                    DaeConnectionState::Closed,
                    DaeNetwork::Udp,
                    echo_addr.to_string(),
                ),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_signal_is_cloneable_and_awaitable() -> anyhow::Result<()> {
        let signal = DaeShutdownSignal::new();
        let waiter = signal.clone();
        assert!(!waiter.is_shutdown_requested());
        signal.request_shutdown();
        assert!(waiter.is_shutdown_requested());
        tokio::time::timeout(Duration::from_secs(1), waiter.wait()).await?;
        Ok(())
    }
}
