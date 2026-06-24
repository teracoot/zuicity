//! Embeddable Zuicity client runtime boundaries.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zuicity_config::ClientConfig;
use zuicity_transport::{
    DEFAULT_NAT_TIMEOUT, JuicityQuicClient, StreamPolicy, TlsPolicy, UdpOverStream,
};

const MIXED_SHUTDOWN_RELAY_DRAIN_GRACE: Duration = Duration::from_millis(25);
const MIXED_EPHEMERAL_BIND_ATTEMPTS: usize = 128;
const RELAY_COPY_BUFFER_SIZE: usize = 64 * 1024;

/// Upstream mixed listener protocol selected from the first TCP byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixedProtocol {
    /// SOCKS5 TCP session, selected when the first byte is RFC 1928 version 5.
    Socks5,
    /// HTTP proxy session, used for all non-SOCKS5 bytes and peek failures.
    Http,
}

impl MixedProtocol {
    /// Classifies a mixed-listener TCP stream from the optional first byte.
    ///
    /// Upstream calls `conn.Peek(1)` and dispatches to SOCKS5 only when the
    /// byte equals `socks5.Version`; every other value and peek error falls
    /// through to HTTP.
    #[must_use]
    pub const fn from_peeked_byte(byte: Option<u8>) -> Self {
        match byte {
            Some(0x05) => Self::Socks5,
            _ => Self::Http,
        }
    }
}

/// Client runtime options independent from CLI parsing.
#[derive(Clone, Debug)]
pub struct ClientRuntimeConfig {
    /// Validated client config.
    pub config: ClientConfig,
    /// TLS policy.
    pub tls: TlsPolicy,
    /// QUIC stream policy.
    pub streams: StreamPolicy,
}

/// Embeddable client runtime handle.
#[derive(Clone, Debug)]
pub struct ClientRuntime {
    config: ClientRuntimeConfig,
}

impl ClientRuntime {
    /// Creates a client runtime handle without starting network IO.
    #[must_use]
    pub fn new(config: ClientRuntimeConfig) -> Self {
        Self { config }
    }

    /// Returns the runtime config.
    #[must_use]
    pub const fn config(&self) -> &ClientRuntimeConfig {
        &self.config
    }

    /// Binds the configured mixed SOCKS5/HTTP TCP listener using root-based server certificate validation.
    pub async fn bind_configured_mixed_listener_with_roots(
        &self,
        roots_pem: &[u8],
    ) -> Result<Option<MixedTcpListener>, ClientError> {
        if self.config.config.raw.listen.is_empty() {
            return Ok(None);
        }
        let local_addr = self.config.config.raw.listen.parse().map_err(|source| {
            ClientError::InvalidMixedListenAddr {
                value: self.config.config.raw.listen.clone(),
                source,
            }
        })?;
        Ok(Some(
            self.bind_mixed_listener_with_roots(local_addr, roots_pem)
                .await?,
        ))
    }

    /// Binds a mixed SOCKS5/HTTP TCP listener using root-based server certificate validation.
    pub async fn bind_mixed_listener_with_roots(
        &self,
        local_addr: SocketAddr,
        roots_pem: &[u8],
    ) -> Result<MixedTcpListener, ClientError> {
        let (listener, udp_socket) = bind_mixed_tcp_udp_pair(local_addr).await?;
        let bound_addr = listener.local_addr()?;
        tracing::info!(
            "[mixed] http & socks5 server listening TCP on {}",
            bound_addr
        );
        Ok(MixedTcpListener {
            listener,
            udp_socket,
            dialer: SharedQuicDialer::new(self.quic_dialer_params(roots_pem)),
        })
    }

    /// Binds a local TCP forwarder using root-based server certificate validation.
    pub async fn bind_tcp_forwarder_with_roots(
        &self,
        local_addr: SocketAddr,
        remote_target: SocketAddr,
        roots_pem: &[u8],
    ) -> Result<TcpForwarder, ClientError> {
        self.bind_tcp_forwarder_with_roots_inner(
            local_addr,
            TcpForwardTarget::Ip(remote_target),
            roots_pem,
        )
        .await
    }

    /// Binds TCP-capable `forward` rules from the validated client config.
    pub async fn bind_configured_tcp_forwarders_with_roots(
        &self,
        roots_pem: &[u8],
    ) -> Result<Vec<TcpForwarder>, ClientError> {
        let mut forwarders = Vec::new();
        for rule in self.config.config.forward_rules() {
            if !rule.relay_tcp {
                continue;
            }
            let local_addr =
                rule.local_addr
                    .parse()
                    .map_err(|source| ClientError::InvalidForwardLocalAddr {
                        value: rule.local_addr.to_owned(),
                        source,
                    })?;
            let remote_target = parse_tcp_forward_target(rule.remote_addr)?;
            forwarders.push(
                self.bind_tcp_forwarder_with_roots_inner(local_addr, remote_target, roots_pem)
                    .await?,
            );
        }
        Ok(forwarders)
    }

    /// Binds a local UDP forwarder using root-based server certificate validation.
    pub async fn bind_udp_forwarder_with_roots(
        &self,
        local_addr: SocketAddr,
        remote_target: SocketAddr,
        roots_pem: &[u8],
    ) -> Result<UdpForwarder, ClientError> {
        self.bind_udp_forwarder_with_roots_inner(
            local_addr,
            UdpForwardTarget::Ip(remote_target),
            roots_pem,
        )
        .await
    }

    /// Binds UDP-capable `forward` rules from the validated client config.
    pub async fn bind_configured_udp_forwarders_with_roots(
        &self,
        roots_pem: &[u8],
    ) -> Result<Vec<UdpForwarder>, ClientError> {
        let mut forwarders = Vec::new();
        for rule in self.config.config.forward_rules() {
            if !rule.relay_udp {
                continue;
            }
            let local_addr =
                rule.local_addr
                    .parse()
                    .map_err(|source| ClientError::InvalidForwardLocalAddr {
                        value: rule.local_addr.to_owned(),
                        source,
                    })?;
            let remote_target = parse_udp_forward_target(rule.remote_addr)?;
            forwarders.push(
                self.bind_udp_forwarder_with_roots_inner(local_addr, remote_target, roots_pem)
                    .await?,
            );
        }
        Ok(forwarders)
    }

    async fn bind_udp_forwarder_with_roots_inner(
        &self,
        local_addr: SocketAddr,
        remote_target: UdpForwardTarget,
        roots_pem: &[u8],
    ) -> Result<UdpForwarder, ClientError> {
        let socket = tokio::net::UdpSocket::bind(local_addr).await?;
        Ok(UdpForwarder {
            socket: Arc::new(socket),
            remote_target,
            udp_idle_timeout: DEFAULT_NAT_TIMEOUT,
            dialer: SharedQuicDialer::new(self.quic_dialer_params(roots_pem)),
        })
    }

    fn quic_dialer_params(&self, roots_pem: &[u8]) -> QuicDialerParams {
        QuicDialerParams {
            server_addr: self.config.config.raw.server.clone(),
            server_name: self.config.config.tls_server_name().into_owned(),
            roots_pem: roots_pem.to_vec(),
            allow_insecure: self.config.config.raw.allow_insecure,
            uuid: self.config.config.uuid,
            password: self.config.config.raw.password.as_bytes().to_vec(),
        }
    }

    async fn bind_tcp_forwarder_with_roots_inner(
        &self,
        local_addr: SocketAddr,
        remote_target: TcpForwardTarget,
        roots_pem: &[u8],
    ) -> Result<TcpForwarder, ClientError> {
        let listener = tokio::net::TcpListener::bind(local_addr).await?;
        Ok(TcpForwarder {
            listener,
            remote_target,
            dialer: SharedQuicDialer::new(self.quic_dialer_params(roots_pem)),
        })
    }
}

async fn bind_mixed_tcp_udp_pair(
    local_addr: SocketAddr,
) -> Result<(tokio::net::TcpListener, Arc<tokio::net::UdpSocket>), std::io::Error> {
    if local_addr.port() != 0 {
        let listener = tokio::net::TcpListener::bind(local_addr).await?;
        let udp_socket = tokio::net::UdpSocket::bind(listener.local_addr()?).await?;
        return Ok((listener, Arc::new(udp_socket)));
    }

    let mut last_udp_error = None;
    for _ in 0..MIXED_EPHEMERAL_BIND_ATTEMPTS {
        let listener = tokio::net::TcpListener::bind(local_addr).await?;
        match tokio::net::UdpSocket::bind(listener.local_addr()?).await {
            Ok(udp_socket) => return Ok((listener, Arc::new(udp_socket))),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                last_udp_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }

    Err(last_udp_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "failed to bind an ephemeral mixed listener port free for both TCP and UDP",
        )
    }))
}

/// Bound mixed SOCKS5/HTTP TCP listener.
#[derive(Debug)]
pub struct MixedTcpListener {
    listener: tokio::net::TcpListener,
    udp_socket: Arc<tokio::net::UdpSocket>,
    dialer: Arc<SharedQuicDialer>,
}

impl MixedTcpListener {
    /// Returns the local mixed TCP listener address.
    pub fn local_addr(&self) -> Result<SocketAddr, ClientError> {
        Ok(self.listener.local_addr()?)
    }

    /// Accepts one local mixed TCP connection and relays it to the requested target.
    pub async fn accept_one_tcp(self) -> Result<MixedTcpReport, ClientError> {
        self.accept_one_tcp_ref().await
    }

    /// Accepts one SOCKS5 UDP ASSOCIATE control connection and relays UDP datagrams until control close.
    pub async fn accept_one_socks5_udp_associate(
        self,
    ) -> Result<Socks5UdpAssociateReport, ClientError> {
        self.accept_one_socks5_udp_associate_ref().await
    }

    /// Runs a mixed SOCKS5/HTTP accept loop until the shutdown future resolves.
    pub async fn run_loop_until(
        self,
        shutdown: impl Future<Output = ()>,
    ) -> Result<MixedTcpLoopReport, ClientError> {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut report = MixedTcpLoopReport::default();
        let mut tcp_relays = tokio::task::JoinSet::new();
        let mut udp_relays = tokio::task::JoinSet::new();
        let mut pending_udp_relays = VecDeque::new();
        let mut udp_routes = HashMap::new();
        let mut udp_datagram = vec![0_u8; 65_535];
        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => {
                    drain_completed_mixed_relays_after_shutdown(&mut tcp_relays, &mut udp_relays, &mut report).await;
                    return Ok(report);
                }
                completed = tcp_relays.join_next(), if !tcp_relays.is_empty() => {
                    if let Some(completed) = completed {
                        match completed {
                            Ok(Ok(relay)) => record_mixed_tcp_relay(&mut report, relay),
                            Ok(Err(error)) => record_mixed_tcp_relay_error(&mut report, error),
                            Err(err) => {
                                tcp_relays.abort_all();
                                udp_relays.abort_all();
                                return Err(err.into());
                            }
                        }
                    }
                }
                completed = udp_relays.join_next(), if !udp_relays.is_empty() => {
                    if let Some(completed) = completed {
                        match completed {
                            Ok(Ok(relay)) => {
                                udp_routes.remove(&relay.udp_peer);
                                record_mixed_udp_relay(&mut report, relay);
                            }
                            Ok(Err(error)) => record_mixed_udp_relay_error(&mut report, error),
                            Err(err) => {
                                tcp_relays.abort_all();
                                udp_relays.abort_all();
                                return Err(err.into());
                            }
                        }
                    }
                }
                received = self.udp_socket.recv_from(&mut udp_datagram) => {
                    let (received, udp_peer) = received?;
                    route_mixed_socks5_udp_datagram(
                        udp_peer,
                        udp_datagram[..received].to_vec(),
                        &mut pending_udp_relays,
                        &mut udp_routes,
                    ).await;
                }
                accepted = self.listener.accept() => {
                    let (local_stream, local_peer) = accepted?;
                    report.accepted_connections += 1;
                    if let Err(error) = self
                        .spawn_or_handle_mixed_stream(
                            local_stream,
                            local_peer,
                            &mut tcp_relays,
                            &mut udp_relays,
                            &mut pending_udp_relays,
                        )
                        .await
                    {
                        record_mixed_tcp_relay_error(&mut report, error);
                    }
                }
            }
        }
    }

    /// Runs a mixed TCP accept loop until the shutdown future resolves.
    pub async fn run_tcp_loop_until(
        self,
        shutdown: impl Future<Output = ()>,
    ) -> Result<MixedTcpLoopReport, ClientError> {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut report = MixedTcpLoopReport::default();
        loop {
            tokio::select! {
                () = &mut shutdown => return Ok(report),
                relay = self.accept_one_tcp_ref() => {
                    let relay = relay?;
                    report.accepted_connections += 1;
                    report.completed_tcp_relays += 1;
                    report.bytes_from_client += relay.bytes_from_client;
                    report.bytes_from_target += relay.bytes_from_target;
                }
            }
        }
    }

    fn tcp_relay_runtime(&self) -> MixedTcpRelayRuntime {
        MixedTcpRelayRuntime {
            dialer: Arc::clone(&self.dialer),
        }
    }

    fn udp_relay_runtime(&self) -> MixedUdpRelayRuntime {
        MixedUdpRelayRuntime {
            udp_socket: Arc::clone(&self.udp_socket),
            dialer: Arc::clone(&self.dialer),
        }
    }

    async fn spawn_or_handle_mixed_stream(
        &self,
        mut local_stream: tokio::net::TcpStream,
        local_peer: SocketAddr,
        tcp_relays: &mut tokio::task::JoinSet<Result<MixedTcpReport, ClientError>>,
        udp_relays: &mut tokio::task::JoinSet<Result<Socks5UdpAssociateReport, ClientError>>,
        pending_udp_relays: &mut VecDeque<tokio::sync::mpsc::Sender<Socks5UdpInboundDatagram>>,
    ) -> Result<(), ClientError> {
        let mut first = [0_u8; 1];
        let peeked = match local_stream.peek(&mut first).await {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(first[0]),
        };
        match MixedProtocol::from_peeked_byte(peeked) {
            MixedProtocol::Http => {
                let runtime = self.tcp_relay_runtime();
                tcp_relays.spawn(async move {
                    runtime.handle_http_connect(local_stream, local_peer).await
                });
                Ok(())
            }
            MixedProtocol::Socks5 => {
                read_socks5_greeting(&mut local_stream).await?;
                let (command, address_type) = read_socks5_request_header(&mut local_stream).await?;
                match command {
                    0x01 => {
                        let target =
                            read_socks5_tcp_target(&mut local_stream, address_type).await?;
                        let runtime = self.tcp_relay_runtime();
                        tcp_relays.spawn(async move {
                            runtime
                                .relay_socks5_connect(local_stream, local_peer, target)
                                .await
                        });
                        Ok(())
                    }
                    0x03 => {
                        discard_socks5_address_and_port(&mut local_stream, address_type).await?;
                        write_socks5_success_response(
                            &mut local_stream,
                            self.udp_socket.local_addr()?,
                        )
                        .await?;
                        let (datagram_tx, datagram_rx) = tokio::sync::mpsc::channel(32);
                        let runtime = self.udp_relay_runtime();
                        udp_relays.spawn(async move {
                            runtime
                                .relay_socks5_udp_association(local_stream, local_peer, datagram_rx)
                                .await
                        });
                        pending_udp_relays.push_back(datagram_tx);
                        Ok(())
                    }
                    other => Err(ClientError::UnsupportedSocks5Command(other)),
                }
            }
        }
    }

    async fn accept_one_tcp_ref(&self) -> Result<MixedTcpReport, ClientError> {
        let (local_stream, local_peer) = self.listener.accept().await?;
        let mut first = [0_u8; 1];
        let peeked = match local_stream.peek(&mut first).await {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(first[0]),
        };
        match MixedProtocol::from_peeked_byte(peeked) {
            MixedProtocol::Http => self.handle_http_connect(local_stream, local_peer).await,
            MixedProtocol::Socks5 => self.handle_socks5_connect(local_stream, local_peer).await,
        }
    }

    async fn accept_one_socks5_udp_associate_ref(
        &self,
    ) -> Result<Socks5UdpAssociateReport, ClientError> {
        let (mut control_stream, control_peer) = self.listener.accept().await?;
        read_socks5_udp_associate_request(&mut control_stream).await?;
        self.relay_one_socks5_udp_associate_datagram(control_stream, control_peer)
            .await
    }

    async fn relay_one_socks5_udp_associate_datagram(
        &self,
        mut control_stream: tokio::net::TcpStream,
        control_peer: SocketAddr,
    ) -> Result<Socks5UdpAssociateReport, ClientError> {
        let udp_local_addr = self.udp_socket.local_addr()?;
        write_socks5_success_response(&mut control_stream, udp_local_addr).await?;

        let connection = self.dialer.get_connection().await?;

        let mut current_target: Option<Socks5UdpTarget> = None;
        let mut stream: Option<UdpOverStream> = None;
        let mut first_udp_peer: Option<SocketAddr> = None;
        let mut first_remote_target: Option<SocketAddr> = None;
        let mut bytes_from_client = 0_u64;
        let mut bytes_from_target = 0_u64;
        let mut datagram = vec![0_u8; 65_535];
        let mut control_probe = [0_u8; 1];
        loop {
            tokio::select! {
                control = control_stream.read(&mut control_probe) => {
                    match control? {
                        0 => break,
                        _ => return Err(ClientError::InvalidSocks5Request),
                    }
                }
                received = self.udp_socket.recv_from(&mut datagram) => {
                    let (received, udp_peer) = received?;
                    match first_udp_peer {
                        Some(peer) if peer != udp_peer => continue,
                        Some(_) => {}
                        None => {
                            first_udp_peer = Some(udp_peer);
                        }
                    }
                    let request = decode_socks5_udp_datagram(&datagram[..received])?;
                    if current_target.as_ref() != Some(&request.target) {
                        if let Some(mut old_stream) = stream.take() {
                            old_stream.finish()?;
                        }
                        stream = Some(match &request.target {
                            Socks5UdpTarget::Ip(addr) => {
                                connection
                                    .open_udp_over_stream(addr.ip(), addr.port())
                                    .await?
                            }
                            Socks5UdpTarget::Domain { domain, port } => {
                                connection
                                    .open_udp_over_domain_stream(domain, *port)
                                    .await?
                            }
                        });
                        current_target = Some(request.target.clone());
                    }
                    let stream = stream
                        .as_mut()
                        .expect("SOCKS5 UDP stream is opened before relaying");
                    stream.send_datagram(&request.payload).await?;
                    let response = tokio::select! {
                        control = control_stream.read(&mut control_probe) => {
                            match control? {
                                0 => break,
                                _ => return Err(ClientError::InvalidSocks5Request),
                            }
                        }
                        response = stream.recv_datagram(65_535) => response?,
                    };
                    let encoded = encode_socks5_udp_datagram(response.target, &response.payload)?;
                    self.udp_socket.send_to(&encoded, udp_peer).await?;
                    first_remote_target.get_or_insert(response.target);
                    bytes_from_client += request.payload.len() as u64;
                    bytes_from_target += response.payload.len() as u64;
                }
            }
        }
        if let Some(mut stream) = stream {
            stream.finish()?;
        }
        Ok(Socks5UdpAssociateReport {
            control_peer,
            udp_peer: first_udp_peer.ok_or(ClientError::InvalidSocks5Request)?,
            remote_target: first_remote_target.ok_or(ClientError::InvalidSocks5Request)?,
            bytes_from_client,
            bytes_from_target,
        })
    }

    async fn handle_http_connect(
        &self,
        mut local_stream: tokio::net::TcpStream,
        local_peer: SocketAddr,
    ) -> Result<MixedTcpReport, ClientError> {
        let target = read_http_connect_target(&mut local_stream).await?;
        let quic_stream = self.open_tcp_proxy_stream(&target).await?;
        local_stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;
        let report = relay_local_tcp_stream(local_stream, local_peer, target, quic_stream).await?;
        Ok(MixedTcpReport::from_tcp_report(MixedProtocol::Http, report))
    }

    async fn handle_socks5_connect(
        &self,
        mut local_stream: tokio::net::TcpStream,
        local_peer: SocketAddr,
    ) -> Result<MixedTcpReport, ClientError> {
        let target = read_socks5_connect_target(&mut local_stream).await?;
        self.relay_socks5_connect(local_stream, local_peer, target)
            .await
    }

    async fn relay_socks5_connect(
        &self,
        mut local_stream: tokio::net::TcpStream,
        local_peer: SocketAddr,
        target: TcpForwardTarget,
    ) -> Result<MixedTcpReport, ClientError> {
        let quic_stream = self.open_tcp_proxy_stream(&target).await?;
        local_stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        let report = relay_local_tcp_stream(local_stream, local_peer, target, quic_stream).await?;
        Ok(MixedTcpReport::from_tcp_report(
            MixedProtocol::Socks5,
            report,
        ))
    }

    async fn open_tcp_proxy_stream(
        &self,
        target: &TcpForwardTarget,
    ) -> Result<zuicity_transport::TcpProxyStream, ClientError> {
        let connection = self.dialer.get_connection().await?;
        let result = match target {
            TcpForwardTarget::Ip(addr) => {
                connection
                    .open_tcp_proxy_stream(addr.ip(), addr.port())
                    .await
            }
            TcpForwardTarget::Domain { domain, port } => {
                connection
                    .open_tcp_proxy_domain_stream(domain, *port)
                    .await
            }
        };
        match result {
            Ok(stream) => Ok(stream),
            Err(error) => {
                self.dialer.invalidate().await;
                Err(error.into())
            }
        }
    }
}

#[derive(Clone, Debug)]
struct MixedTcpRelayRuntime {
    dialer: Arc<SharedQuicDialer>,
}

impl MixedTcpRelayRuntime {
    async fn handle_http_connect(
        &self,
        mut local_stream: tokio::net::TcpStream,
        local_peer: SocketAddr,
    ) -> Result<MixedTcpReport, ClientError> {
        let target = read_http_connect_target(&mut local_stream).await?;
        let quic_stream = self.open_tcp_proxy_stream(&target).await?;
        local_stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;
        let report = relay_local_tcp_stream(local_stream, local_peer, target, quic_stream).await?;
        Ok(MixedTcpReport::from_tcp_report(MixedProtocol::Http, report))
    }

    async fn relay_socks5_connect(
        &self,
        mut local_stream: tokio::net::TcpStream,
        local_peer: SocketAddr,
        target: TcpForwardTarget,
    ) -> Result<MixedTcpReport, ClientError> {
        let quic_stream = self.open_tcp_proxy_stream(&target).await?;
        local_stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        let report = relay_local_tcp_stream(local_stream, local_peer, target, quic_stream).await?;
        Ok(MixedTcpReport::from_tcp_report(
            MixedProtocol::Socks5,
            report,
        ))
    }

    async fn open_tcp_proxy_stream(
        &self,
        target: &TcpForwardTarget,
    ) -> Result<zuicity_transport::TcpProxyStream, ClientError> {
        let connection = self.dialer.get_connection().await?;
        let result = match target {
            TcpForwardTarget::Ip(addr) => {
                connection
                    .open_tcp_proxy_stream(addr.ip(), addr.port())
                    .await
            }
            TcpForwardTarget::Domain { domain, port } => {
                connection
                    .open_tcp_proxy_domain_stream(domain, *port)
                    .await
            }
        };
        match result {
            Ok(stream) => Ok(stream),
            Err(error) => {
                self.dialer.invalidate().await;
                Err(error.into())
            }
        }
    }
}

#[derive(Clone, Debug)]
struct MixedUdpRelayRuntime {
    udp_socket: Arc<tokio::net::UdpSocket>,
    dialer: Arc<SharedQuicDialer>,
}

#[derive(Debug)]
struct Socks5UdpInboundDatagram {
    udp_peer: SocketAddr,
    datagram: Vec<u8>,
}

impl MixedUdpRelayRuntime {
    async fn relay_socks5_udp_association(
        &self,
        mut control_stream: tokio::net::TcpStream,
        control_peer: SocketAddr,
        mut incoming: tokio::sync::mpsc::Receiver<Socks5UdpInboundDatagram>,
    ) -> Result<Socks5UdpAssociateReport, ClientError> {
        let connection = self.dialer.get_connection().await?;

        let mut current_target: Option<Socks5UdpTarget> = None;
        let mut stream: Option<UdpOverStream> = None;
        let mut first_udp_peer: Option<SocketAddr> = None;
        let mut first_remote_target: Option<SocketAddr> = None;
        let mut bytes_from_client = 0_u64;
        let mut bytes_from_target = 0_u64;
        let mut control_probe = [0_u8; 1];
        loop {
            tokio::select! {
                control = control_stream.read(&mut control_probe) => {
                    match control? {
                        0 => break,
                        _ => return Err(ClientError::InvalidSocks5Request),
                    }
                }
                received = incoming.recv() => {
                    let Some(received) = received else {
                        break;
                    };
                    match first_udp_peer {
                        Some(peer) if peer != received.udp_peer => continue,
                        Some(_) => {}
                        None => {
                            first_udp_peer = Some(received.udp_peer);
                        }
                    }
                    let request = decode_socks5_udp_datagram(&received.datagram)?;
                    if current_target.as_ref() != Some(&request.target) {
                        if let Some(mut old_stream) = stream.take() {
                            old_stream.finish()?;
                        }
                        stream = Some(match &request.target {
                            Socks5UdpTarget::Ip(addr) => {
                                connection
                                    .open_udp_over_stream(addr.ip(), addr.port())
                                    .await?
                            }
                            Socks5UdpTarget::Domain { domain, port } => {
                                connection
                                    .open_udp_over_domain_stream(domain, *port)
                                    .await?
                            }
                        });
                        current_target = Some(request.target.clone());
                    }
                    let stream = stream
                        .as_mut()
                        .expect("SOCKS5 UDP stream is opened before relaying");
                    stream.send_datagram(&request.payload).await?;
                    let response = tokio::select! {
                        control = control_stream.read(&mut control_probe) => {
                            match control? {
                                0 => break,
                                _ => return Err(ClientError::InvalidSocks5Request),
                            }
                        }
                        response = stream.recv_datagram(65_535) => response?,
                    };
                    let encoded = encode_socks5_udp_datagram(response.target, &response.payload)?;
                    self.udp_socket.send_to(&encoded, received.udp_peer).await?;
                    first_remote_target.get_or_insert(response.target);
                    bytes_from_client += request.payload.len() as u64;
                    bytes_from_target += response.payload.len() as u64;
                }
            }
        }
        if let Some(mut stream) = stream {
            stream.finish()?;
        }
        Ok(Socks5UdpAssociateReport {
            control_peer,
            udp_peer: first_udp_peer.ok_or(ClientError::InvalidSocks5Request)?,
            remote_target: first_remote_target.ok_or(ClientError::InvalidSocks5Request)?,
            bytes_from_client,
            bytes_from_target,
        })
    }
}

async fn route_mixed_socks5_udp_datagram(
    udp_peer: SocketAddr,
    mut datagram: Vec<u8>,
    pending_udp_relays: &mut VecDeque<tokio::sync::mpsc::Sender<Socks5UdpInboundDatagram>>,
    udp_routes: &mut HashMap<SocketAddr, tokio::sync::mpsc::Sender<Socks5UdpInboundDatagram>>,
) {
    if let Some(route) = udp_routes.get(&udp_peer).cloned() {
        match route
            .send(Socks5UdpInboundDatagram { udp_peer, datagram })
            .await
        {
            Ok(()) => return,
            Err(error) => {
                datagram = error.0.datagram;
                udp_routes.remove(&udp_peer);
            }
        }
    }

    while let Some(route) = pending_udp_relays.pop_front() {
        if route.is_closed() {
            continue;
        }
        match route
            .send(Socks5UdpInboundDatagram { udp_peer, datagram })
            .await
        {
            Ok(()) => {
                udp_routes.insert(udp_peer, route);
                return;
            }
            Err(error) => {
                datagram = error.0.datagram;
            }
        }
    }
}

/// Connection parameters shared by every forwarder dial.
///
/// Mirrors the upstream Go client which builds the juicity dialer once and
/// reuses it for every accepted local connection (`cmd/client/run.go:105`).
#[derive(Clone, Debug)]
struct QuicDialerParams {
    server_addr: String,
    server_name: String,
    roots_pem: Vec<u8>,
    allow_insecure: bool,
    uuid: uuid::Uuid,
    password: Vec<u8>,
}

/// Lazily-established, auto-reconnecting authenticated QUIC connection reused
/// across all accepted local connections of a forwarder.
///
/// A single authenticated QUIC connection multiplexes one bidirectional stream
/// per accepted TCP connection / UDP local peer, removing the per-connection
/// TLS1.3 handshake and auth round-trip. The cache is discarded and rebuilt
/// automatically once the underlying connection reports a close reason, which
/// recovers from idle close, server restart, and migration failure.
#[derive(Debug)]
struct SharedQuicDialer {
    params: QuicDialerParams,
    cache: tokio::sync::Mutex<Option<CachedQuicConnection>>,
}

#[derive(Debug)]
struct CachedQuicConnection {
    // The endpoint is kept alive alongside the connection so it is not dropped
    // while streams are still being multiplexed over the connection.
    _client: JuicityQuicClient,
    connection: zuicity_transport::AuthenticatedConnection,
}

impl SharedQuicDialer {
    fn new(params: QuicDialerParams) -> Arc<Self> {
        Arc::new(Self {
            params,
            cache: tokio::sync::Mutex::new(None),
        })
    }

    /// Returns a healthy authenticated QUIC connection, establishing or
    /// re-establishing it as needed.
    ///
    /// The returned [`AuthenticatedConnection`] is a cheap clone of the cached
    /// quinn handle; opening a new proxy stream on it multiplexes over the same
    /// connection. A cached connection whose quinn `close_reason()` is set is
    /// treated as dead, discarded, and replaced by a fresh dial.
    async fn get_connection(
        &self,
    ) -> Result<zuicity_transport::AuthenticatedConnection, ClientError> {
        let mut cache = self.cache.lock().await;
        if let Some(cached) = cache.as_ref() {
            if cached.connection.as_quinn().close_reason().is_none() {
                return Ok(cached.connection.clone());
            }
            // The cached connection has closed/errored; drop it before redialing.
            *cache = None;
        }
        let cached = self.dial().await?;
        let connection = cached.connection.clone();
        *cache = Some(cached);
        Ok(connection)
    }

    /// Discards any cached connection so the next [`Self::get_connection`] dials
    /// afresh. Used after a stream-open error that indicates the connection died.
    async fn invalidate(&self) {
        *self.cache.lock().await = None;
    }

    async fn dial(&self) -> Result<CachedQuicConnection, ClientError> {
        let server_addr = parse_client_server_addr(&self.params.server_addr)?;
        let client = JuicityQuicClient::bind(client_dialer_bind_addr(server_addr))?;
        let connection = client
            .connect_with_roots(
                server_addr,
                &self.params.server_name,
                &self.params.roots_pem,
                self.params.allow_insecure,
                self.params.uuid,
                &self.params.password,
            )
            .await?;
        Ok(CachedQuicConnection {
            _client: client,
            connection,
        })
    }
}

/// Bound local TCP forwarder.
#[derive(Debug)]
pub struct TcpForwarder {
    listener: tokio::net::TcpListener,
    remote_target: TcpForwardTarget,
    dialer: Arc<SharedQuicDialer>,
}

/// TCP proxy target configured for a local forwarder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpForwardTarget {
    /// IP socket-address target.
    Ip(SocketAddr),
    /// Domain-name target plus port.
    Domain {
        /// Domain name encoded into the Juicity TCP proxy header.
        domain: String,
        /// TCP target port encoded into the Juicity TCP proxy header.
        port: u16,
    },
}

impl TcpForwardTarget {
    fn ip_or_domain(value: &str) -> Result<Self, ClientError> {
        if let Ok(addr) = value.parse() {
            return Ok(Self::Ip(addr));
        }
        let (domain, port) =
            split_domain_port(value).ok_or_else(|| ClientError::InvalidForwardRemoteTarget {
                value: value.to_owned(),
            })?;
        Ok(Self::Domain {
            domain: domain.to_owned(),
            port,
        })
    }
}

impl fmt::Display for TcpForwardTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => addr.fmt(formatter),
            Self::Domain { domain, port } => write!(formatter, "{domain}:{port}"),
        }
    }
}

impl TcpForwarder {
    /// Returns the local TCP listener address.
    pub fn local_addr(&self) -> Result<SocketAddr, ClientError> {
        Ok(self.listener.local_addr()?)
    }

    /// Accepts one local TCP connection and relays it to the configured remote target.
    pub async fn accept_one(self) -> Result<TcpForwardReport, ClientError> {
        self.accept_one_ref().await
    }

    /// Runs a TCP forward accept loop until the shutdown future resolves.
    pub async fn run_tcp_forward_loop_until(
        self,
        shutdown: impl Future<Output = ()>,
    ) -> Result<TcpForwardLoopReport, ClientError> {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut report = TcpForwardLoopReport::default();
        loop {
            tokio::select! {
                () = &mut shutdown => return Ok(report),
                relay = self.accept_one_ref() => {
                    let relay = relay?;
                    report.accepted_connections += 1;
                    report.completed_tcp_relays += 1;
                    report.bytes_from_client += relay.bytes_from_client;
                    report.bytes_from_target += relay.bytes_from_target;
                }
            }
        }
    }

    async fn accept_one_ref(&self) -> Result<TcpForwardReport, ClientError> {
        let (local_stream, local_peer) = self.listener.accept().await?;
        let quic_stream = self.open_tcp_stream_with_reconnect().await?;
        relay_local_tcp_stream(
            local_stream,
            local_peer,
            self.remote_target.clone(),
            quic_stream,
        )
        .await
    }

    /// Opens a TCP proxy stream over the shared connection, redialing once if
    /// the cached connection has died (idle close, server restart, migration).
    async fn open_tcp_stream_with_reconnect(
        &self,
    ) -> Result<zuicity_transport::TcpProxyStream, ClientError> {
        let connection = self.dialer.get_connection().await?;
        match self.open_tcp_stream(&connection).await {
            Ok(stream) => Ok(stream),
            Err(error) => {
                self.dialer.invalidate().await;
                let connection = self.dialer.get_connection().await?;
                self.open_tcp_stream(&connection).await.map_err(|_| error)
            }
        }
    }

    async fn open_tcp_stream(
        &self,
        connection: &zuicity_transport::AuthenticatedConnection,
    ) -> Result<zuicity_transport::TcpProxyStream, ClientError> {
        let stream = match &self.remote_target {
            TcpForwardTarget::Ip(addr) => {
                connection
                    .open_tcp_proxy_stream(addr.ip(), addr.port())
                    .await?
            }
            TcpForwardTarget::Domain { domain, port } => {
                connection
                    .open_tcp_proxy_domain_stream(domain, *port)
                    .await?
            }
        };
        Ok(stream)
    }
}

async fn relay_copy<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut buffer = vec![0_u8; RELAY_COPY_BUFFER_SIZE];
    let mut copied = 0_u64;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read]).await?;
        copied += read as u64;
    }
    writer.flush().await?;
    Ok(copied)
}

async fn relay_local_tcp_stream(
    local_stream: tokio::net::TcpStream,
    local_peer: SocketAddr,
    remote_target: TcpForwardTarget,
    quic_stream: zuicity_transport::TcpProxyStream,
) -> Result<TcpForwardReport, ClientError> {
    // Disable Nagle on the locally accepted socket: relayed writes are already
    // batched into 64 KiB chunks, so withholding small segments only adds
    // round-trip delay without improving bulk throughput.
    local_stream.set_nodelay(true)?;
    let (mut quic_send, mut quic_recv) = quic_stream.into_split();
    let (mut local_read, mut local_write) = local_stream.into_split();

    let local_to_remote = async {
        let bytes = relay_copy(&mut local_read, &mut quic_send).await?;
        quic_send
            .finish()
            .map_err(zuicity_transport::TransportError::from)?;
        Ok::<_, ClientError>(bytes)
    };
    let remote_to_local = async {
        let bytes = relay_copy(&mut quic_recv, &mut local_write).await?;
        local_write.shutdown().await?;
        Ok::<_, ClientError>(bytes)
    };

    let (bytes_from_client, bytes_from_target) =
        tokio::try_join!(local_to_remote, remote_to_local)?;
    Ok(TcpForwardReport {
        local_peer,
        remote_target,
        bytes_from_client,
        bytes_from_target,
    })
}

async fn read_http_connect_target(
    stream: &mut tokio::net::TcpStream,
) -> Result<TcpForwardTarget, ClientError> {
    let mut request = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        if request.len() >= 8192 {
            return Err(ClientError::InvalidHttpConnectRequest);
        }
        stream.read_exact(&mut byte).await?;
        request.push(byte[0]);
    }
    let request =
        std::str::from_utf8(&request).map_err(|_| ClientError::InvalidHttpConnectRequest)?;
    let mut parts = request
        .lines()
        .next()
        .ok_or(ClientError::InvalidHttpConnectRequest)?
        .split_whitespace();
    let method = parts.next().ok_or(ClientError::InvalidHttpConnectRequest)?;
    let target = parts.next().ok_or(ClientError::InvalidHttpConnectRequest)?;
    let version = parts.next().ok_or(ClientError::InvalidHttpConnectRequest)?;
    if method != "CONNECT" || !version.starts_with("HTTP/") || parts.next().is_some() {
        return Err(ClientError::InvalidHttpConnectRequest);
    }
    parse_tcp_forward_target(target)
}

async fn read_socks5_greeting(stream: &mut tokio::net::TcpStream) -> Result<(), ClientError> {
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 || greeting[1] == 0 {
        return Err(ClientError::InvalidSocks5Request);
    }
    let mut methods = vec![0_u8; greeting[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xff]).await?;
        return Err(ClientError::UnsupportedSocks5Auth);
    }
    stream.write_all(&[0x05, 0x00]).await?;
    Ok(())
}

async fn read_socks5_request_header(
    stream: &mut tokio::net::TcpStream,
) -> Result<(u8, u8), ClientError> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 || header[2] != 0x00 {
        return Err(ClientError::InvalidSocks5Request);
    }
    Ok((header[1], header[3]))
}

async fn read_socks5_tcp_target(
    stream: &mut tokio::net::TcpStream,
    address_type: u8,
) -> Result<TcpForwardTarget, ClientError> {
    let target = match address_type {
        0x01 => {
            let mut addr = [0_u8; 4];
            stream.read_exact(&mut addr).await?;
            let port = read_network_port(stream).await?;
            TcpForwardTarget::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port))
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            if len[0] == 0 {
                return Err(ClientError::InvalidSocks5Request);
            }
            let mut domain = vec![0_u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let domain =
                String::from_utf8(domain).map_err(|_| ClientError::InvalidSocks5Request)?;
            let port = read_network_port(stream).await?;
            TcpForwardTarget::Domain { domain, port }
        }
        0x04 => {
            let mut addr = [0_u8; 16];
            stream.read_exact(&mut addr).await?;
            let port = read_network_port(stream).await?;
            TcpForwardTarget::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port))
        }
        _ => return Err(ClientError::InvalidSocks5Request),
    };
    Ok(target)
}

async fn read_socks5_connect_target(
    stream: &mut tokio::net::TcpStream,
) -> Result<TcpForwardTarget, ClientError> {
    read_socks5_greeting(stream).await?;
    let (command, address_type) = read_socks5_request_header(stream).await?;
    if command != 0x01 {
        return Err(ClientError::UnsupportedSocks5Command(command));
    }
    read_socks5_tcp_target(stream, address_type).await
}

async fn read_socks5_udp_associate_request(
    stream: &mut tokio::net::TcpStream,
) -> Result<(), ClientError> {
    read_socks5_greeting(stream).await?;
    let (command, address_type) = read_socks5_request_header(stream).await?;
    if command != 0x03 {
        return Err(ClientError::UnsupportedSocks5Command(command));
    }
    discard_socks5_address_and_port(stream, address_type).await
}

async fn discard_socks5_address_and_port(
    stream: &mut tokio::net::TcpStream,
    atyp: u8,
) -> Result<(), ClientError> {
    match atyp {
        0x01 => {
            let mut addr = [0_u8; 4];
            stream.read_exact(&mut addr).await?;
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            if len[0] == 0 {
                return Err(ClientError::InvalidSocks5Request);
            }
            let mut domain = vec![0_u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
        }
        0x04 => {
            let mut addr = [0_u8; 16];
            stream.read_exact(&mut addr).await?;
        }
        _ => return Err(ClientError::InvalidSocks5Request),
    }
    let _ = read_network_port(stream).await?;
    Ok(())
}

async fn write_socks5_success_response(
    stream: &mut tokio::net::TcpStream,
    bind_addr: SocketAddr,
) -> Result<(), ClientError> {
    let mut response = Vec::with_capacity(22);
    response.extend_from_slice(&[0x05, 0x00, 0x00]);
    match bind_addr {
        SocketAddr::V4(addr) => {
            response.push(0x01);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            response.push(0x04);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    stream.write_all(&response).await?;
    Ok(())
}

struct Socks5UdpDatagram {
    target: Socks5UdpTarget,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Socks5UdpTarget {
    Ip(SocketAddr),
    Domain { domain: String, port: u16 },
}

fn decode_socks5_udp_datagram(datagram: &[u8]) -> Result<Socks5UdpDatagram, ClientError> {
    if datagram.len() < 4 || datagram[0] != 0 || datagram[1] != 0 || datagram[2] != 0 {
        return Err(ClientError::InvalidSocks5Request);
    }
    let mut offset = 4;
    let target = match datagram[3] {
        0x01 => {
            if datagram.len() < offset + 4 + 2 {
                return Err(ClientError::InvalidSocks5Request);
            }
            let address = Ipv4Addr::new(
                datagram[offset],
                datagram[offset + 1],
                datagram[offset + 2],
                datagram[offset + 3],
            );
            offset += 4;
            let port = u16::from_be_bytes([datagram[offset], datagram[offset + 1]]);
            offset += 2;
            Socks5UdpTarget::Ip(SocketAddr::new(IpAddr::V4(address), port))
        }
        0x03 => {
            if datagram.len() <= offset {
                return Err(ClientError::InvalidSocks5Request);
            }
            let len = datagram[offset] as usize;
            offset += 1;
            if len == 0 || datagram.len() < offset + len + 2 {
                return Err(ClientError::InvalidSocks5Request);
            }
            let domain = std::str::from_utf8(&datagram[offset..offset + len])
                .map_err(|_| ClientError::InvalidSocks5Request)?
                .to_owned();
            offset += len;
            let port = u16::from_be_bytes([datagram[offset], datagram[offset + 1]]);
            offset += 2;
            Socks5UdpTarget::Domain { domain, port }
        }
        0x04 => {
            if datagram.len() < offset + 16 + 2 {
                return Err(ClientError::InvalidSocks5Request);
            }
            let mut address = [0_u8; 16];
            address.copy_from_slice(&datagram[offset..offset + 16]);
            offset += 16;
            let port = u16::from_be_bytes([datagram[offset], datagram[offset + 1]]);
            offset += 2;
            Socks5UdpTarget::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(address)), port))
        }
        _ => return Err(ClientError::InvalidSocks5Request),
    };
    Ok(Socks5UdpDatagram {
        target,
        payload: datagram[offset..].to_vec(),
    })
}

fn encode_socks5_udp_datagram(target: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, ClientError> {
    let mut encoded = Vec::with_capacity(3 + 1 + 16 + 2 + payload.len());
    encoded.extend_from_slice(&[0x00, 0x00, 0x00]);
    match target {
        SocketAddr::V4(addr) => {
            encoded.push(0x01);
            encoded.extend_from_slice(&addr.ip().octets());
            encoded.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            encoded.push(0x04);
            encoded.extend_from_slice(&addr.ip().octets());
            encoded.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

async fn read_network_port(stream: &mut tokio::net::TcpStream) -> Result<u16, ClientError> {
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(u16::from_be_bytes(port))
}

fn parse_tcp_forward_target(value: &str) -> Result<TcpForwardTarget, ClientError> {
    TcpForwardTarget::ip_or_domain(value)
}

fn parse_udp_forward_target(value: &str) -> Result<UdpForwardTarget, ClientError> {
    UdpForwardTarget::ip_or_domain(value)
}

fn split_domain_port(value: &str) -> Option<(&str, u16)> {
    let (domain, port) = value.rsplit_once(':')?;
    if domain.is_empty() || port.is_empty() || domain.starts_with('[') || domain.contains(':') {
        return None;
    }
    let port = port.parse().ok()?;
    Some((domain, port))
}

/// Bound local UDP forwarder.
#[derive(Debug)]
pub struct UdpForwarder {
    socket: Arc<tokio::net::UdpSocket>,
    remote_target: UdpForwardTarget,
    udp_idle_timeout: Duration,
    dialer: Arc<SharedQuicDialer>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum UdpForwardTarget {
    Ip(SocketAddr),
    Domain { domain: String, port: u16 },
}

impl UdpForwardTarget {
    fn ip_or_domain(value: &str) -> Result<Self, ClientError> {
        if let Ok(addr) = value.parse() {
            return Ok(Self::Ip(addr));
        }
        let (domain, port) =
            split_domain_port(value).ok_or_else(|| ClientError::InvalidForwardRemoteTarget {
                value: value.to_owned(),
            })?;
        Ok(Self::Domain {
            domain: domain.to_owned(),
            port,
        })
    }
}

struct UdpForwardAssociation {
    stream: UdpOverStream,
    last_used: Instant,
}

impl UdpForwarder {
    /// Returns the local UDP socket address.
    pub fn local_addr(&self) -> Result<SocketAddr, ClientError> {
        Ok(self.socket.local_addr()?)
    }

    /// Returns the idle timeout used for local UDP source associations.
    #[must_use]
    pub const fn udp_idle_timeout(&self) -> Duration {
        self.udp_idle_timeout
    }

    /// Overrides the UDP idle timeout for embedders and deterministic tests.
    #[must_use]
    pub fn with_udp_idle_timeout(mut self, udp_idle_timeout: Duration) -> Self {
        self.udp_idle_timeout = if udp_idle_timeout.is_zero() {
            DEFAULT_NAT_TIMEOUT
        } else {
            udp_idle_timeout
        };
        self
    }

    /// Relays one local UDP datagram to the configured remote target.
    pub async fn forward_one_datagram(self) -> Result<UdpForwardReport, ClientError> {
        self.forward_one_datagram_ref().await
    }

    /// Runs a UDP forward loop until the shutdown future resolves.
    pub async fn run_udp_forward_loop_until(
        self,
        shutdown: impl Future<Output = ()>,
    ) -> Result<UdpForwardLoopReport, ClientError> {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut report = UdpForwardLoopReport::default();
        let mut associations = HashMap::new();
        let mut cleanup = tokio::time::interval(udp_cleanup_period(self.udp_idle_timeout));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut payload = vec![0_u8; 65_535];

        loop {
            tokio::select! {
                () = &mut shutdown => {
                    finish_all_udp_associations(&mut associations)?;
                    return Ok(report);
                }
                _ = cleanup.tick() => {
                    finish_idle_udp_associations(&mut associations, self.udp_idle_timeout)?;
                }
                received = self.socket.recv_from(&mut payload) => {
                    let (received, local_peer) = received?;
                    let payload = payload[..received].to_vec();
                    finish_idle_udp_associations(&mut associations, self.udp_idle_timeout)?;
                    if !associations.contains_key(&local_peer) {
                        associations.insert(local_peer, self.open_udp_association().await?);
                    }
                    let association = associations
                        .get_mut(&local_peer)
                        .expect("UDP association was inserted");
                    let relay = self
                        .forward_payload_on_association(local_peer, &payload, association)
                        .await?;
                    report.received_datagrams += 1;
                    report.completed_udp_relays += 1;
                    report.bytes_from_client += relay.bytes_from_client;
                    report.bytes_from_target += relay.bytes_from_target;
                }
            }
        }
    }

    async fn forward_one_datagram_ref(&self) -> Result<UdpForwardReport, ClientError> {
        let mut payload = vec![0_u8; 65_535];
        let (received, local_peer) = self.socket.recv_from(&mut payload).await?;
        payload.truncate(received);

        let mut association = self.open_udp_association().await?;
        let report = self
            .forward_payload_on_association(local_peer, &payload, &mut association)
            .await?;
        association.stream.finish()?;
        Ok(report)
    }

    async fn open_udp_association(&self) -> Result<UdpForwardAssociation, ClientError> {
        let stream = self.open_udp_stream_with_reconnect().await?;
        Ok(UdpForwardAssociation {
            stream,
            last_used: Instant::now(),
        })
    }

    /// Opens a UDP-over-stream over the shared connection, redialing once if the
    /// cached connection has died (idle close, server restart, migration).
    async fn open_udp_stream_with_reconnect(&self) -> Result<UdpOverStream, ClientError> {
        let connection = self.dialer.get_connection().await?;
        match self.open_udp_stream(&connection).await {
            Ok(stream) => Ok(stream),
            Err(error) => {
                self.dialer.invalidate().await;
                let connection = self.dialer.get_connection().await?;
                self.open_udp_stream(&connection).await.map_err(|_| error)
            }
        }
    }

    async fn open_udp_stream(
        &self,
        connection: &zuicity_transport::AuthenticatedConnection,
    ) -> Result<UdpOverStream, ClientError> {
        let stream = match &self.remote_target {
            UdpForwardTarget::Ip(addr) => {
                connection
                    .open_udp_over_stream(addr.ip(), addr.port())
                    .await?
            }
            UdpForwardTarget::Domain { domain, port } => {
                connection
                    .open_udp_over_domain_stream(domain, *port)
                    .await?
            }
        };
        Ok(stream)
    }

    async fn forward_payload_on_association(
        &self,
        local_peer: SocketAddr,
        payload: &[u8],
        association: &mut UdpForwardAssociation,
    ) -> Result<UdpForwardReport, ClientError> {
        association.last_used = Instant::now();
        association.stream.send_datagram(payload).await?;
        let response = association.stream.recv_datagram(65_535).await?;
        self.socket.send_to(&response.payload, local_peer).await?;
        association.last_used = Instant::now();
        Ok(UdpForwardReport {
            local_peer,
            remote_target: response.target,
            bytes_from_client: payload.len() as u64,
            bytes_from_target: response.payload.len() as u64,
        })
    }
}

fn udp_cleanup_period(timeout: Duration) -> Duration {
    if timeout.is_zero() {
        Duration::from_millis(1)
    } else {
        timeout.min(Duration::from_secs(1))
    }
}

fn finish_idle_udp_associations(
    associations: &mut HashMap<SocketAddr, UdpForwardAssociation>,
    timeout: Duration,
) -> Result<(), ClientError> {
    if timeout.is_zero() {
        return Ok(());
    }
    let now = Instant::now();
    let expired = associations
        .iter()
        .filter_map(|(local_peer, association)| {
            (now.duration_since(association.last_used) >= timeout).then_some(*local_peer)
        })
        .collect::<Vec<_>>();
    for local_peer in expired {
        if let Some(mut association) = associations.remove(&local_peer) {
            association.stream.finish()?;
        }
    }
    Ok(())
}

fn finish_all_udp_associations(
    associations: &mut HashMap<SocketAddr, UdpForwardAssociation>,
) -> Result<(), ClientError> {
    for (_, mut association) in associations.drain() {
        association.stream.finish()?;
    }
    Ok(())
}

fn record_mixed_tcp_relay(report: &mut MixedTcpLoopReport, relay: MixedTcpReport) {
    report.completed_tcp_relays += 1;
    report.bytes_from_client += relay.bytes_from_client;
    report.bytes_from_target += relay.bytes_from_target;
}

fn record_mixed_udp_relay(report: &mut MixedTcpLoopReport, relay: Socks5UdpAssociateReport) {
    report.completed_udp_associations += 1;
    report.bytes_from_client += relay.bytes_from_client;
    report.bytes_from_target += relay.bytes_from_target;
}

fn record_mixed_tcp_relay_error(report: &mut MixedTcpLoopReport, error: ClientError) {
    report.failed_tcp_relays += 1;
    tracing::warn!(error = %error, "mixed listener TCP relay failed");
}

fn record_mixed_udp_relay_error(report: &mut MixedTcpLoopReport, error: ClientError) {
    report.failed_udp_associations += 1;
    tracing::warn!(error = %error, "mixed listener SOCKS5 UDP association failed");
}

async fn drain_completed_mixed_relays_after_shutdown(
    tcp_relays: &mut tokio::task::JoinSet<Result<MixedTcpReport, ClientError>>,
    udp_relays: &mut tokio::task::JoinSet<Result<Socks5UdpAssociateReport, ClientError>>,
    report: &mut MixedTcpLoopReport,
) {
    drain_gracefully_completed_mixed_tcp_relays(tcp_relays, report).await;
    drain_gracefully_completed_mixed_udp_relays(udp_relays, report).await;
    tcp_relays.abort_all();
    udp_relays.abort_all();
    while let Some(completed) = tcp_relays.join_next().await {
        match completed {
            Ok(Ok(relay)) => record_mixed_tcp_relay(report, relay),
            Ok(Err(error)) => record_mixed_tcp_relay_error(report, error),
            Err(_) => {}
        }
    }
    while let Some(completed) = udp_relays.join_next().await {
        match completed {
            Ok(Ok(relay)) => record_mixed_udp_relay(report, relay),
            Ok(Err(error)) => record_mixed_udp_relay_error(report, error),
            Err(_) => {}
        }
    }
}

async fn drain_gracefully_completed_mixed_tcp_relays(
    tcp_relays: &mut tokio::task::JoinSet<Result<MixedTcpReport, ClientError>>,
    report: &mut MixedTcpLoopReport,
) {
    while !tcp_relays.is_empty() {
        match tokio::time::timeout(MIXED_SHUTDOWN_RELAY_DRAIN_GRACE, tcp_relays.join_next()).await {
            Ok(Some(Ok(Ok(relay)))) => record_mixed_tcp_relay(report, relay),
            Ok(Some(Ok(Err(error)))) => record_mixed_tcp_relay_error(report, error),
            Ok(Some(Err(_))) => {}
            Ok(None) | Err(_) => break,
        }
    }
}

async fn drain_gracefully_completed_mixed_udp_relays(
    udp_relays: &mut tokio::task::JoinSet<Result<Socks5UdpAssociateReport, ClientError>>,
    report: &mut MixedTcpLoopReport,
) {
    while !udp_relays.is_empty() {
        match tokio::time::timeout(MIXED_SHUTDOWN_RELAY_DRAIN_GRACE, udp_relays.join_next()).await {
            Ok(Some(Ok(Ok(relay)))) => record_mixed_udp_relay(report, relay),
            Ok(Some(Ok(Err(error)))) => record_mixed_udp_relay_error(report, error),
            Ok(Some(Err(_))) => {}
            Ok(None) | Err(_) => break,
        }
    }
}

/// Summary for a completed mixed-listener SOCKS5 UDP ASSOCIATE relay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5UdpAssociateReport {
    /// TCP control connection peer that created the UDP association.
    pub control_peer: SocketAddr,
    /// UDP client peer that sent the relayed datagram.
    pub udp_peer: SocketAddr,
    /// Remote UDP target returned by the Juicity UDP-over-stream relay.
    pub remote_target: SocketAddr,
    /// Bytes copied from local SOCKS5 UDP client to remote target.
    pub bytes_from_client: u64,
    /// Bytes copied from remote target back to local SOCKS5 UDP client.
    pub bytes_from_target: u64,
}

/// Summary for a completed mixed-listener TCP relay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixedTcpReport {
    /// Protocol selected by the upstream-compatible first-byte dispatch rule.
    pub protocol: MixedProtocol,
    /// Local client socket address.
    pub local_peer: SocketAddr,
    /// Remote target requested through HTTP CONNECT or SOCKS5 CONNECT.
    pub remote_target: TcpForwardTarget,
    /// Bytes copied from local TCP client to remote target after proxy negotiation.
    pub bytes_from_client: u64,
    /// Bytes copied from remote target back to local TCP client.
    pub bytes_from_target: u64,
}

impl MixedTcpReport {
    fn from_tcp_report(protocol: MixedProtocol, report: TcpForwardReport) -> Self {
        Self {
            protocol,
            local_peer: report.local_peer,
            remote_target: report.remote_target,
            bytes_from_client: report.bytes_from_client,
            bytes_from_target: report.bytes_from_target,
        }
    }
}

/// Aggregate report for a mixed-listener TCP accept loop.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MixedTcpLoopReport {
    /// Local mixed TCP connections accepted by the loop.
    pub accepted_connections: u64,
    /// Mixed TCP relays completed by the loop.
    pub completed_tcp_relays: u64,
    /// Mixed TCP relay attempts that failed without stopping the loop.
    pub failed_tcp_relays: u64,
    /// SOCKS5 UDP ASSOCIATE relays completed by the loop.
    pub completed_udp_associations: u64,
    /// SOCKS5 UDP ASSOCIATE relay attempts that failed without stopping the loop.
    pub failed_udp_associations: u64,
    /// Bytes copied from local clients to remote targets after proxy negotiation.
    pub bytes_from_client: u64,
    /// Bytes copied from remote targets back to local clients.
    pub bytes_from_target: u64,
}

/// Summary for a completed local UDP forward.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpForwardReport {
    /// Local UDP client socket address.
    pub local_peer: SocketAddr,
    /// Remote target encoded into the Juicity UDP-over-stream frame.
    pub remote_target: SocketAddr,
    /// Bytes copied from local UDP client to remote target.
    pub bytes_from_client: u64,
    /// Bytes copied from remote target back to local UDP client.
    pub bytes_from_target: u64,
}

/// Aggregate report for a local UDP forward loop.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UdpForwardLoopReport {
    /// Local UDP datagrams received by the loop.
    pub received_datagrams: u64,
    /// UDP-over-stream relays completed by the loop.
    pub completed_udp_relays: u64,
    /// Bytes copied from local UDP clients to remote targets.
    pub bytes_from_client: u64,
    /// Bytes copied from remote targets back to local UDP clients.
    pub bytes_from_target: u64,
}

/// Summary for a completed local TCP forward.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpForwardReport {
    /// Local client socket address.
    pub local_peer: SocketAddr,
    /// Remote target encoded into the Juicity TCP proxy stream.
    pub remote_target: TcpForwardTarget,
    /// Bytes copied from local TCP client to remote target.
    pub bytes_from_client: u64,
    /// Bytes copied from remote target back to local TCP client.
    pub bytes_from_target: u64,
}

/// Aggregate report for a local TCP forward loop.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpForwardLoopReport {
    /// Local TCP connections accepted by the loop.
    pub accepted_connections: u64,
    /// TCP proxy relays completed by the loop.
    pub completed_tcp_relays: u64,
    /// Bytes copied from local TCP clients to remote targets.
    pub bytes_from_client: u64,
    /// Bytes copied from remote targets back to local TCP clients.
    pub bytes_from_target: u64,
}

fn parse_client_server_addr(value: &str) -> Result<SocketAddr, ClientError> {
    Ok(value.parse()?)
}

/// Returns the local UDP bind address for the QUIC dialer that reaches `server`.
///
/// The dialer must bind an unspecified address of the server's family
/// (`0.0.0.0` / `[::]`), not loopback. A loopback-bound socket cannot send to a
/// non-loopback server and fails with EINVAL, which breaks every non-loopback
/// (real cross-host) deployment.
fn client_dialer_bind_addr(server: SocketAddr) -> SocketAddr {
    if server.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0_u16; 8], 0))
    }
}

/// Client runtime errors.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Config parsing or validation failed.
    #[error(transparent)]
    Config(#[from] zuicity_config::ConfigError),
    /// Transport failed.
    #[error(transparent)]
    Transport(#[from] zuicity_transport::TransportError),
    /// Server address failed to parse.
    #[error("parse server socket address: {0}")]
    ServerAddr(#[from] std::net::AddrParseError),
    /// Mixed listener address failed to parse.
    #[error("parse mixed listen socket address {value:?}: {source}")]
    InvalidMixedListenAddr {
        /// Invalid listen address value.
        value: String,
        /// Parse failure.
        source: std::net::AddrParseError,
    },
    /// HTTP CONNECT request was malformed or unsupported.
    #[error("invalid HTTP CONNECT request")]
    InvalidHttpConnectRequest,
    /// SOCKS5 request was malformed or unsupported.
    #[error("invalid SOCKS5 request")]
    InvalidSocks5Request,
    /// SOCKS5 authentication methods did not include no-auth.
    #[error("unsupported SOCKS5 authentication methods")]
    UnsupportedSocks5Auth,
    /// SOCKS5 command is not CONNECT.
    #[error("unsupported SOCKS5 command {0}")]
    UnsupportedSocks5Command(u8),
    /// Forward local address failed to parse.
    #[error("parse forward local socket address {value:?}: {source}")]
    InvalidForwardLocalAddr {
        /// Invalid local address value.
        value: String,
        /// Parse failure.
        source: std::net::AddrParseError,
    },
    /// Forward remote target failed to parse.
    #[error("parse forward remote socket address {value:?}: {source}")]
    InvalidForwardRemoteAddr {
        /// Invalid remote address value.
        value: String,
        /// Parse failure.
        source: std::net::AddrParseError,
    },
    /// TCP forward remote target lacked a valid host:port shape.
    #[error("parse TCP forward remote target {value:?}")]
    InvalidForwardRemoteTarget {
        /// Invalid remote target value.
        value: String,
    },
    /// Local TCP I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Test server runtime failed.
    #[cfg(test)]
    #[error(transparent)]
    Server(#[from] zuicity_server::ServerError),
    /// Join failed while waiting for a runtime task.
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_dialer_binds_unspecified_address_of_server_family() {
        let v4 = client_dialer_bind_addr("10.200.0.1:9443".parse().unwrap());
        assert!(v4.ip().is_unspecified());
        assert!(v4.is_ipv4());
        assert_eq!(v4.port(), 0);

        let v6 = client_dialer_bind_addr("[2001:db8::1]:9443".parse().unwrap());
        assert!(v6.ip().is_unspecified());
        assert!(v6.is_ipv6());
        assert_eq!(v6.port(), 0);

        let loopback = client_dialer_bind_addr("127.0.0.1:9443".parse().unwrap());
        assert!(loopback.ip().is_unspecified());
    }

    fn client_config(json: &str) -> Result<ClientRuntimeConfig, zuicity_config::ConfigError> {
        Ok(ClientRuntimeConfig {
            config: zuicity_config::validate_client(zuicity_config::load_json_str(json)?)?,
            tls: zuicity_transport::TlsPolicy::upstream(),
            streams: zuicity_transport::StreamPolicy::upstream(),
        })
    }

    fn server_config(
        json: &str,
    ) -> Result<zuicity_server::ServerRuntimeConfig, zuicity_config::ConfigError> {
        Ok(zuicity_server::ServerRuntimeConfig::from_config(
            zuicity_config::validate_server(zuicity_config::load_json_str(json)?)?,
        ))
    }

    #[tokio::test]
    async fn client_tcp_forwarder_reaches_remote_echo_through_rust_server()
    -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "client forward password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
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
                .run_tcp_proxy_loop_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let forwarder = runtime
            .bind_tcp_forwarder_with_roots(
                ([127, 0, 0, 1], 0).into(),
                echo_addr,
                cert.cert.pem().as_bytes(),
            )
            .await?;
        let local_addr = forwarder.local_addr()?;
        let forward_task = tokio::spawn(async move { forwarder.accept_one().await });

        let mut stream = tokio::net::TcpStream::connect(local_addr).await?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(b"client forward tcp").await?;
        stream.shutdown().await?;
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await?;
        assert_eq!(echoed, b"client forward tcp");

        let report = forward_task.await??;
        assert_eq!(report.remote_target, TcpForwardTarget::Ip(echo_addr));
        assert_eq!(report.bytes_from_client, b"client forward tcp".len() as u64);
        assert_eq!(report.bytes_from_target, b"client forward tcp".len() as u64);
        shutdown_tx.send(()).expect("send server shutdown");
        let server_report = server_task.await??;
        assert_eq!(server_report.completed_tcp_relays, 1);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn client_tcp_forwarder_streams_delayed_chunks_through_rust_server()
    -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "client forward streaming password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
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
                .run_tcp_proxy_loop_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let forwarder = runtime
            .bind_tcp_forwarder_with_roots(
                ([127, 0, 0, 1], 0).into(),
                echo_addr,
                cert.cert.pem().as_bytes(),
            )
            .await?;
        let local_addr = forwarder.local_addr()?;
        let forward_task = tokio::spawn(async move { forwarder.accept_one().await });

        let mut stream = tokio::net::TcpStream::connect(local_addr).await?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(b"chunk-one-").await?;
        tokio::time::sleep(std::time::Duration::from_millis(750)).await;
        stream.write_all(b"chunk-two").await?;
        stream.shutdown().await?;
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await?;
        assert_eq!(echoed, b"chunk-one-chunk-two");

        let report = forward_task.await??;
        assert_eq!(report.remote_target, TcpForwardTarget::Ip(echo_addr));
        assert_eq!(
            report.bytes_from_client,
            b"chunk-one-chunk-two".len() as u64
        );
        assert_eq!(
            report.bytes_from_target,
            b"chunk-one-chunk-two".len() as u64
        );
        shutdown_tx.send(()).expect("send server shutdown");
        let server_report = server_task.await??;
        assert_eq!(server_report.completed_tcp_relays, 1);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn client_tcp_forward_loop_reuses_one_quic_connection_across_relays()
    -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "client forward loop password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let server_runtime = zuicity_server::ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let server = server_runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            server
                .run_proxy_loop_until(async {
                    let _ = server_shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let forwarder = runtime
            .bind_tcp_forwarder_with_roots(
                ([127, 0, 0, 1], 0).into(),
                echo_addr,
                cert.cert.pem().as_bytes(),
            )
            .await?;
        let local_addr = forwarder.local_addr()?;
        let (forward_shutdown_tx, forward_shutdown_rx) = tokio::sync::oneshot::channel();
        let forward_task = tokio::spawn(async move {
            forwarder
                .run_tcp_forward_loop_until(async {
                    let _ = forward_shutdown_rx.await;
                })
                .await
        });

        async fn roundtrip(
            addr: std::net::SocketAddr,
            payload: &'static [u8],
        ) -> Result<Vec<u8>, ClientError> {
            let mut stream = tokio::net::TcpStream::connect(addr).await?;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            stream.write_all(payload).await?;
            stream.shutdown().await?;
            let mut echoed = Vec::new();
            stream.read_to_end(&mut echoed).await?;
            Ok(echoed)
        }

        for payload in [b"loop-one".as_slice(), b"loop-two", b"loop-three"] {
            assert_eq!(roundtrip(local_addr, payload).await?, payload);
        }
        forward_shutdown_tx
            .send(())
            .expect("send forwarder shutdown");
        let forward_report = forward_task.await??;
        assert_eq!(forward_report.accepted_connections, 3);
        assert_eq!(forward_report.completed_tcp_relays, 3);
        assert_eq!(
            forward_report.bytes_from_client,
            b"loop-oneloop-twoloop-three".len() as u64
        );
        assert_eq!(
            forward_report.bytes_from_target,
            b"loop-oneloop-twoloop-three".len() as u64
        );

        server_shutdown_tx.send(()).expect("send server shutdown");
        let server_report = server_task.await??;
        assert_eq!(server_report.accepted_connections, 1);
        assert_eq!(server_report.completed_tcp_relays, 3);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn client_binds_tcp_forwarders_from_config_rules_and_skips_non_tcp()
    -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "client config forward password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
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
                .run_tcp_proxy_loop_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local","forward":{{"127.0.0.1:0/tcp":"{echo_addr}","127.0.0.1:0/udp":"{echo_addr}","127.0.0.1:0/quic":"{echo_addr}"}}}}"#
        ))?);
        let mut forwarders = runtime
            .bind_configured_tcp_forwarders_with_roots(cert.cert.pem().as_bytes())
            .await?;
        assert_eq!(forwarders.len(), 1);
        let forwarder = forwarders.pop().expect("one TCP forwarder");
        let local_addr = forwarder.local_addr()?;
        let forward_task = tokio::spawn(async move { forwarder.accept_one().await });

        let mut stream = tokio::net::TcpStream::connect(local_addr).await?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(b"config forward tcp").await?;
        stream.shutdown().await?;
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await?;
        assert_eq!(echoed, b"config forward tcp");

        let report = forward_task.await??;
        assert_eq!(report.remote_target, TcpForwardTarget::Ip(echo_addr));
        assert_eq!(report.bytes_from_client, b"config forward tcp".len() as u64);
        assert_eq!(report.bytes_from_target, b"config forward tcp".len() as u64);
        shutdown_tx.send(()).expect("send server shutdown");
        let server_report = server_task.await??;
        assert_eq!(server_report.completed_tcp_relays, 1);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn client_binds_tcp_forwarder_from_config_domain_remote() -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "client config domain forward password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
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
                .run_tcp_proxy_loop_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local","forward":{{"127.0.0.1:0/tcp":"localhost:{}"}}}}"#,
            echo_addr.port()
        ))?);
        let mut forwarders = runtime
            .bind_configured_tcp_forwarders_with_roots(cert.cert.pem().as_bytes())
            .await?;
        assert_eq!(forwarders.len(), 1);
        let forwarder = forwarders.pop().expect("one TCP forwarder");
        let local_addr = forwarder.local_addr()?;
        let forward_task = tokio::spawn(async move { forwarder.accept_one().await });

        let mut stream = tokio::net::TcpStream::connect(local_addr).await?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(b"config domain forward tcp").await?;
        stream.shutdown().await?;
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await?;
        assert_eq!(echoed, b"config domain forward tcp");

        let report = forward_task.await??;
        assert_eq!(
            report.remote_target.to_string(),
            format!("localhost:{}", echo_addr.port())
        );
        assert_eq!(
            report.bytes_from_client,
            b"config domain forward tcp".len() as u64
        );
        assert_eq!(
            report.bytes_from_target,
            b"config domain forward tcp".len() as u64
        );
        shutdown_tx.send(()).expect("send server shutdown");
        let server_report = server_task.await??;
        assert_eq!(server_report.completed_tcp_relays, 1);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn client_udp_forwarder_reaches_domain_remote_through_rust_server()
    -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "client udp domain forward password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
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
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local","forward":{{"127.0.0.1:0/udp":"localhost:{}"}}}}"#,
            echo_addr.port()
        ))?);
        let mut forwarders = runtime
            .bind_configured_udp_forwarders_with_roots(cert.cert.pem().as_bytes())
            .await?;
        assert_eq!(forwarders.len(), 1);
        let forwarder = forwarders.pop().expect("one UDP domain forwarder");
        let local_addr = forwarder.local_addr()?;
        let forward_task = tokio::spawn(async move { forwarder.forward_one_datagram().await });

        let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        socket
            .send_to(b"client udp domain forward", local_addr)
            .await?;
        let mut buf = [0_u8; 1024];
        let (received, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await
        .expect("receive UDP domain forward response within timeout")?;
        assert_eq!(from, local_addr);
        assert_eq!(&buf[..received], b"client udp domain forward");

        let report = forward_task.await??;
        assert_eq!(report.local_peer, socket.local_addr()?);
        assert_eq!(report.remote_target, echo_addr);
        assert_eq!(
            report.bytes_from_client,
            b"client udp domain forward".len() as u64
        );
        assert_eq!(
            report.bytes_from_target,
            b"client udp domain forward".len() as u64
        );
        let server_report = server_task.await??;
        assert_eq!(server_report.target, echo_addr);
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn client_udp_forwarder_reaches_remote_echo_through_rust_server()
    -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "client udp forward password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
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
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let forwarder = runtime
            .bind_udp_forwarder_with_roots(
                ([127, 0, 0, 1], 0).into(),
                echo_addr,
                cert.cert.pem().as_bytes(),
            )
            .await?;
        let local_addr = forwarder.local_addr()?;
        let forward_task = tokio::spawn(async move { forwarder.forward_one_datagram().await });

        let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        socket.send_to(b"client udp forward", local_addr).await?;
        let mut buf = [0_u8; 1024];
        let (received, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await
        .expect("receive UDP forward response within timeout")?;
        assert_eq!(from, local_addr);
        assert_eq!(&buf[..received], b"client udp forward");

        let report = forward_task.await??;
        assert_eq!(report.local_peer, socket.local_addr()?);
        assert_eq!(report.remote_target, echo_addr);
        assert_eq!(report.bytes_from_client, b"client udp forward".len() as u64);
        assert_eq!(report.bytes_from_target, b"client udp forward".len() as u64);
        let server_report = server_task.await??;
        assert_eq!(server_report.target, echo_addr);
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn client_binds_udp_forwarders_from_config_rules_and_skips_non_udp()
    -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "client config udp forward password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
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
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local","forward":{{"127.0.0.1:0/udp":"{echo_addr}","127.0.0.2:0/tcp":"{echo_addr}","127.0.0.3:0/quic":"{echo_addr}"}}}}"#
        ))?);
        let mut forwarders = runtime
            .bind_configured_udp_forwarders_with_roots(cert.cert.pem().as_bytes())
            .await?;
        assert_eq!(forwarders.len(), 1);
        let forwarder = forwarders.pop().expect("one UDP forwarder");
        let local_addr = forwarder.local_addr()?;
        let forward_task = tokio::spawn(async move { forwarder.forward_one_datagram().await });

        let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        socket.send_to(b"config udp forward", local_addr).await?;
        let mut buf = [0_u8; 1024];
        let (received, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await
        .expect("receive UDP config forward response within timeout")?;
        assert_eq!(from, local_addr);
        assert_eq!(&buf[..received], b"config udp forward");

        let report = forward_task.await??;
        assert_eq!(report.remote_target, echo_addr);
        assert_eq!(report.bytes_from_client, b"config udp forward".len() as u64);
        assert_eq!(report.bytes_from_target, b"config udp forward".len() as u64);
        let server_report = server_task.await??;
        assert_eq!(server_report.target, echo_addr);
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn client_udp_forward_loop_handles_multiple_datagrams_until_shutdown()
    -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "client udp loop password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
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
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let forwarder = runtime
            .bind_udp_forwarder_with_roots(
                ([127, 0, 0, 1], 0).into(),
                echo_addr,
                cert.cert.pem().as_bytes(),
            )
            .await?;
        let local_addr = forwarder.local_addr()?;
        let (forward_shutdown_tx, forward_shutdown_rx) = tokio::sync::oneshot::channel();
        let forward_task = tokio::spawn(async move {
            forwarder
                .run_udp_forward_loop_until(async {
                    let _ = forward_shutdown_rx.await;
                })
                .await
        });

        let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let mut expected_bytes = 0_u64;
        for payload in [
            b"first local udp".as_slice(),
            b"second local udp".as_slice(),
        ] {
            socket.send_to(payload, local_addr).await?;
            let mut buf = [0_u8; 1024];
            let (received, from) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                socket.recv_from(&mut buf),
            )
            .await
            .expect("receive UDP loop response within timeout")?;
            assert_eq!(from, local_addr);
            assert_eq!(&buf[..received], payload);
            expected_bytes += payload.len() as u64;
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        forward_shutdown_tx
            .send(())
            .expect("send UDP forwarder shutdown");
        let forward_report = forward_task.await??;
        assert_eq!(forward_report.received_datagrams, 2);
        assert_eq!(forward_report.completed_udp_relays, 2);
        assert_eq!(forward_report.bytes_from_client, expected_bytes);
        assert_eq!(forward_report.bytes_from_target, expected_bytes);

        let server_report = server_task.await??;
        assert_eq!(server_report.target, echo_addr);
        assert_eq!(server_report.bytes_from_client, expected_bytes);
        assert_eq!(server_report.bytes_from_target, expected_bytes);
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn client_udp_forward_loop_expires_idle_local_peer_association() -> Result<(), ClientError>
    {
        let uuid = uuid::Uuid::new_v4();
        let password = "client udp idle timeout password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let server_runtime = zuicity_server::ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let server = server_runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .run_udp_over_stream_loop_until(async {
                    let _ = server_shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let forwarder = runtime
            .bind_udp_forwarder_with_roots(
                ([127, 0, 0, 1], 0).into(),
                echo_addr,
                cert.cert.pem().as_bytes(),
            )
            .await?
            .with_udp_idle_timeout(Duration::from_millis(50));
        let local_addr = forwarder.local_addr()?;
        let (forward_shutdown_tx, forward_shutdown_rx) = tokio::sync::oneshot::channel();
        let forward_task = tokio::spawn(async move {
            forwarder
                .run_udp_forward_loop_until(async {
                    let _ = forward_shutdown_rx.await;
                })
                .await
        });

        let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let mut expected_bytes = 0_u64;
        for (payload, wait_after) in [
            (
                b"idle pooled udp one".as_slice(),
                Duration::from_millis(150),
            ),
            (b"idle pooled udp two".as_slice(), Duration::ZERO),
        ] {
            socket.send_to(payload, local_addr).await?;
            let mut buf = [0_u8; 1024];
            let (received, from) =
                tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
                    .await
                    .expect("receive UDP idle-timeout response within timeout")?;
            assert_eq!(from, local_addr);
            assert_eq!(&buf[..received], payload);
            expected_bytes += payload.len() as u64;
            if !wait_after.is_zero() {
                tokio::time::sleep(wait_after).await;
            }
        }

        forward_shutdown_tx
            .send(())
            .expect("send UDP forwarder shutdown");
        let forward_report = forward_task.await??;
        assert_eq!(forward_report.received_datagrams, 2);
        assert_eq!(forward_report.completed_udp_relays, 2);
        assert_eq!(forward_report.bytes_from_client, expected_bytes);
        assert_eq!(forward_report.bytes_from_target, expected_bytes);
        server_shutdown_tx
            .send(())
            .expect("send UDP idle-timeout server shutdown");

        let server_report = server_task.await??;
        // The idle association still expires at the UDP-over-stream level (two
        // separate relays complete), but the authenticated QUIC connection is
        // now reused across both datagrams instead of being torn down and
        // redialed, so the server accepts a single connection.
        assert_eq!(server_report.accepted_connections, 1);
        assert_eq!(server_report.completed_udp_relays, 2);
        assert_eq!(server_report.bytes_from_client, expected_bytes);
        assert_eq!(server_report.bytes_from_target, expected_bytes);
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn client_udp_forward_loop_reuses_one_quic_connection_across_peers()
    -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "client udp reuse password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let server_runtime = zuicity_server::ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let server = server_runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .run_proxy_loop_until(async {
                    let _ = server_shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let forwarder = runtime
            .bind_udp_forwarder_with_roots(
                ([127, 0, 0, 1], 0).into(),
                echo_addr,
                cert.cert.pem().as_bytes(),
            )
            .await?
            .with_udp_idle_timeout(Duration::from_millis(50));
        let local_addr = forwarder.local_addr()?;
        let (forward_shutdown_tx, forward_shutdown_rx) = tokio::sync::oneshot::channel();
        let forward_task = tokio::spawn(async move {
            forwarder
                .run_udp_forward_loop_until(async {
                    let _ = forward_shutdown_rx.await;
                })
                .await
        });

        let mut expected_bytes = 0_u64;
        for payload in [
            b"peer-one udp".as_slice(),
            b"peer-two udp",
            b"peer-three udp",
        ] {
            let peer = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
            peer.send_to(payload, local_addr).await?;
            let mut buf = [0_u8; 1024];
            let (received, from) =
                tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
                    .await
                    .expect("receive UDP reuse response within timeout")?;
            assert_eq!(from, local_addr);
            assert_eq!(&buf[..received], payload);
            expected_bytes += payload.len() as u64;
            tokio::time::sleep(Duration::from_millis(120)).await;
        }

        forward_shutdown_tx
            .send(())
            .expect("send UDP forwarder shutdown");
        let forward_report = forward_task.await??;
        assert_eq!(forward_report.received_datagrams, 3);
        assert_eq!(forward_report.completed_udp_relays, 3);
        assert_eq!(forward_report.bytes_from_client, expected_bytes);
        assert_eq!(forward_report.bytes_from_target, expected_bytes);

        server_shutdown_tx.send(()).expect("send server shutdown");
        let server_report = server_task.await??;
        assert_eq!(server_report.accepted_connections, 1);
        assert_eq!(server_report.completed_udp_relays, 3);
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn reused_connection_relays_many_concurrent_udp_streams_without_serializing()
    -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "client udp concurrent reuse password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let server_runtime = zuicity_server::ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let server = server_runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .run_proxy_loop_until(async {
                    let _ = server_shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let forwarder = runtime
            .bind_udp_forwarder_with_roots(
                ([127, 0, 0, 1], 0).into(),
                echo_addr,
                cert.cert.pem().as_bytes(),
            )
            .await?
            .with_udp_idle_timeout(Duration::from_secs(60));
        let local_addr = forwarder.local_addr()?;
        let (forward_shutdown_tx, forward_shutdown_rx) = tokio::sync::oneshot::channel();
        let forward_task = tokio::spawn(async move {
            forwarder
                .run_udp_forward_loop_until(async {
                    let _ = forward_shutdown_rx.await;
                })
                .await
        });

        let mut expected_bytes = 0_u64;
        for payload in [
            b"concurrent peer one".as_slice(),
            b"concurrent peer two",
            b"concurrent peer three",
        ] {
            let peer = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
            peer.send_to(payload, local_addr).await?;
            let mut buf = [0_u8; 1024];
            let (received, from) =
                tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
                    .await
                    .expect("receive concurrent UDP response before NAT timeout")?;
            assert_eq!(from, local_addr);
            assert_eq!(&buf[..received], payload);
            expected_bytes += payload.len() as u64;
        }

        forward_shutdown_tx
            .send(())
            .expect("send UDP forwarder shutdown");
        let forward_report = forward_task.await??;
        assert_eq!(forward_report.received_datagrams, 3);
        assert_eq!(forward_report.completed_udp_relays, 3);
        assert_eq!(forward_report.bytes_from_client, expected_bytes);
        assert_eq!(forward_report.bytes_from_target, expected_bytes);

        server_shutdown_tx.send(()).expect("send server shutdown");
        let server_report = server_task.await??;
        assert_eq!(server_report.accepted_connections, 1);
        assert_eq!(server_report.completed_udp_relays, 3);
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn mixed_http_connect_reaches_remote_echo_through_rust_server() -> Result<(), ClientError>
    {
        let uuid = uuid::Uuid::new_v4();
        let password = "mixed http connect password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let server_runtime = zuicity_server::ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let server = server_runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move { server.accept_one_tcp_proxy().await });

        let echo_addr = echo.local_addr();
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let listener = runtime
            .bind_mixed_listener_with_roots(([127, 0, 0, 1], 0).into(), cert.cert.pem().as_bytes())
            .await?;
        let local_addr = listener.local_addr()?;
        let listener_task = tokio::spawn(async move { listener.accept_one_tcp().await });

        let mut stream = tokio::net::TcpStream::connect(local_addr).await?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream
            .write_all(
                format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n").as_bytes(),
            )
            .await?;
        let mut response = Vec::new();
        let mut chunk = [0_u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut chunk).await?;
            response.push(chunk[0]);
        }
        assert_eq!(response, b"HTTP/1.1 200 Connection established\r\n\r\n");

        stream.write_all(b"mixed http connect tcp").await?;
        stream.shutdown().await?;
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await?;
        assert_eq!(echoed, b"mixed http connect tcp");

        let report = listener_task.await??;
        assert_eq!(report.protocol, MixedProtocol::Http);
        assert_eq!(report.remote_target, TcpForwardTarget::Ip(echo_addr));
        assert_eq!(
            report.bytes_from_client,
            b"mixed http connect tcp".len() as u64
        );
        assert_eq!(
            report.bytes_from_target,
            b"mixed http connect tcp".len() as u64
        );
        let server_report = server_task.await??;
        assert_eq!(server_report.target, echo_addr);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn mixed_socks5_connect_reaches_remote_echo_through_rust_server()
    -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "mixed socks5 connect password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let server_runtime = zuicity_server::ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let server = server_runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move { server.accept_one_tcp_proxy().await });

        let echo_addr = echo.local_addr();
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let listener = runtime
            .bind_mixed_listener_with_roots(([127, 0, 0, 1], 0).into(), cert.cert.pem().as_bytes())
            .await?;
        let local_addr = listener.local_addr()?;
        let listener_task = tokio::spawn(async move { listener.accept_one_tcp().await });

        let mut stream = tokio::net::TcpStream::connect(local_addr).await?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting_response = [0_u8; 2];
        stream.read_exact(&mut greeting_response).await?;
        assert_eq!(greeting_response, [0x05, 0x00]);

        let SocketAddr::V4(echo_v4) = echo_addr else {
            panic!("TCP echo fixture should bind IPv4 loopback")
        };
        let mut request = vec![0x05, 0x01, 0x00, 0x01];
        request.extend_from_slice(&echo_v4.ip().octets());
        request.extend_from_slice(&echo_v4.port().to_be_bytes());
        stream.write_all(&request).await?;
        let mut connect_response = [0_u8; 10];
        stream.read_exact(&mut connect_response).await?;
        assert_eq!(connect_response, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

        stream.write_all(b"mixed socks5 connect tcp").await?;
        stream.shutdown().await?;
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await?;
        assert_eq!(echoed, b"mixed socks5 connect tcp");

        let report = listener_task.await??;
        assert_eq!(report.protocol, MixedProtocol::Socks5);
        assert_eq!(report.remote_target, TcpForwardTarget::Ip(echo_addr));
        assert_eq!(
            report.bytes_from_client,
            b"mixed socks5 connect tcp".len() as u64
        );
        assert_eq!(
            report.bytes_from_target,
            b"mixed socks5 connect tcp".len() as u64
        );
        let server_report = server_task.await??;
        assert_eq!(server_report.target, echo_addr);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn mixed_socks5_udp_associate_reaches_remote_echo_through_rust_server()
    -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "mixed socks5 udp associate password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
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
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let listener = runtime
            .bind_mixed_listener_with_roots(([127, 0, 0, 1], 0).into(), cert.cert.pem().as_bytes())
            .await?;
        let local_addr = listener.local_addr()?;
        let listener_task =
            tokio::spawn(async move { listener.accept_one_socks5_udp_associate().await });

        let mut control = tokio::net::TcpStream::connect(local_addr).await?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        control.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting_response = [0_u8; 2];
        control.read_exact(&mut greeting_response).await?;
        assert_eq!(greeting_response, [0x05, 0x00]);

        control
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        let mut associate_response = [0_u8; 10];
        control.read_exact(&mut associate_response).await?;
        assert_eq!(&associate_response[..4], &[0x05, 0x00, 0x00, 0x01]);
        let associate_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                associate_response[4],
                associate_response[5],
                associate_response[6],
                associate_response[7],
            )),
            u16::from_be_bytes([associate_response[8], associate_response[9]]),
        );
        assert_eq!(associate_addr.port(), local_addr.port());

        let SocketAddr::V4(echo_v4) = echo_addr else {
            panic!("UDP echo fixture should bind IPv4 loopback")
        };
        let payload = b"mixed socks5 udp associate";
        let mut udp_request = vec![0x00, 0x00, 0x00, 0x01];
        udp_request.extend_from_slice(&echo_v4.ip().octets());
        udp_request.extend_from_slice(&echo_v4.port().to_be_bytes());
        udp_request.extend_from_slice(payload);

        let udp_client = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        udp_client.send_to(&udp_request, associate_addr).await?;
        let mut response = [0_u8; 1024];
        let (received, from) =
            tokio::time::timeout(Duration::from_secs(2), udp_client.recv_from(&mut response))
                .await
                .expect("receive SOCKS5 UDP associate response within timeout")?;
        assert_eq!(from, associate_addr);
        assert_eq!(&response[..4], &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(&response[4..8], &echo_v4.ip().octets());
        assert_eq!(
            u16::from_be_bytes([response[8], response[9]]),
            echo_v4.port()
        );
        assert_eq!(&response[10..received], payload);

        control.shutdown().await?;
        let report = listener_task.await??;
        assert_eq!(report.control_peer, control.local_addr()?);
        assert_eq!(report.udp_peer, udp_client.local_addr()?);
        assert_eq!(report.remote_target, echo_addr);
        assert_eq!(report.bytes_from_client, payload.len() as u64);
        assert_eq!(report.bytes_from_target, payload.len() as u64);
        let server_report = server_task.await??;
        assert_eq!(server_report.target, echo_addr);
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn mixed_socks5_udp_associate_relays_multiple_datagrams_on_one_association()
    -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "mixed socks5 udp multi datagram password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
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
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let listener = runtime
            .bind_mixed_listener_with_roots(([127, 0, 0, 1], 0).into(), cert.cert.pem().as_bytes())
            .await?;
        let local_addr = listener.local_addr()?;
        let listener_task =
            tokio::spawn(async move { listener.accept_one_socks5_udp_associate().await });

        let mut control = tokio::net::TcpStream::connect(local_addr).await?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        control.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting_response = [0_u8; 2];
        control.read_exact(&mut greeting_response).await?;
        assert_eq!(greeting_response, [0x05, 0x00]);
        control
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        let mut associate_response = [0_u8; 10];
        control.read_exact(&mut associate_response).await?;
        let associate_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                associate_response[4],
                associate_response[5],
                associate_response[6],
                associate_response[7],
            )),
            u16::from_be_bytes([associate_response[8], associate_response[9]]),
        );

        let SocketAddr::V4(echo_v4) = echo_addr else {
            panic!("UDP echo fixture should bind IPv4 loopback")
        };
        let udp_client = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let mut expected_bytes = 0_u64;
        for payload in [
            b"mixed socks5 udp multi one".as_slice(),
            b"mixed socks5 udp multi two".as_slice(),
        ] {
            let mut udp_request = vec![0x00, 0x00, 0x00, 0x01];
            udp_request.extend_from_slice(&echo_v4.ip().octets());
            udp_request.extend_from_slice(&echo_v4.port().to_be_bytes());
            udp_request.extend_from_slice(payload);
            udp_client.send_to(&udp_request, associate_addr).await?;
            let mut response = [0_u8; 1024];
            let (received, from) =
                tokio::time::timeout(Duration::from_secs(2), udp_client.recv_from(&mut response))
                    .await
                    .expect("receive multi-datagram SOCKS5 UDP response within timeout")?;
            assert_eq!(from, associate_addr);
            assert_eq!(&response[10..received], payload);
            expected_bytes += payload.len() as u64;
        }

        control.shutdown().await?;
        let report = listener_task.await??;
        assert_eq!(report.control_peer, control.local_addr()?);
        assert_eq!(report.udp_peer, udp_client.local_addr()?);
        assert_eq!(report.remote_target, echo_addr);
        assert_eq!(report.bytes_from_client, expected_bytes);
        assert_eq!(report.bytes_from_target, expected_bytes);
        let server_report = server_task.await??;
        assert_eq!(server_report.target, echo_addr);
        assert_eq!(server_report.bytes_from_client, expected_bytes);
        assert_eq!(server_report.bytes_from_target, expected_bytes);
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn mixed_run_loop_serves_concurrent_http_connect_clients() -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "mixed concurrent http connect password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let server_runtime = zuicity_server::ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let server = server_runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .run_proxy_loop_until(async {
                    let _ = server_shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let listener = runtime
            .bind_mixed_listener_with_roots(([127, 0, 0, 1], 0).into(), cert.cert.pem().as_bytes())
            .await?;
        let local_addr = listener.local_addr()?;
        let (listener_shutdown_tx, listener_shutdown_rx) = tokio::sync::oneshot::channel();
        let listener_task = tokio::spawn(async move {
            listener
                .run_loop_until(async {
                    let _ = listener_shutdown_rx.await;
                })
                .await
        });

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut first = tokio::net::TcpStream::connect(local_addr).await?;
        first
            .write_all(
                format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n").as_bytes(),
            )
            .await?;
        let mut first_response = Vec::new();
        let mut first_chunk = [0_u8; 1];
        tokio::time::timeout(Duration::from_secs(2), async {
            while !first_response.ends_with(b"\r\n\r\n") {
                first.read_exact(&mut first_chunk).await?;
                first_response.push(first_chunk[0]);
            }
            Ok::<_, std::io::Error>(())
        })
        .await
        .expect("first HTTP CONNECT response within timeout")?;
        assert_eq!(
            first_response,
            b"HTTP/1.1 200 Connection established\r\n\r\n"
        );
        let first_payload = b"mixed concurrent first stays open";
        first.write_all(first_payload).await?;
        let mut first_echo = vec![0_u8; first_payload.len()];
        tokio::time::timeout(Duration::from_secs(2), first.read_exact(&mut first_echo))
            .await
            .expect("first client echo while connection remains open")?;
        assert_eq!(&first_echo, first_payload);

        let mut second = tokio::net::TcpStream::connect(local_addr).await?;
        second
            .write_all(
                format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n").as_bytes(),
            )
            .await?;
        let mut second_response = Vec::new();
        let mut second_chunk = [0_u8; 1];
        tokio::time::timeout(Duration::from_secs(2), async {
            while !second_response.ends_with(b"\r\n\r\n") {
                second.read_exact(&mut second_chunk).await?;
                second_response.push(second_chunk[0]);
            }
            Ok::<_, std::io::Error>(())
        })
        .await
        .expect("second HTTP CONNECT response while first relay remains open")?;
        assert_eq!(
            second_response,
            b"HTTP/1.1 200 Connection established\r\n\r\n"
        );
        let second_payload = b"mixed concurrent second completes";
        second.write_all(second_payload).await?;
        second.shutdown().await?;
        let mut second_echo = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), second.read_to_end(&mut second_echo))
            .await
            .expect("second client echo within timeout")?;
        assert_eq!(second_echo, second_payload);

        first.shutdown().await?;
        let mut first_tail = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), first.read_to_end(&mut first_tail))
            .await
            .expect("first client closes after second completes")?;
        assert!(first_tail.is_empty());

        listener_shutdown_tx
            .send(())
            .expect("send mixed listener shutdown");
        let listener_report = listener_task.await??;
        let expected_bytes = (first_payload.len() + second_payload.len()) as u64;
        assert_eq!(listener_report.accepted_connections, 2);
        assert_eq!(listener_report.completed_tcp_relays, 2);
        assert_eq!(listener_report.completed_udp_associations, 0);
        assert_eq!(listener_report.bytes_from_client, expected_bytes);
        assert_eq!(listener_report.bytes_from_target, expected_bytes);

        server_shutdown_tx
            .send(())
            .expect("send TCP proxy server shutdown");
        let server_report = server_task.await??;
        // Both concurrent HTTP CONNECT clients now multiplex over one shared,
        // reused authenticated QUIC connection, so the server accepts a single
        // connection serving two TCP proxy relays.
        assert_eq!(server_report.accepted_connections, 1);
        assert_eq!(server_report.completed_tcp_relays, 2);
        assert_eq!(server_report.bytes_from_client, expected_bytes);
        assert_eq!(server_report.bytes_from_target, expected_bytes);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn mixed_run_loop_shutdown_closes_active_http_connect_relay() -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "mixed active http shutdown password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let server_runtime = zuicity_server::ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let server = server_runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .run_proxy_loop_until(async {
                    let _ = server_shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let listener = runtime
            .bind_mixed_listener_with_roots(([127, 0, 0, 1], 0).into(), cert.cert.pem().as_bytes())
            .await?;
        let local_addr = listener.local_addr()?;
        let (listener_shutdown_tx, listener_shutdown_rx) = tokio::sync::oneshot::channel();
        let listener_task = tokio::spawn(async move {
            listener
                .run_loop_until(async {
                    let _ = listener_shutdown_rx.await;
                })
                .await
        });

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(local_addr).await?;
        stream
            .write_all(
                format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n").as_bytes(),
            )
            .await?;
        let mut response = Vec::new();
        let mut chunk = [0_u8; 1];
        tokio::time::timeout(Duration::from_secs(2), async {
            while !response.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut chunk).await?;
                response.push(chunk[0]);
            }
            Ok::<_, std::io::Error>(())
        })
        .await
        .expect("HTTP CONNECT response before shutdown")?;
        assert_eq!(response, b"HTTP/1.1 200 Connection established\r\n\r\n");

        let payload = b"mixed active http shutdown remains open";
        stream.write_all(payload).await?;
        let mut echoed = vec![0_u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echoed))
            .await
            .expect("active HTTP CONNECT echo before shutdown")?;
        assert_eq!(&echoed, payload);
        assert!(
            !listener_task.is_finished(),
            "active HTTP CONNECT relay unexpectedly completed before shutdown"
        );

        listener_shutdown_tx
            .send(())
            .expect("send mixed listener shutdown");
        let listener_report = tokio::time::timeout(Duration::from_secs(2), listener_task)
            .await
            .expect("mixed listener returns promptly while HTTP CONNECT relay is active")??;
        assert_eq!(listener_report.accepted_connections, 1);
        assert_eq!(listener_report.completed_tcp_relays, 0);
        assert_eq!(listener_report.completed_udp_associations, 0);

        let mut after_shutdown = [0_u8; 1];
        let close_result =
            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut after_shutdown))
                .await
                .expect("active HTTP CONNECT client observes listener shutdown");
        assert!(
            matches!(close_result, Ok(0) | Err(_)),
            "active HTTP CONNECT client remained readable after listener shutdown"
        );

        server_shutdown_tx
            .send(())
            .expect("send TCP proxy server shutdown");
        let server_report = tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("server loop returns promptly after mixed listener shutdown")??;
        assert_eq!(server_report.accepted_connections, 1);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn mixed_run_loop_shutdown_closes_active_socks5_connect_relay() -> Result<(), ClientError>
    {
        let uuid = uuid::Uuid::new_v4();
        let password = "mixed active socks5 shutdown password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let server_runtime = zuicity_server::ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let server = server_runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .run_proxy_loop_until(async {
                    let _ = server_shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let listener = runtime
            .bind_mixed_listener_with_roots(([127, 0, 0, 1], 0).into(), cert.cert.pem().as_bytes())
            .await?;
        let local_addr = listener.local_addr()?;
        let (listener_shutdown_tx, listener_shutdown_rx) = tokio::sync::oneshot::channel();
        let listener_task = tokio::spawn(async move {
            listener
                .run_loop_until(async {
                    let _ = listener_shutdown_rx.await;
                })
                .await
        });

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(local_addr).await?;
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting_response = [0_u8; 2];
        tokio::time::timeout(
            Duration::from_secs(2),
            stream.read_exact(&mut greeting_response),
        )
        .await
        .expect("SOCKS5 greeting response before shutdown")?;
        assert_eq!(greeting_response, [0x05, 0x00]);

        let SocketAddr::V4(echo_v4) = echo_addr else {
            panic!("TCP echo fixture should bind IPv4 loopback")
        };
        let mut request = vec![0x05, 0x01, 0x00, 0x01];
        request.extend_from_slice(&echo_v4.ip().octets());
        request.extend_from_slice(&echo_v4.port().to_be_bytes());
        stream.write_all(&request).await?;
        let mut connect_response = [0_u8; 10];
        tokio::time::timeout(
            Duration::from_secs(2),
            stream.read_exact(&mut connect_response),
        )
        .await
        .expect("SOCKS5 CONNECT response before shutdown")?;
        assert_eq!(connect_response, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

        let payload = b"mixed active socks5 shutdown remains open";
        stream.write_all(payload).await?;
        let mut echoed = vec![0_u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echoed))
            .await
            .expect("active SOCKS5 CONNECT echo before shutdown")?;
        assert_eq!(&echoed, payload);
        assert!(
            !listener_task.is_finished(),
            "active SOCKS5 CONNECT relay unexpectedly completed before shutdown"
        );

        listener_shutdown_tx
            .send(())
            .expect("send mixed listener shutdown");
        let listener_report = tokio::time::timeout(Duration::from_secs(2), listener_task)
            .await
            .expect("mixed listener returns promptly while SOCKS5 CONNECT relay is active")??;
        assert_eq!(listener_report.accepted_connections, 1);
        assert_eq!(listener_report.completed_tcp_relays, 0);
        assert_eq!(listener_report.completed_udp_associations, 0);

        let mut after_shutdown = [0_u8; 1];
        let close_result =
            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut after_shutdown))
                .await
                .expect("active SOCKS5 CONNECT client observes listener shutdown");
        assert!(
            matches!(close_result, Ok(0) | Err(_)),
            "active SOCKS5 CONNECT client remained readable after listener shutdown"
        );

        server_shutdown_tx
            .send(())
            .expect("send TCP proxy server shutdown");
        let server_report = tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("server loop returns promptly after mixed listener shutdown")??;
        assert_eq!(server_report.accepted_connections, 1);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn mixed_run_loop_isolates_malformed_socks5_and_accepts_next_http_connect()
    -> Result<(), ClientError> {
        let uuid = uuid::Uuid::new_v4();
        let password = "mixed malformed socks5 isolation password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let server_runtime = zuicity_server::ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let server = server_runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .run_proxy_loop_until(async {
                    let _ = server_shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let listener = runtime
            .bind_mixed_listener_with_roots(([127, 0, 0, 1], 0).into(), cert.cert.pem().as_bytes())
            .await?;
        let local_addr = listener.local_addr()?;
        let (listener_shutdown_tx, listener_shutdown_rx) = tokio::sync::oneshot::channel();
        let listener_task = tokio::spawn(async move {
            listener
                .run_loop_until(async {
                    let _ = listener_shutdown_rx.await;
                })
                .await
        });

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut malformed = tokio::net::TcpStream::connect(local_addr).await?;
        malformed.write_all(&[0x05, 0x01, 0x02]).await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !listener_task.is_finished(),
            "malformed SOCKS5 negotiation stopped the mixed listener"
        );
        drop(malformed);

        let mut stream = tokio::net::TcpStream::connect(local_addr).await?;
        stream
            .write_all(
                format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n").as_bytes(),
            )
            .await?;
        let mut response = Vec::new();
        let mut chunk = [0_u8; 1];
        tokio::time::timeout(Duration::from_secs(2), async {
            while !response.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut chunk).await?;
                response.push(chunk[0]);
            }
            Ok::<_, std::io::Error>(())
        })
        .await
        .expect("HTTP CONNECT response after malformed SOCKS5 client")?;
        assert_eq!(response, b"HTTP/1.1 200 Connection established\r\n\r\n");

        let payload = b"mixed malformed socks5 isolation";
        stream.write_all(payload).await?;
        stream.shutdown().await?;
        let mut echoed = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut echoed))
            .await
            .expect("HTTP CONNECT echo after malformed SOCKS5 client")?;
        assert_eq!(echoed, payload);

        listener_shutdown_tx
            .send(())
            .expect("send mixed listener shutdown");
        let listener_report = listener_task.await??;
        assert_eq!(listener_report.accepted_connections, 2);
        assert_eq!(listener_report.completed_tcp_relays, 1);
        assert_eq!(listener_report.failed_tcp_relays, 1);
        assert_eq!(listener_report.completed_udp_associations, 0);
        assert_eq!(listener_report.failed_udp_associations, 0);
        assert_eq!(listener_report.bytes_from_client, payload.len() as u64);
        assert_eq!(listener_report.bytes_from_target, payload.len() as u64);

        server_shutdown_tx
            .send(())
            .expect("send TCP proxy server shutdown");
        let server_report = server_task.await??;
        assert_eq!(server_report.accepted_connections, 1);
        assert_eq!(server_report.completed_tcp_relays, 1);
        assert_eq!(server_report.bytes_from_client, payload.len() as u64);
        assert_eq!(server_report.bytes_from_target, payload.len() as u64);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn mixed_run_loop_serves_socks5_udp_associate_until_shutdown() -> Result<(), ClientError>
    {
        let uuid = uuid::Uuid::new_v4();
        let password = "mixed run loop socks5 udp associate password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
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
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let listener = runtime
            .bind_mixed_listener_with_roots(([127, 0, 0, 1], 0).into(), cert.cert.pem().as_bytes())
            .await?;
        let local_addr = listener.local_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let listener_task = tokio::spawn(async move {
            listener
                .run_loop_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let mut control = tokio::net::TcpStream::connect(local_addr).await?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        control.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting_response = [0_u8; 2];
        control.read_exact(&mut greeting_response).await?;
        assert_eq!(greeting_response, [0x05, 0x00]);
        control
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        let mut associate_response = [0_u8; 10];
        control.read_exact(&mut associate_response).await?;
        let associate_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                associate_response[4],
                associate_response[5],
                associate_response[6],
                associate_response[7],
            )),
            u16::from_be_bytes([associate_response[8], associate_response[9]]),
        );

        let SocketAddr::V4(echo_v4) = echo_addr else {
            panic!("UDP echo fixture should bind IPv4 loopback")
        };
        let payload = b"mixed run loop socks5 udp";
        let mut udp_request = vec![0x00, 0x00, 0x00, 0x01];
        udp_request.extend_from_slice(&echo_v4.ip().octets());
        udp_request.extend_from_slice(&echo_v4.port().to_be_bytes());
        udp_request.extend_from_slice(payload);
        let udp_client = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        udp_client.send_to(&udp_request, associate_addr).await?;
        let mut response = [0_u8; 1024];
        let (received, from) =
            tokio::time::timeout(Duration::from_secs(2), udp_client.recv_from(&mut response))
                .await
                .expect("receive mixed run-loop SOCKS5 UDP response within timeout")?;
        assert_eq!(from, associate_addr);
        assert_eq!(&response[10..received], payload);

        control.shutdown().await?;
        shutdown_tx.send(()).expect("send mixed listener shutdown");
        let report = listener_task.await??;
        assert_eq!(report.accepted_connections, 1);
        assert_eq!(report.completed_tcp_relays, 0);
        assert_eq!(report.completed_udp_associations, 1);
        assert_eq!(report.bytes_from_client, payload.len() as u64);
        assert_eq!(report.bytes_from_target, payload.len() as u64);
        let server_report = server_task.await??;
        assert_eq!(server_report.target, echo_addr);
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn mixed_run_loop_shutdown_closes_active_socks5_udp_associate() -> Result<(), ClientError>
    {
        let uuid = uuid::Uuid::new_v4();
        let password = "mixed active socks5 udp shutdown password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let server_runtime = zuicity_server::ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let server = server_runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .run_udp_over_stream_loop_until(async {
                    let _ = server_shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let listener = runtime
            .bind_mixed_listener_with_roots(([127, 0, 0, 1], 0).into(), cert.cert.pem().as_bytes())
            .await?;
        let local_addr = listener.local_addr()?;
        let (listener_shutdown_tx, listener_shutdown_rx) = tokio::sync::oneshot::channel();
        let listener_task = tokio::spawn(async move {
            listener
                .run_loop_until(async {
                    let _ = listener_shutdown_rx.await;
                })
                .await
        });

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut control = tokio::net::TcpStream::connect(local_addr).await?;
        control.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting_response = [0_u8; 2];
        tokio::time::timeout(
            Duration::from_secs(2),
            control.read_exact(&mut greeting_response),
        )
        .await
        .expect("SOCKS5 greeting response before shutdown")?;
        assert_eq!(greeting_response, [0x05, 0x00]);
        control
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        let mut associate_response = [0_u8; 10];
        tokio::time::timeout(
            Duration::from_secs(2),
            control.read_exact(&mut associate_response),
        )
        .await
        .expect("SOCKS5 UDP ASSOCIATE response before shutdown")?;
        assert_eq!(&associate_response[..4], &[0x05, 0x00, 0x00, 0x01]);
        let associate_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                associate_response[4],
                associate_response[5],
                associate_response[6],
                associate_response[7],
            )),
            u16::from_be_bytes([associate_response[8], associate_response[9]]),
        );
        assert_eq!(associate_addr.port(), local_addr.port());

        let SocketAddr::V4(echo_v4) = echo_addr else {
            panic!("UDP echo fixture should bind IPv4 loopback")
        };
        let payload = b"mixed active socks5 udp shutdown remains open";
        let mut udp_request = vec![0x00, 0x00, 0x00, 0x01];
        udp_request.extend_from_slice(&echo_v4.ip().octets());
        udp_request.extend_from_slice(&echo_v4.port().to_be_bytes());
        udp_request.extend_from_slice(payload);
        let udp_client = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        udp_client.send_to(&udp_request, associate_addr).await?;
        let mut response = [0_u8; 1024];
        let (received, from) =
            tokio::time::timeout(Duration::from_secs(2), udp_client.recv_from(&mut response))
                .await
                .expect("active SOCKS5 UDP response before shutdown")?;
        assert_eq!(from, associate_addr);
        assert_eq!(&response[..4], &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(&response[4..8], &echo_v4.ip().octets());
        assert_eq!(
            u16::from_be_bytes([response[8], response[9]]),
            echo_v4.port()
        );
        assert_eq!(&response[10..received], payload);
        assert!(
            !listener_task.is_finished(),
            "active SOCKS5 UDP association unexpectedly completed before shutdown"
        );

        listener_shutdown_tx
            .send(())
            .expect("send mixed listener shutdown");
        let listener_report = tokio::time::timeout(Duration::from_secs(2), listener_task)
            .await
            .expect("mixed listener returns promptly while SOCKS5 UDP association is active")??;
        assert_eq!(listener_report.accepted_connections, 1);
        assert_eq!(listener_report.completed_tcp_relays, 0);
        assert_eq!(listener_report.completed_udp_associations, 0);
        assert_eq!(listener_report.failed_udp_associations, 0);

        let mut after_shutdown = [0_u8; 1];
        let close_result =
            tokio::time::timeout(Duration::from_secs(2), control.read(&mut after_shutdown))
                .await
                .expect("active SOCKS5 UDP control observes listener shutdown");
        assert!(
            matches!(close_result, Ok(0) | Err(_)),
            "active SOCKS5 UDP control remained readable after listener shutdown"
        );

        let _ = server_shutdown_tx.send(());
        let server_result = tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("server loop returns promptly after active SOCKS5 UDP shutdown")
            .expect("join UDP server loop task");
        assert!(
            server_result.is_ok(),
            "server UDP loop errored after active SOCKS5 UDP shutdown: {server_result:?}"
        );
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn mixed_run_loop_accepts_concurrent_socks5_udp_associations() -> Result<(), ClientError>
    {
        async fn open_udp_associate(
            local_addr: SocketAddr,
        ) -> Result<(tokio::net::TcpStream, SocketAddr), ClientError> {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let mut control = tokio::net::TcpStream::connect(local_addr).await?;
            control.write_all(&[0x05, 0x01, 0x00]).await?;
            let mut greeting_response = [0_u8; 2];
            tokio::time::timeout(
                Duration::from_secs(2),
                control.read_exact(&mut greeting_response),
            )
            .await
            .expect("SOCKS5 greeting response within timeout")?;
            assert_eq!(greeting_response, [0x05, 0x00]);
            control
                .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            let mut associate_response = [0_u8; 10];
            tokio::time::timeout(
                Duration::from_secs(2),
                control.read_exact(&mut associate_response),
            )
            .await
            .expect("SOCKS5 UDP ASSOCIATE response within timeout")?;
            assert_eq!(&associate_response[..4], &[0x05, 0x00, 0x00, 0x01]);
            let associate_addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    associate_response[4],
                    associate_response[5],
                    associate_response[6],
                    associate_response[7],
                )),
                u16::from_be_bytes([associate_response[8], associate_response[9]]),
            );
            assert_eq!(associate_addr.port(), local_addr.port());
            Ok((control, associate_addr))
        }

        async fn send_socks5_udp_echo(
            udp_client: &tokio::net::UdpSocket,
            associate_addr: SocketAddr,
            echo_addr: SocketAddr,
            payload: &[u8],
        ) -> Result<(), ClientError> {
            let SocketAddr::V4(echo_v4) = echo_addr else {
                panic!("UDP echo fixture should bind IPv4 loopback")
            };
            let mut udp_request = vec![0x00, 0x00, 0x00, 0x01];
            udp_request.extend_from_slice(&echo_v4.ip().octets());
            udp_request.extend_from_slice(&echo_v4.port().to_be_bytes());
            udp_request.extend_from_slice(payload);
            udp_client.send_to(&udp_request, associate_addr).await?;
            let mut response = [0_u8; 1024];
            let (received, from) =
                tokio::time::timeout(Duration::from_secs(2), udp_client.recv_from(&mut response))
                    .await
                    .expect("concurrent SOCKS5 UDP response within timeout")?;
            assert_eq!(from, associate_addr);
            assert_eq!(&response[..4], &[0x00, 0x00, 0x00, 0x01]);
            assert_eq!(&response[4..8], &echo_v4.ip().octets());
            assert_eq!(
                u16::from_be_bytes([response[8], response[9]]),
                echo_v4.port()
            );
            assert_eq!(&response[10..received], payload);
            Ok(())
        }

        let uuid = uuid::Uuid::new_v4();
        let password = "mixed concurrent socks5 udp associate password";
        let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
            .expect("generate fixture cert");
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let server_runtime = zuicity_server::ServerRuntime::new(server_config(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))?);
        let server = server_runtime.bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .run_udp_over_stream_loop_until(async {
                    let _ = server_shutdown_rx.await;
                })
                .await
        });

        let echo_addr = echo.local_addr();
        let runtime = ClientRuntime::new(client_config(&format!(
            r#"{{"listen":"127.0.0.1:0","server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"server.local"}}"#
        ))?);
        let listener = runtime
            .bind_mixed_listener_with_roots(([127, 0, 0, 1], 0).into(), cert.cert.pem().as_bytes())
            .await?;
        let local_addr = listener.local_addr()?;
        let (listener_shutdown_tx, listener_shutdown_rx) = tokio::sync::oneshot::channel();
        let listener_task = tokio::spawn(async move {
            listener
                .run_loop_until(async {
                    let _ = listener_shutdown_rx.await;
                })
                .await
        });

        let (mut first_control, first_associate_addr) = open_udp_associate(local_addr).await?;
        let (mut second_control, second_associate_addr) = open_udp_associate(local_addr).await?;
        assert_eq!(first_associate_addr, second_associate_addr);

        let first_udp = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let second_udp = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let first_payload = b"mixed concurrent socks5 udp first";
        let second_payload = b"mixed concurrent socks5 udp second";
        send_socks5_udp_echo(&first_udp, first_associate_addr, echo_addr, first_payload).await?;
        send_socks5_udp_echo(
            &second_udp,
            second_associate_addr,
            echo_addr,
            second_payload,
        )
        .await?;

        use tokio::io::AsyncWriteExt;
        first_control.shutdown().await?;
        second_control.shutdown().await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        listener_shutdown_tx
            .send(())
            .expect("send mixed listener shutdown");
        let listener_report = listener_task.await??;
        let expected_bytes = (first_payload.len() + second_payload.len()) as u64;
        assert_eq!(listener_report.accepted_connections, 2);
        assert_eq!(listener_report.completed_tcp_relays, 0);
        assert_eq!(listener_report.completed_udp_associations, 2);
        assert_eq!(listener_report.bytes_from_client, expected_bytes);
        assert_eq!(listener_report.bytes_from_target, expected_bytes);

        server_shutdown_tx
            .send(())
            .expect("send UDP proxy server shutdown");
        let server_report = server_task.await??;
        // Both SOCKS5 UDP associations now multiplex over one shared, reused
        // authenticated QUIC connection, so the server accepts a single
        // connection serving two UDP-over-stream relays.
        assert_eq!(server_report.accepted_connections, 1);
        assert_eq!(server_report.completed_udp_relays, 2);
        assert_eq!(server_report.bytes_from_client, expected_bytes);
        assert_eq!(server_report.bytes_from_target, expected_bytes);
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[test]
    fn mixed_listener_dispatch_matches_upstream_peek_rule() {
        assert_eq!(
            MixedProtocol::from_peeked_byte(Some(0x05)),
            MixedProtocol::Socks5
        );
        assert_eq!(
            MixedProtocol::from_peeked_byte(Some(b'G')),
            MixedProtocol::Http
        );
        assert_eq!(
            MixedProtocol::from_peeked_byte(Some(0x04)),
            MixedProtocol::Http
        );
        assert_eq!(MixedProtocol::from_peeked_byte(None), MixedProtocol::Http);
    }
}
