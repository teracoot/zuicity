/// Re-exported so downstream crates can classify a stream that stopped because
/// its connection was lost without taking a direct `quinn` dependency.
pub use quinn::StoppedError;

/// Transport construction errors.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Transport runtime has not been implemented for this parity slice yet.
    #[error("transport runtime is not implemented for this parity slice")]
    RuntimeNotImplemented,
    /// I/O failed while loading PEM data or constructing endpoints.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// No certificate was found in the PEM input.
    #[error("no certificate found in pem input")]
    NoCertificates,
    /// No private key was found in the PEM input.
    #[error("no private key found in pem input")]
    NoPrivateKey,
    /// Rustls rejected the TLS configuration.
    #[error("tls config: {0}")]
    Rustls(#[from] rustls::Error),
    /// Quinn rejected the QUIC crypto configuration.
    #[error("quic crypto config: {0}")]
    QuinnCrypto(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
    /// Quinn rejected connection parameters before sending packets.
    #[error("quic connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    /// QUIC connection failed.
    #[error("quic connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// QUIC stream read failed.
    #[error("quic stream read: {0}")]
    ReadExact(#[from] quinn::ReadExactError),
    /// QUIC stream write failed.
    #[error("quic stream write: {0}")]
    Write(#[from] quinn::WriteError),
    /// QUIC stream was already closed.
    #[error("quic stream closed")]
    ClosedStream(#[from] quinn::ClosedStream),
    /// QUIC stream stop monitoring failed.
    #[error("quic stream stopped: {0}")]
    Stopped(#[from] quinn::StoppedError),
    /// QUIC stream read-to-end failed.
    #[error("quic stream read-to-end: {0}")]
    ReadToEnd(#[from] quinn::ReadToEndError),
    /// Protocol frame or authentication-token derivation failed.
    #[error("protocol: {0}")]
    Protocol(#[from] zuicity_protocol::ProtocolError),
    /// Server endpoint closed before an incoming connection arrived.
    #[error("endpoint closed")]
    EndpointClosed,
    /// Authentication failed.
    #[error("authentication rejected")]
    AuthenticationRejected,
    /// Authentication did not complete before the application deadline.
    #[error("authentication timed out")]
    AuthenticationTimedOut,
    /// Peer closed a proxy stream before sending the first header byte.
    #[error("proxy stream closed before header")]
    ProxyStreamClosedBeforeHeader,
    /// A non-TCP proxy stream arrived where TCP was required.
    #[error("unexpected proxy network {0:?}")]
    UnexpectedProxyNetwork(zuicity_protocol::Network),
    /// UDP response frames must carry concrete IP targets.
    #[error("UDP response frame used a domain target")]
    UnsupportedDomainTarget,
    /// UDP-over-stream ended before any datagram was relayed.
    #[error("UDP-over-stream session ended before any datagram")]
    EmptyUdpOverStream,
    /// TCP proxy target resolved to no usable address.
    #[error("TCP proxy target resolved to no usable address")]
    NoUsableTcpTarget,
    /// Domain target resolution yielded no address that responded before timeout.
    #[error("UDP domain proxy target resolved to no usable address")]
    NoUsableUdpTarget,
    /// Outbound proxy link was not parseable.
    #[error("invalid proxy dialer link {link}: {message}")]
    InvalidProxyDialerLink {
        /// Raw link string.
        link: String,
        /// Parse failure message.
        message: String,
    },
    /// Outbound proxy link scheme is not supported yet.
    #[error("unsupported proxy dialer link scheme {scheme}")]
    UnsupportedProxyDialerLinkScheme {
        /// Unsupported scheme.
        scheme: String,
    },
    /// Outbound proxy link is unsupported for this target network.
    #[error("proxy dialer link scheme {scheme} does not support {network:?}")]
    UnsupportedProxyDialerLinkNetwork {
        /// Proxy link scheme.
        scheme: &'static str,
        /// Target network.
        network: zuicity_protocol::Network,
    },
    /// HTTP CONNECT proxy failed during handshake or connect.
    #[error("HTTP CONNECT proxy {stage} failed: {message}")]
    HttpProxy {
        /// HTTP CONNECT stage.
        stage: &'static str,
        /// Failure message.
        message: String,
    },
    /// Trojan proxy failed during TLS handshake or request setup.
    #[error("Trojan proxy {stage} failed: {message}")]
    TrojanProxy {
        /// Trojan proxy stage.
        stage: &'static str,
        /// Failure message.
        message: String,
    },
    /// VMess proxy failed during request setup or stream framing.
    #[error("VMess proxy {stage} failed: {message}")]
    VmessProxy {
        /// VMess proxy stage.
        stage: &'static str,
        /// Failure message.
        message: String,
    },
    /// VLESS proxy failed during request setup or response framing.
    #[error("VLESS proxy {stage} failed: {message}")]
    VlessProxy {
        /// VLESS proxy stage.
        stage: &'static str,
        /// Failure message.
        message: String,
    },
    /// TUIC proxy failed during QUIC setup or command framing.
    #[error("TUIC proxy {stage} failed: {message}")]
    TuicProxy {
        /// TUIC proxy stage.
        stage: &'static str,
        /// Failure message.
        message: String,
    },
    /// Hysteria2 proxy failed during QUIC setup, authentication, or stream framing.
    #[error("Hysteria2 proxy {stage} failed: {message}")]
    Hysteria2Proxy {
        /// Hysteria2 proxy stage.
        stage: &'static str,
        /// Failure message.
        message: String,
    },
    /// SOCKS5 proxy failed during handshake or connect.
    #[error("SOCKS5 proxy {stage} failed: {message}")]
    Socks5Proxy {
        /// SOCKS5 handshake stage.
        stage: &'static str,
        /// Failure message.
        message: String,
    },
    /// Domain target bytes were not valid UTF-8.
    #[error("domain proxy target is not valid UTF-8: {0}")]
    InvalidDomainTarget(#[from] std::str::Utf8Error),
    /// A decoded UDP-over-stream frame exceeded the caller-provided limit.
    #[error("UDP-over-stream frame size {size} exceeds limit {limit}")]
    UdpFrameTooLarge {
        /// Decoded datagram payload size.
        size: usize,
        /// Caller-provided maximum payload size.
        limit: usize,
    },
    /// Tokio task failed while validating transport behavior.
    #[error("task join: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),
}
