use std::{sync::Arc, time::Duration};

use zuicity_protocol::ALPN_H3;

/// Upstream initial stream receive window, 2 MiB.
pub const INITIAL_STREAM_RECEIVE_WINDOW: u64 = 2 * 1024 * 1024;

/// Upstream maximum stream receive window, 32 MiB.
pub const MAX_STREAM_RECEIVE_WINDOW: u64 = 32 * 1024 * 1024;

/// Upstream initial connection receive window, 32 MiB.
pub const INITIAL_CONNECTION_RECEIVE_WINDOW: u64 = 32 * 1024 * 1024;

/// Upstream maximum connection receive window, 64 MiB.
pub const MAX_CONNECTION_RECEIVE_WINDOW: u64 = 64 * 1024 * 1024;

/// Upstream server incoming stream limit.
pub const MAX_OPEN_INCOMING_STREAMS: u64 = 100;

/// Upstream client fallback stream rotation threshold from the protocol spec.
pub const CLIENT_STREAM_ROTATION_THRESHOLD: u64 = 30;

/// Upstream congestion window value passed to the congestion controller hook.
pub const UPSTREAM_CWND: u32 = 10;

/// Upstream client keepalive period.
pub const CLIENT_KEEP_ALIVE: Duration = Duration::from_secs(5);

/// Upstream server keepalive period.
pub const SERVER_KEEP_ALIVE: Duration = Duration::from_secs(10);

/// Upstream default UDP NAT association timeout.
pub const DEFAULT_NAT_TIMEOUT: Duration = Duration::from_secs(3 * 60);

/// Quinn's default maximum QUIC idle timeout, in milliseconds.
pub const DEFAULT_QUIC_MAX_IDLE_TIMEOUT_MILLIS: u32 = 30_000;

/// Upstream client handshake idle timeout.
pub const CLIENT_HANDSHAKE_IDLE_TIMEOUT: Duration = Duration::from_secs(8);

/// QUIC stream policy required by upstream Juicity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamPolicy {
    /// Server maximum incoming bidirectional streams.
    pub max_incoming_streams: u64,
    /// Server maximum incoming unidirectional streams.
    pub max_incoming_uni_streams: u64,
    /// Client fallback rotation threshold when dynamic stream availability is unavailable.
    pub client_stream_rotation_threshold: u64,
}

impl StreamPolicy {
    /// Returns the upstream stream policy.
    #[must_use]
    pub const fn upstream() -> Self {
        Self {
            max_incoming_streams: MAX_OPEN_INCOMING_STREAMS,
            max_incoming_uni_streams: MAX_OPEN_INCOMING_STREAMS,
            client_stream_rotation_threshold: CLIENT_STREAM_ROTATION_THRESHOLD,
        }
    }

    /// Returns the upstream reserved stream capacity used when rotating client QUIC connections.
    #[must_use]
    pub fn client_reserved_stream_capacity(&self) -> u64 {
        (self.max_incoming_streams / 5).clamp(1, 5)
    }
}

impl Default for StreamPolicy {
    fn default() -> Self {
        Self::upstream()
    }
}

/// TLS minimum version supported by Juicity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MinimumTlsVersion {
    /// TLS 1.3.
    Tls13,
}

/// TLS policy common to client and server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsPolicy {
    /// Required ALPN value.
    pub alpn: &'static str,
    /// Minimum TLS version.
    pub min_version: MinimumTlsVersion,
    /// Whether TLS 1.3 or newer is required.
    pub tls13_or_newer: bool,
}

impl TlsPolicy {
    /// Returns the upstream TLS policy.
    #[must_use]
    pub const fn upstream() -> Self {
        Self {
            alpn: ALPN_H3,
            min_version: MinimumTlsVersion::Tls13,
            tls13_or_newer: true,
        }
    }
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self::upstream()
    }
}

/// Congestion controller requested by upstream Juicity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CongestionController {
    /// BBR congestion control.
    Bbr,
}

/// QUIC receive window policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveWindowPolicy {
    /// Initial stream receive window.
    pub initial_stream: u64,
    /// Maximum stream receive window.
    pub max_stream: u64,
    /// Initial connection receive window.
    pub initial_connection: u64,
    /// Maximum connection receive window.
    pub max_connection: u64,
}

impl ReceiveWindowPolicy {
    /// Returns the upstream receive-window policy shared by client and server.
    #[must_use]
    pub const fn upstream() -> Self {
        Self {
            initial_stream: INITIAL_STREAM_RECEIVE_WINDOW,
            max_stream: MAX_STREAM_RECEIVE_WINDOW,
            initial_connection: INITIAL_CONNECTION_RECEIVE_WINDOW,
            max_connection: MAX_CONNECTION_RECEIVE_WINDOW,
        }
    }
}

/// QUIC runtime policy shared by embeddable client/server runtimes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicRuntimePolicy {
    /// QUIC receive windows.
    pub receive_windows: ReceiveWindowPolicy,
    /// QUIC stream policy.
    pub streams: StreamPolicy,
    /// Keepalive period.
    pub keep_alive: Duration,
    /// Maximum negotiated QUIC idle timeout in milliseconds.
    pub max_idle_timeout_millis: Option<u32>,
    /// Optional client handshake idle timeout.
    pub handshake_idle_timeout: Option<Duration>,
    /// Whether path MTU discovery is disabled.
    pub disable_path_mtu_discovery: bool,
    /// Whether QUIC datagrams are enabled.
    pub enable_datagrams: bool,
    /// Selected congestion controller.
    pub congestion_controller: CongestionController,
    /// Congestion window value passed to upstream's congestion hook.
    pub cwnd: u32,
}

impl QuicRuntimePolicy {
    /// Returns the upstream client QUIC policy.
    #[must_use]
    pub const fn upstream_client() -> Self {
        Self {
            receive_windows: ReceiveWindowPolicy::upstream(),
            streams: StreamPolicy::upstream(),
            keep_alive: CLIENT_KEEP_ALIVE,
            max_idle_timeout_millis: Some(DEFAULT_QUIC_MAX_IDLE_TIMEOUT_MILLIS),
            handshake_idle_timeout: Some(CLIENT_HANDSHAKE_IDLE_TIMEOUT),
            disable_path_mtu_discovery: false,
            enable_datagrams: false,
            congestion_controller: CongestionController::Bbr,
            cwnd: UPSTREAM_CWND,
        }
    }

    /// Returns the upstream server QUIC policy.
    #[must_use]
    pub const fn upstream_server() -> Self {
        Self {
            receive_windows: ReceiveWindowPolicy::upstream(),
            streams: StreamPolicy::upstream(),
            keep_alive: SERVER_KEEP_ALIVE,
            max_idle_timeout_millis: Some(DEFAULT_QUIC_MAX_IDLE_TIMEOUT_MILLIS),
            handshake_idle_timeout: None,
            disable_path_mtu_discovery: false,
            enable_datagrams: true,
            congestion_controller: CongestionController::Bbr,
            cwnd: UPSTREAM_CWND,
        }
    }
}

/// Introspectable Quinn transport configuration built from Juicity policy.
#[derive(Debug)]
pub struct BuiltTransportConfig {
    pub(crate) inner: quinn::TransportConfig,
    pub(crate) policy: QuicRuntimePolicy,
}

impl BuiltTransportConfig {
    /// Returns the applied Juicity runtime policy.
    #[must_use]
    pub const fn policy(&self) -> &QuicRuntimePolicy {
        &self.policy
    }

    /// Returns the configured bidirectional stream limit.
    #[must_use]
    pub const fn max_concurrent_bidi_streams(&self) -> quinn::VarInt {
        quinn::VarInt::from_u32(MAX_OPEN_INCOMING_STREAMS as u32)
    }

    /// Returns the configured unidirectional stream limit.
    #[must_use]
    pub const fn max_concurrent_uni_streams(&self) -> quinn::VarInt {
        quinn::VarInt::from_u32(MAX_OPEN_INCOMING_STREAMS as u32)
    }

    /// Returns the configured stream receive window.
    #[must_use]
    pub const fn stream_receive_window(&self) -> quinn::VarInt {
        quinn::VarInt::from_u32(INITIAL_STREAM_RECEIVE_WINDOW as u32)
    }

    /// Returns the configured connection receive window.
    #[must_use]
    pub const fn receive_window(&self) -> quinn::VarInt {
        quinn::VarInt::from_u32(INITIAL_CONNECTION_RECEIVE_WINDOW as u32)
    }

    /// Returns the configured keepalive interval.
    #[must_use]
    pub const fn keep_alive_interval(&self) -> Option<Duration> {
        Some(self.policy.keep_alive)
    }

    /// Returns the configured QUIC maximum idle timeout in milliseconds.
    #[must_use]
    pub const fn max_idle_timeout_millis(&self) -> Option<u32> {
        self.policy.max_idle_timeout_millis
    }

    /// Returns the datagram receive-buffer setting derived from the policy.
    #[must_use]
    pub const fn datagram_receive_buffer_size(&self) -> Option<usize> {
        if self.policy.enable_datagrams {
            Some(u16::MAX as usize)
        } else {
            None
        }
    }

    /// Converts into a shareable Quinn transport config.
    #[must_use]
    pub fn into_arc(self) -> Arc<quinn::TransportConfig> {
        Arc::new(self.inner)
    }
}
