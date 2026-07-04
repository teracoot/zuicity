use std::net::SocketAddr;

/// Decoded UDP-over-stream datagram returned to the client side.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpOverStreamDatagram {
    /// UDP peer represented in the datagram header.
    pub target: SocketAddr,
    /// Datagram payload bytes.
    pub payload: Vec<u8>,
}

/// Summary for a completed one-datagram UDP-over-stream relay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpOverStreamRelayReport {
    /// Proxied UDP target address.
    pub target: SocketAddr,
    /// Bytes copied from QUIC client frame to UDP target.
    pub bytes_from_client: u64,
    /// Bytes copied from UDP target to QUIC client frame.
    pub bytes_from_target: u64,
}

/// Summary for a completed TCP proxy relay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpProxyRelayReport {
    /// Proxied TCP target address.
    pub target: SocketAddr,
    /// Bytes copied from QUIC client stream to TCP target.
    pub bytes_from_client: u64,
    /// Bytes copied from TCP target to QUIC client stream.
    pub bytes_from_target: u64,
}

/// Summary for one classified proxy relay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyRelayReport {
    /// TCP proxy stream relay completed.
    Tcp(TcpProxyRelayReport),
    /// UDP-over-stream session relay completed.
    Udp(UdpOverStreamRelayReport),
}

impl ProxyRelayReport {
    /// Returns bytes copied from the QUIC client side to the target side.
    #[must_use]
    pub const fn bytes_from_client(&self) -> u64 {
        match self {
            Self::Tcp(report) => report.bytes_from_client,
            Self::Udp(report) => report.bytes_from_client,
        }
    }

    /// Returns bytes copied from the target side back to the QUIC client side.
    #[must_use]
    pub const fn bytes_from_target(&self) -> u64 {
        match self {
            Self::Tcp(report) => report.bytes_from_target,
            Self::Udp(report) => report.bytes_from_target,
        }
    }
}
