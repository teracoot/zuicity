use std::net::SocketAddr;

use crate::{PlainUdpSocket, TransportError};

/// Builds a quinn endpoint bound to `addr` using the adaptive
/// [`PlainUdpSocket`]: no GRO/ECN/PMTUDISC on the receive path, optional
/// per-message UDP GSO on send (per [`crate::GsoMode::from_env`]). With
/// `Some(server_config)` it is a server endpoint, otherwise a client endpoint.
pub(super) fn build_ecn_safe_endpoint(
    addr: SocketAddr,
    server_config: Option<quinn::ServerConfig>,
) -> Result<quinn::Endpoint, TransportError> {
    let socket = std::net::UdpSocket::bind(addr)?;
    build_ecn_safe_endpoint_from_socket(socket, server_config)
}

/// Wraps an already-bound std UDP socket into an adaptive-GSO quinn endpoint.
pub(super) fn build_ecn_safe_endpoint_from_socket(
    socket: std::net::UdpSocket,
    server_config: Option<quinn::ServerConfig>,
) -> Result<quinn::Endpoint, TransportError> {
    let runtime =
        quinn::default_runtime().ok_or_else(|| std::io::Error::other("no async runtime found"))?;
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        server_config,
        std::sync::Arc::new(PlainUdpSocket::new(socket)?),
        runtime,
    )?;
    Ok(endpoint)
}
