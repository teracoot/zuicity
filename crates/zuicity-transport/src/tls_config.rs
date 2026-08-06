use std::{io::Cursor, sync::Arc};

use zuicity_protocol::ALPN_H3;

use crate::{
    BuiltTransportConfig, CongestionController, QuicRuntimePolicy, TransportError,
    tls_verify::{NoCertificateVerification, PinnedCertChainVerification},
};

/// Builds a Quinn transport config from an upstream Juicity policy.
#[must_use]
pub fn build_transport_config(policy: &QuicRuntimePolicy) -> BuiltTransportConfig {
    let mut inner = quinn::TransportConfig::default();
    inner.max_concurrent_bidi_streams(quinn::VarInt::from_u32(
        policy.streams.max_incoming_streams as u32,
    ));
    inner.max_concurrent_uni_streams(quinn::VarInt::from_u32(
        policy.streams.max_incoming_uni_streams as u32,
    ));
    inner.stream_receive_window(quinn::VarInt::from_u32(
        policy.receive_windows.max_stream as u32,
    ));
    inner.receive_window(quinn::VarInt::from_u32(
        policy.receive_windows.max_connection as u32,
    ));
    inner.send_window(policy.receive_windows.max_connection);
    inner.keep_alive_interval(Some(policy.keep_alive));
    inner.max_idle_timeout(
        policy
            .max_idle_timeout_millis
            .map(|millis| quinn::IdleTimeout::from(quinn::VarInt::from_u32(millis))),
    );
    inner.datagram_receive_buffer_size(if policy.enable_datagrams {
        Some(usize::from(u16::MAX))
    } else {
        None
    });
    if policy.disable_path_mtu_discovery {
        inner.mtu_discovery_config(None);
    }
    // Let Quinn group datagrams into `Transmit` values. PlainUdpSocket emits
    // ordinary datagrams by default and may use per-message UDP GSO only under
    // the explicit Linux opt-in.
    let segmentation_offload_enabled = cfg!(target_os = "linux");
    inner.enable_segmentation_offload(segmentation_offload_enabled);
    apply_congestion_controller(&mut inner, policy);
    BuiltTransportConfig {
        inner,
        policy: policy.clone(),
        #[cfg(test)]
        segmentation_offload_enabled,
    }
}

/// Installs the policy's congestion controller on a quinn [`TransportConfig`].
///
/// Quinn defaults to CUBIC; Juicity defaults to BBR and may explicitly select
/// CUBIC or NewReno. Upstream's BBR hook ignores the configured `cwnd` argument
/// and starts at 32 packets.
fn apply_congestion_controller(inner: &mut quinn::TransportConfig, policy: &QuicRuntimePolicy) {
    inner.congestion_controller_factory(congestion_controller_factory(policy));
}

pub(crate) fn congestion_controller_factory(
    policy: &QuicRuntimePolicy,
) -> Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> {
    match policy.congestion_controller {
        CongestionController::Bbr => {
            let mut bbr = quinn::congestion::BbrConfig::default();
            bbr.initial_window(bbr_initial_window_bytes());
            Arc::new(bbr)
        }
        CongestionController::Cubic => Arc::new(quinn::congestion::CubicConfig::default()),
        CongestionController::NewReno => Arc::new(quinn::congestion::NewRenoConfig::default()),
    }
}

pub(crate) const fn bbr_initial_window_bytes() -> u64 {
    const UPSTREAM_BBR_INITIAL_WINDOW_PACKETS: u64 = 32;
    const UPSTREAM_INITIAL_PACKET_BYTES: u64 = 1280;
    UPSTREAM_BBR_INITIAL_WINDOW_PACKETS * UPSTREAM_INITIAL_PACKET_BYTES
}

/// Builds upstream-compatible rustls server crypto from PEM certificate and key bytes.
pub fn build_server_crypto_config_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<rustls::ServerConfig, TransportError> {
    let cert_chain = parse_certificates(cert_pem)?;
    let key = parse_private_key(key_pem)?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(cert_chain, key)?;
    config.alpn_protocols = vec![ALPN_H3.as_bytes().to_vec()];
    Ok(config)
}

/// Builds upstream-compatible Quinn server config from PEM certificate and key bytes.
pub fn build_server_config_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<QuicServerConfig, TransportError> {
    build_server_config_from_pem_with_policy(
        cert_pem,
        key_pem,
        &QuicRuntimePolicy::upstream_server(),
    )
}

/// Builds a Quinn server config from PEM material and an explicit QUIC policy.
pub fn build_server_config_from_pem_with_policy(
    cert_pem: &[u8],
    key_pem: &[u8],
    policy: &QuicRuntimePolicy,
) -> Result<QuicServerConfig, TransportError> {
    let crypto = build_server_crypto_config_from_pem(cert_pem, key_pem)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
    ));
    config.transport_config(build_transport_config(policy).into_arc());
    Ok(QuicServerConfig {
        inner: config,
        policy: policy.clone(),
    })
}

/// Builds upstream-compatible rustls client crypto from optional root PEMs.
pub fn build_client_crypto_config_with_roots(
    roots_pem: &[u8],
    allow_insecure: bool,
) -> Result<rustls::ClientConfig, TransportError> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut config = if allow_insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        let roots = if roots_pem.is_empty() {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            roots
        } else {
            parse_root_store(roots_pem)?
        };
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = vec![ALPN_H3.as_bytes().to_vec()];
    Ok(config)
}

/// Builds upstream-compatible Quinn client config from optional root PEMs.
pub fn build_client_config_with_roots(
    roots_pem: &[u8],
    allow_insecure: bool,
) -> Result<QuicClientConfig, TransportError> {
    let policy = QuicRuntimePolicy::upstream_client();
    build_client_config_with_roots_and_policy(roots_pem, allow_insecure, &policy)
}

pub(crate) fn build_client_config_with_roots_and_policy(
    roots_pem: &[u8],
    allow_insecure: bool,
    policy: &QuicRuntimePolicy,
) -> Result<QuicClientConfig, TransportError> {
    let crypto = build_client_crypto_config_with_roots(roots_pem, allow_insecure)?;
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    config.transport_config(build_transport_config(policy).into_arc());
    Ok(QuicClientConfig {
        inner: config,
        policy: policy.clone(),
    })
}

fn build_client_crypto_config_with_webpki_roots(
    allow_insecure: bool,
) -> Result<rustls::ClientConfig, TransportError> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut config = if allow_insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = vec![ALPN_H3.as_bytes().to_vec()];
    Ok(config)
}

pub(crate) fn build_client_config_with_webpki_roots(
    allow_insecure: bool,
    policy: &QuicRuntimePolicy,
) -> Result<QuicClientConfig, TransportError> {
    let crypto = build_client_crypto_config_with_webpki_roots(allow_insecure)?;
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    config.transport_config(build_transport_config(policy).into_arc());
    Ok(QuicClientConfig {
        inner: config,
        policy: policy.clone(),
    })
}

/// Builds upstream-compatible rustls client crypto using only a pinned certificate-chain hash.
pub fn build_client_crypto_config_with_cert_chain_pin(
    pinned_cert_chain_sha256: &[u8],
) -> Result<rustls::ClientConfig, TransportError> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertChainVerification::new(
            pinned_cert_chain_sha256,
        )))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_H3.as_bytes().to_vec()];
    Ok(config)
}

/// Builds upstream-compatible Quinn client config using only a pinned certificate-chain hash.
pub fn build_client_config_with_cert_chain_pin(
    pinned_cert_chain_sha256: &[u8],
) -> Result<QuicClientConfig, TransportError> {
    let policy = QuicRuntimePolicy::upstream_client();
    build_client_config_with_cert_chain_pin_and_policy(pinned_cert_chain_sha256, &policy)
}

pub(crate) fn build_client_config_with_cert_chain_pin_and_policy(
    pinned_cert_chain_sha256: &[u8],
    policy: &QuicRuntimePolicy,
) -> Result<QuicClientConfig, TransportError> {
    let crypto = build_client_crypto_config_with_cert_chain_pin(pinned_cert_chain_sha256)?;
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    config.transport_config(build_transport_config(policy).into_arc());
    Ok(QuicClientConfig {
        inner: config,
        policy: policy.clone(),
    })
}

/// Introspectable Quinn server config wrapper.
#[derive(Clone, Debug)]
pub struct QuicServerConfig {
    /// Built Quinn server configuration.
    pub inner: quinn::ServerConfig,
    policy: QuicRuntimePolicy,
}

impl QuicServerConfig {
    /// Returns the applied upstream transport policy wrapper.
    #[must_use]
    pub fn transport(&self) -> BuiltTransportConfig {
        build_transport_config(&self.policy)
    }
}

/// Introspectable Quinn client config wrapper.
#[derive(Clone, Debug)]
pub struct QuicClientConfig {
    /// Built Quinn client configuration.
    pub inner: quinn::ClientConfig,
    policy: QuicRuntimePolicy,
}

impl QuicClientConfig {
    /// Returns the applied upstream transport policy wrapper.
    #[must_use]
    pub fn transport(&self) -> BuiltTransportConfig {
        build_transport_config(&self.policy)
    }
}

fn parse_certificates(
    pem: &[u8],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, TransportError> {
    let certs = rustls_pemfile::certs(&mut Cursor::new(pem)).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(TransportError::NoCertificates);
    }
    Ok(certs)
}

fn parse_private_key(
    pem: &[u8],
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, TransportError> {
    rustls_pemfile::private_key(&mut Cursor::new(pem))?.ok_or(TransportError::NoPrivateKey)
}

fn parse_root_store(pem: &[u8]) -> Result<rustls::RootCertStore, TransportError> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in parse_certificates(pem)? {
        roots.add(cert)?;
    }
    Ok(roots)
}
