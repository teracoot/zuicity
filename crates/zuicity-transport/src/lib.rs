//! QUIC/TLS transport boundaries for Zuicity runtimes.

use aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit, generic_array::GenericArray};
use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update as Sha3Update, XofReader},
};
use zuicity_protocol::{
    ALPN_H3, AUTHENTICATION_FRAME_LEN, AtomicCounter64, AuthenticationRequest, Network,
    ProtocolError, ProxyAddress, ProxyHeader, RUNTIME_ADDR_TYPE_DOMAIN, RUNTIME_ADDR_TYPE_IPV4,
    RUNTIME_ADDR_TYPE_IPV6, decode_udp_datagram, encode_udp_datagram, export_authentication_token,
};

use std::{
    collections::HashMap,
    fmt,
    io::Cursor,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, atomic::Ordering},
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

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

/// Per-direction relay copy buffer. Larger than tokio::io::copy's 8 KiB default
/// so bulk transfers hand the QUIC stack and the kernel socket large write
/// batches, cutting syscall and stream-frame overhead on high-throughput flows.
const RELAY_COPY_BUFFER_SIZE: usize = 64 * 1024;

/// Upstream TUIC command-frame version used by daeuniverse/outbound.
const TUIC_VERSION_5: u8 = 0x05;

/// Upstream TUIC authentication command type.
const TUIC_COMMAND_AUTHENTICATE: u8 = 0x00;

/// Upstream TUIC TCP CONNECT command type.
const TUIC_COMMAND_CONNECT: u8 = 0x01;

/// Upstream TUIC native UDP packet command type.
const TUIC_COMMAND_PACKET: u8 = 0x02;

/// Upstream TUIC UDP association close command type.
const TUIC_COMMAND_DISSOCIATE: u8 = 0x03;

/// Upstream TUIC heartbeat command type (datagram, two bytes, no payload).
const TUIC_COMMAND_HEARTBEAT: u8 = 0x04;

/// Maximum bytes accepted from a single TUIC UDP-over-stream command.
const TUIC_UNI_STREAM_MAX_LEN: usize = 70_000;

/// Upstream TUIC domain address discriminator.
const TUIC_ADDR_DOMAIN: u8 = 0x00;

/// Upstream TUIC IPv4 address discriminator.
const TUIC_ADDR_IPV4: u8 = 0x01;

/// Upstream TUIC IPv6 address discriminator.
const TUIC_ADDR_IPV6: u8 = 0x02;

/// Upstream TUIC fragment-continuation address discriminator.
const TUIC_ADDR_NONE: u8 = 0xff;

/// Upstream TUIC UDP packet header length before the variable address field.
const TUIC_UDP_PACKET_FIXED_LEN: usize = 10;

/// Upstream TUIC client keepalive period.
const TUIC_CLIENT_KEEP_ALIVE: Duration = Duration::from_secs(3);

/// Upstream Hysteria2 HTTP/3 authentication authority.
const HYSTERIA2_AUTHORITY: &str = "hysteria";

/// Upstream Hysteria2 HTTP/3 authentication path.
const HYSTERIA2_AUTH_PATH: &str = "/auth";

/// Upstream Hysteria2 authentication success status.
const HYSTERIA2_AUTH_STATUS_OK: u16 = 233;

/// Upstream Hysteria2 TCP request frame type.
const HYSTERIA2_TCP_REQUEST_FRAME_TYPE: u64 = 0x401;

/// Upstream Hysteria2 UDP datagram size used before fragmentation.
const HYSTERIA2_MAX_UDP_SIZE: usize = 4096;

/// Upstream Hysteria2 UDP packet fixed header length before address varint.
const HYSTERIA2_UDP_PACKET_FIXED_LEN: usize = 8;

/// Upstream Hysteria2 UDP address length guard.
const HYSTERIA2_MAX_UDP_ADDRESS_LEN: usize = 2048;

/// Upstream first Hysteria2 UDP session ID.
const HYSTERIA2_INITIAL_UDP_SESSION_ID: u32 = 1;

/// Upstream packet ID used by non-fragmented Hysteria2 UDP datagrams.
const HYSTERIA2_UNFRAGMENTED_PACKET_ID: u16 = 0;

/// Upstream Hysteria2 stream receive window, 8 MiB.
const HYSTERIA2_STREAM_RECEIVE_WINDOW: u64 = 8 * 1024 * 1024;

/// Upstream Hysteria2 connection receive window, 20 MiB.
const HYSTERIA2_CONNECTION_RECEIVE_WINDOW: u64 = HYSTERIA2_STREAM_RECEIVE_WINDOW * 5 / 2;

/// Upstream Hysteria2 keepalive period.
const HYSTERIA2_KEEP_ALIVE: Duration = Duration::from_secs(10);

/// Upstream Hysteria2 auth padding length bounds.
const HYSTERIA2_AUTH_PADDING_RANGE: std::ops::Range<usize> = 256..2048;

/// Upstream Hysteria2 TCP request padding length bounds.
const HYSTERIA2_TCP_REQUEST_PADDING_RANGE: std::ops::Range<usize> = 64..512;

const HYSTERIA2_PADDING_CHARS: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Upstream client handshake idle timeout.
pub const CLIENT_HANDSHAKE_IDLE_TIMEOUT: Duration = Duration::from_secs(8);

/// Target-side egress policy for server proxy relays.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProxyEgressPolicy {
    /// Optional source IP used when dialing proxied targets.
    pub send_through: Option<IpAddr>,
    /// Optional packet mark applied to outbound target sockets.
    pub fwmark: Option<u32>,
    /// Optional upstream-compatible outbound proxy link for target dials.
    pub dialer_link: Option<ProxyDialerLink>,
}

impl ProxyEgressPolicy {
    /// Returns the default direct egress policy.
    #[must_use]
    pub const fn direct() -> Self {
        Self {
            send_through: None,
            fwmark: None,
            dialer_link: None,
        }
    }

    /// Builds an egress policy with an optional source IP.
    #[must_use]
    pub const fn with_send_through(send_through: Option<IpAddr>) -> Self {
        Self {
            send_through,
            fwmark: None,
            dialer_link: None,
        }
    }

    /// Builds an egress policy with optional source IP and packet mark.
    #[must_use]
    pub const fn with_send_through_and_fwmark(
        send_through: Option<IpAddr>,
        fwmark: Option<u32>,
    ) -> Self {
        Self {
            send_through,
            fwmark,
            dialer_link: None,
        }
    }

    /// Builds an egress policy with optional source IP, packet mark, and outbound link.
    #[must_use]
    pub const fn with_send_through_fwmark_and_dialer_link(
        send_through: Option<IpAddr>,
        fwmark: Option<u32>,
        dialer_link: Option<ProxyDialerLink>,
    ) -> Self {
        Self {
            send_through,
            fwmark,
            dialer_link,
        }
    }
}

/// Parsed upstream-compatible outbound proxy link used for target dials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyDialerLink {
    /// HTTP CONNECT proxy endpoint for TCP target dials.
    HttpConnect(HttpConnectDialerLink),
    /// SOCKS5 proxy endpoint.
    Socks5(Socks5DialerLink),
    /// Shadowsocks proxy endpoint for TCP target dials.
    Shadowsocks(ShadowsocksDialerLink),
    /// ShadowsocksR origin/plain proxy endpoint for TCP target dials.
    ShadowsocksR(ShadowsocksRDialerLink),
    /// Trojan TCP-over-TLS proxy endpoint for TCP target dials.
    Trojan(TrojanDialerLink),
    /// Juicity QUIC proxy endpoint for TCP target dials.
    Juicity(JuicityDialerLink),
    /// TUIC QUIC proxy endpoint for TCP target dials.
    Tuic(TuicDialerLink),
    /// Hysteria2 QUIC proxy endpoint; parser-only until the Hysteria2 runtime stack is implemented.
    Hysteria2(Hysteria2DialerLink),
    /// VMess AEAD plain-TCP proxy endpoint for TCP target dials.
    Vmess(VmessDialerLink),
    /// VLESS plain-TCP proxy endpoint for TCP target dials.
    Vless(VlessDialerLink),
    /// Upstream-style proxy chain split by `->` and wrapped right-to-left.
    Chain(Vec<ProxyDialerLink>),
}

impl ProxyDialerLink {
    /// Parses the subset of upstream `dialer_link` supported by this runtime.
    pub fn parse(raw: &str) -> Result<Self, TransportError> {
        let links = raw.split("->").map(str::trim).collect::<Vec<_>>();
        if links.len() > 1 {
            let mut parsed = Vec::with_capacity(links.len());
            for link in links {
                if link.is_empty() {
                    return Err(TransportError::InvalidProxyDialerLink {
                        link: raw.to_owned(),
                        message: "proxy chain contains an empty hop".to_owned(),
                    });
                }
                parsed.push(Self::parse_single(link)?);
            }
            return Ok(Self::Chain(parsed));
        }
        Self::parse_single(raw.trim())
    }

    fn parse_single(raw: &str) -> Result<Self, TransportError> {
        let lowercase = raw.to_ascii_lowercase();
        if lowercase.starts_with("ssr://") {
            return Ok(Self::ShadowsocksR(ShadowsocksRDialerLink::from_url(raw)?));
        }
        if lowercase.starts_with("shadowsocksr://") {
            return Err(TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "upstream ShadowsocksR links use the ssr:// parser prefix".to_owned(),
            });
        }
        let parsed =
            url::Url::parse(raw).map_err(|source| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: source.to_string(),
            })?;
        match parsed.scheme().to_ascii_lowercase().as_str() {
            "http" | "https" => Ok(Self::HttpConnect(HttpConnectDialerLink::from_url(
                raw, &parsed,
            )?)),
            "socks" | "socks5" => Ok(Self::Socks5(Socks5DialerLink::from_url(raw, &parsed)?)),
            "ss" | "shadowsocks" => Ok(Self::Shadowsocks(ShadowsocksDialerLink::from_url(
                raw, &parsed,
            )?)),
            "trojan" | "trojan-go" => Ok(Self::Trojan(TrojanDialerLink::from_url(raw, &parsed)?)),
            "juicity" => Ok(Self::Juicity(JuicityDialerLink::from_url(raw, &parsed)?)),
            "tuic" => Ok(Self::Tuic(TuicDialerLink::from_url(raw, &parsed)?)),
            "hysteria2" | "hy2" => Ok(Self::Hysteria2(Hysteria2DialerLink::from_url(
                raw, &parsed,
            )?)),
            "vmess" => Ok(Self::Vmess(VmessDialerLink::from_url(raw, &parsed)?)),
            "vless" => Ok(Self::Vless(VlessDialerLink::from_url(raw, &parsed)?)),
            scheme => Err(TransportError::UnsupportedProxyDialerLinkScheme {
                scheme: scheme.to_owned(),
            }),
        }
    }

    fn endpoint(&self) -> Option<(&str, u16)> {
        match self {
            Self::HttpConnect(link) => Some((link.host.as_str(), link.port)),
            Self::Socks5(link) => Some((link.host.as_str(), link.port)),
            Self::Shadowsocks(link) => Some((link.host.as_str(), link.port)),
            Self::ShadowsocksR(link) => Some((link.host.as_str(), link.port)),
            Self::Trojan(link) => Some((link.host.as_str(), link.port)),
            Self::Juicity(_) => None,
            Self::Tuic(_) => None,
            Self::Hysteria2(_) => None,
            Self::Vmess(link) => Some((link.host.as_str(), link.port)),
            Self::Vless(link) => Some((link.host.as_str(), link.port)),
            Self::Chain(_) => None,
        }
    }

    /// Returns the parsed proxy endpoint host and port when the link targets a
    /// single host:port outbound (not a chain or a QUIC link without an exposed
    /// host/port pair). Intended for parity inspection and differential testing.
    #[must_use]
    pub fn endpoint_host_port(&self) -> Option<(&str, u16)> {
        self.endpoint()
    }

    /// Returns the canonical scheme name of this parsed link for parity
    /// inspection and differential testing.
    #[must_use]
    pub fn scheme(&self) -> &'static str {
        self.scheme_for_error()
    }

    fn scheme_for_error(&self) -> &'static str {
        match self {
            Self::HttpConnect(link) => link.scheme(),
            Self::Socks5(_) => "socks5",
            Self::Shadowsocks(_) => "shadowsocks",
            Self::ShadowsocksR(_) => "shadowsocksr",
            Self::Trojan(_) => "trojan",
            Self::Juicity(_) => "juicity",
            Self::Tuic(_) => "tuic",
            Self::Hysteria2(_) => "hysteria2",
            Self::Vmess(_) => "vmess",
            Self::Vless(_) => "vless",
            Self::Chain(_) => "chain",
        }
    }
}

/// Parsed HTTP CONNECT outbound proxy endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpConnectDialerLink {
    host: String,
    port: u16,
    tls: bool,
    sni: Option<String>,
    allow_insecure: bool,
    username: Option<String>,
    password: Option<String>,
}

impl HttpConnectDialerLink {
    fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
        let host = parsed
            .host_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing HTTP CONNECT host".to_owned(),
            })?
            .to_owned();
        let tls = parsed.scheme().eq_ignore_ascii_case("https");
        Ok(Self {
            host,
            port: parsed.port().unwrap_or(if tls { 443 } else { 80 }),
            tls,
            sni: parsed
                .query_pairs()
                .find_map(|(key, value)| (key == "sni").then(|| value.into_owned()))
                .filter(|value| !value.is_empty()),
            allow_insecure: http_connect_allow_insecure(parsed),
            username: (!parsed.username().is_empty()).then(|| parsed.username().to_owned()),
            password: parsed.password().map(ToOwned::to_owned),
        })
    }

    const fn scheme(&self) -> &'static str {
        if self.tls { "https" } else { "http" }
    }
}

fn http_connect_allow_insecure(parsed: &url::Url) -> bool {
    parsed.query_pairs().any(|(key, value)| {
        matches!(
            key.as_ref(),
            "allowInsecure" | "allow_insecure" | "allowinsecure" | "skipVerify"
        ) && dialer_link_query_bool(&value)
    })
}

/// Parsed SOCKS5 outbound proxy endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5DialerLink {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl Socks5DialerLink {
    fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
        let host = parsed
            .host_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing SOCKS5 host".to_owned(),
            })?
            .to_owned();
        let port = parsed
            .port()
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing SOCKS5 port".to_owned(),
            })?;
        Ok(Self {
            host,
            port,
            username: (!parsed.username().is_empty()).then(|| parsed.username().to_owned()),
            password: parsed.password().map(ToOwned::to_owned),
        })
    }
}

/// Parsed Shadowsocks outbound proxy endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowsocksDialerLink {
    host: String,
    port: u16,
    normalized_link: String,
}

impl ShadowsocksDialerLink {
    fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
        if !parsed.username().is_empty() && parsed.port().is_none() {
            return Err(TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing Shadowsocks port".to_owned(),
            });
        }
        Self::from_normalized_link(raw, normalize_shadowsocks_link(raw, parsed))
    }

    fn from_parts(
        raw: &str,
        host: &str,
        port: u16,
        method: &str,
        password: &str,
    ) -> Result<Self, TransportError> {
        if host.is_empty() {
            return Err(TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing ShadowsocksR host".to_owned(),
            });
        }
        let userinfo = general_purpose::URL_SAFE_NO_PAD.encode(format!("{method}:{password}"));
        let host = dialer_link_host_authority(host);
        Self::from_normalized_link(raw, format!("ss://{userinfo}@{host}:{port}"))
    }

    fn from_normalized_link(raw: &str, normalized_link: String) -> Result<Self, TransportError> {
        let server_config =
            shadowsocks::config::ServerConfig::from_url(&normalized_link).map_err(|source| {
                TransportError::InvalidProxyDialerLink {
                    link: raw.to_owned(),
                    message: source.to_string(),
                }
            })?;
        if server_config.plugin().is_some() {
            return Err(TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "Shadowsocks plugin dialer_link is not supported".to_owned(),
            });
        }
        let (host, port) = shadowsocks_server_addr_parts(server_config.tcp_external_addr());
        Ok(Self {
            host,
            port,
            normalized_link,
        })
    }

    fn server_config(&self) -> Result<shadowsocks::config::ServerConfig, TransportError> {
        shadowsocks::config::ServerConfig::from_url(&self.normalized_link).map_err(|source| {
            TransportError::InvalidProxyDialerLink {
                link: self.normalized_link.clone(),
                message: source.to_string(),
            }
        })
    }
}

/// Parsed ShadowsocksR outbound proxy endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowsocksRDialerLink {
    host: String,
    port: u16,
    shadowsocks: ShadowsocksDialerLink,
}

impl ShadowsocksRDialerLink {
    fn from_url(raw: &str) -> Result<Self, TransportError> {
        let content =
            raw.strip_prefix("ssr://")
                .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                    link: raw.to_owned(),
                    message: "ShadowsocksR links must use the ssr:// prefix".to_owned(),
                })?;
        let parsed = parse_shadowsocksr_link_content(raw, content)?;
        if parsed.proto != "origin" {
            return Err(TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: format!(
                    "ShadowsocksR protocol {} is not supported; only origin is supported",
                    parsed.proto
                ),
            });
        }
        if parsed.obfs != "plain" {
            return Err(TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: format!(
                    "ShadowsocksR obfs {} is not supported; only plain is supported",
                    parsed.obfs
                ),
            });
        }
        let shadowsocks = ShadowsocksDialerLink::from_parts(
            raw,
            &parsed.host,
            parsed.port,
            &parsed.cipher,
            &parsed.password,
        )?;
        Ok(Self {
            host: shadowsocks.host.clone(),
            port: shadowsocks.port,
            shadowsocks,
        })
    }
}

/// Parsed Trojan outbound proxy endpoint for TCP-over-TLS target dials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanDialerLink {
    host: String,
    port: u16,
    password: String,
    sni: String,
    allow_insecure: bool,
}

impl TrojanDialerLink {
    fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
        let host = parsed
            .host_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing Trojan host".to_owned(),
            })?
            .to_owned();
        let port = parsed
            .port()
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing Trojan port".to_owned(),
            })?;
        let transport_type = parsed
            .query_pairs()
            .find_map(|(key, value)| (key == "type").then(|| value.into_owned()))
            .unwrap_or_default();
        if !transport_type.is_empty() {
            return Err(TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: format!(
                    "Trojan transport type {transport_type} is not supported; only TCP over TLS is supported"
                ),
            });
        }
        let encryption = parsed
            .query_pairs()
            .find_map(|(key, value)| (key == "encryption").then(|| value.into_owned()))
            .unwrap_or_default();
        if !encryption.is_empty() {
            return Err(TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "Trojan encryption plugins are not supported".to_owned(),
            });
        }
        let password = percent_decode_utf8(raw, parsed.username(), "Trojan password")?;
        let sni = parsed
            .query_pairs()
            .find_map(|(key, value)| {
                matches!(key.as_ref(), "peer" | "sni").then(|| value.into_owned())
            })
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| host.clone());
        Ok(Self {
            host,
            port,
            password,
            sni,
            allow_insecure: http_connect_allow_insecure(parsed),
        })
    }
}

/// Parsed Juicity outbound proxy endpoint for TCP-over-QUIC target dials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityDialerLink {
    host: String,
    port: u16,
    uuid: uuid::Uuid,
    password: String,
    sni: String,
    allow_insecure: bool,
    congestion_control: String,
    pinned_cert_chain_sha256: Option<Vec<u8>>,
}

impl JuicityDialerLink {
    fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
        let host = parsed
            .host_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing Juicity host".to_owned(),
            })?
            .to_owned();
        let port = parsed
            .port()
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing Juicity port".to_owned(),
            })?;
        let raw_uuid = percent_decode_utf8(raw, parsed.username(), "Juicity UUID")?;
        let uuid = uuid::Uuid::parse_str(&raw_uuid).map_err(|source| {
            TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: format!("parse Juicity UUID: {source}"),
            }
        })?;
        let password = match parsed.password() {
            Some(password) => percent_decode_utf8(raw, password, "Juicity password")?,
            None => String::new(),
        };
        let sni = dialer_link_query_value(parsed, "peer")
            .or_else(|| dialer_link_query_value(parsed, "sni"))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| host.clone());
        let pinned_cert_chain_sha256 = dialer_link_query_value(parsed, "pinned_certchain_sha256")
            .filter(|value| !value.is_empty())
            .map(|value| decode_juicity_pinned_cert_chain_sha256(raw, &value))
            .transpose()?;
        Ok(Self {
            host,
            port,
            uuid,
            password,
            sni,
            allow_insecure: http_connect_allow_insecure(parsed),
            congestion_control: dialer_link_query_value(parsed, "congestion_control")
                .unwrap_or_default(),
            pinned_cert_chain_sha256,
        })
    }
}

/// Parsed Hysteria2 outbound proxy endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hysteria2DialerLink {
    host: String,
    port: u16,
    user: String,
    password: String,
    insecure: bool,
    sni: Option<String>,
    pin_sha256: Option<String>,
    max_tx: Option<u64>,
    max_rx: Option<u64>,
}

impl Hysteria2DialerLink {
    fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
        let host = parsed
            .host_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing Hysteria2 host".to_owned(),
            })?
            .to_owned();
        let port = parsed
            .port()
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing Hysteria2 port".to_owned(),
            })?;
        let user = percent_decode_utf8(raw, parsed.username(), "Hysteria2 user")?;
        let password = match parsed.password() {
            Some(password) => percent_decode_utf8(raw, password, "Hysteria2 password")?,
            None => String::new(),
        };
        Ok(Self {
            host,
            port,
            user,
            password,
            insecure: dialer_link_query_bool_strict(raw, parsed, "insecure", "Hysteria2 insecure")?
                .unwrap_or(false),
            sni: dialer_link_query_value(parsed, "sni").filter(|value| !value.is_empty()),
            pin_sha256: dialer_link_query_value(parsed, "pinSHA256")
                .filter(|value| !value.is_empty()),
            max_tx: dialer_link_query_u64(raw, parsed, "maxTx", "Hysteria2 maxTx")?,
            max_rx: dialer_link_query_u64(raw, parsed, "maxRx", "Hysteria2 maxRx")?,
        })
    }
}

/// Parsed TUIC outbound proxy endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuicDialerLink {
    host: String,
    port: u16,
    user: String,
    password: String,
    sni: Option<String>,
    allow_insecure: bool,
    disable_sni: bool,
    congestion_control: Option<String>,
    alpn: Vec<String>,
    udp_relay_mode: Option<String>,
}

impl TuicDialerLink {
    fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
        let host = parsed
            .host_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing TUIC host".to_owned(),
            })?
            .to_owned();
        let port = parsed
            .port()
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing TUIC port".to_owned(),
            })?;
        let user = percent_decode_utf8(raw, parsed.username(), "TUIC user")?;
        let password = match parsed.password() {
            Some(password) => percent_decode_utf8(raw, password, "TUIC password")?,
            None => String::new(),
        };
        let disable_sni = dialer_link_query_value(parsed, "disable_sni")
            .as_deref()
            .is_some_and(dialer_link_query_bool);
        let sni = if disable_sni {
            None
        } else {
            dialer_link_query_value(parsed, "peer")
                .or_else(|| dialer_link_query_value(parsed, "sni"))
                .filter(|value| !value.is_empty())
                .or_else(|| Some(host.clone()))
        };
        let alpn = dialer_link_query_value(parsed, "alpn")
            .map(|value| {
                value
                    .split(',')
                    .filter(|item| !item.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            host,
            port,
            user,
            password,
            sni,
            allow_insecure: http_connect_allow_insecure(parsed) || disable_sni,
            disable_sni,
            congestion_control: dialer_link_query_value(parsed, "congestion_control")
                .filter(|value| !value.is_empty()),
            alpn,
            udp_relay_mode: dialer_link_query_value(parsed, "udp_relay_mode")
                .filter(|value| !value.is_empty()),
        })
    }
}

/// Parsed VMess outbound proxy endpoint for AEAD plain TCP target dials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmessDialerLink {
    host: String,
    port: u16,
    id: String,
    key: [u8; 16],
    cmd_key: [u8; 16],
}

#[derive(Debug, Default, serde::Deserialize)]
struct VmessJsonLink {
    #[serde(default)]
    add: String,
    #[serde(default)]
    port: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    aid: String,
    #[serde(default)]
    net: String,
    #[serde(default, rename = "type")]
    header_type: String,
    #[serde(default)]
    tls: String,
}

impl VmessDialerLink {
    fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
        let link = parse_vmess_link(raw, parsed)?;
        let key = vless_user_to_key(raw, &link.id)?;
        let cmd_key = vmess_cmd_key(&key);
        Ok(Self {
            host: link.host,
            port: link.port,
            id: link.id,
            key,
            cmd_key,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedVmessDialerLink {
    host: String,
    port: u16,
    id: String,
}

fn parse_vmess_link(raw: &str, parsed: &url::Url) -> Result<ParsedVmessDialerLink, TransportError> {
    let payload =
        raw.strip_prefix("vmess://")
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing VMess payload".to_owned(),
            })?;
    let payload = payload
        .split_once('?')
        .map_or(payload, |(payload, _)| payload);
    let decoded = decode_vmess_base64(raw, payload)?;
    match serde_json::from_slice::<VmessJsonLink>(&decoded) {
        Ok(json) => parsed_vmess_json(raw, json),
        Err(_) => parse_vmess_raw_link(raw, parsed, &decoded),
    }
}

fn parsed_vmess_json(
    raw: &str,
    json: VmessJsonLink,
) -> Result<ParsedVmessDialerLink, TransportError> {
    let aid = if json.aid.is_empty() {
        "0"
    } else {
        json.aid.as_str()
    };
    if aid != "0" {
        return Err(TransportError::InvalidProxyDialerLink {
            link: raw.to_owned(),
            message: format!(
                "VMess alterId {aid} is not supported; only AEAD alterId 0 is supported"
            ),
        });
    }
    let net = if json.net.is_empty() {
        "tcp"
    } else {
        json.net.as_str()
    };
    if net != "tcp" {
        return Err(TransportError::InvalidProxyDialerLink {
            link: raw.to_owned(),
            message: format!(
                "VMess transport network {net} is not supported; only plain TCP is supported"
            ),
        });
    }
    if !matches!(json.header_type.as_str(), "" | "none") {
        return Err(TransportError::InvalidProxyDialerLink {
            link: raw.to_owned(),
            message: format!(
                "VMess TCP header type {} is not supported; only none is supported",
                json.header_type
            ),
        });
    }
    if !matches!(json.tls.as_str(), "" | "none") {
        return Err(TransportError::InvalidProxyDialerLink {
            link: raw.to_owned(),
            message: format!(
                "VMess TLS mode {} is not supported in this plain-TCP slice",
                json.tls
            ),
        });
    }
    let port =
        json.port
            .parse::<u16>()
            .map_err(|source| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: format!("invalid VMess port: {source}"),
            })?;
    if json.add.is_empty() {
        return Err(TransportError::InvalidProxyDialerLink {
            link: raw.to_owned(),
            message: "missing VMess host".to_owned(),
        });
    }
    if json.id.is_empty() {
        return Err(TransportError::InvalidProxyDialerLink {
            link: raw.to_owned(),
            message: "missing VMess id".to_owned(),
        });
    }
    Ok(ParsedVmessDialerLink {
        host: json.add,
        port,
        id: json.id,
    })
}

fn parse_vmess_raw_link(
    raw: &str,
    parsed: &url::Url,
    decoded: &[u8],
) -> Result<ParsedVmessDialerLink, TransportError> {
    let decoded =
        std::str::from_utf8(decoded).map_err(|source| TransportError::InvalidProxyDialerLink {
            link: raw.to_owned(),
            message: format!("invalid VMess raw payload: {source}"),
        })?;
    let (security_and_id, address) =
        decoded
            .rsplit_once('@')
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "unrecognized VMess raw address".to_owned(),
            })?;
    let (_, id) =
        security_and_id
            .split_once(':')
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "unrecognized VMess raw credential".to_owned(),
            })?;
    let (host, port) =
        address
            .rsplit_once(':')
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing VMess raw port".to_owned(),
            })?;
    let port = port
        .parse::<u16>()
        .map_err(|source| TransportError::InvalidProxyDialerLink {
            link: raw.to_owned(),
            message: format!("invalid VMess port: {source}"),
        })?;
    let query = parsed.query_pairs().collect::<Vec<_>>();
    let net = query
        .iter()
        .find_map(|(key, value)| (key == "obfs").then(|| value.as_ref()))
        .unwrap_or("tcp");
    if net != "tcp" && !net.is_empty() {
        return Err(TransportError::InvalidProxyDialerLink {
            link: raw.to_owned(),
            message: format!(
                "VMess transport network {net} is not supported; only plain TCP is supported"
            ),
        });
    }
    let tls = query
        .iter()
        .find_map(|(key, value)| (key == "tls").then(|| value.as_ref()))
        .unwrap_or("");
    if tls == "1" || tls == "tls" {
        return Err(TransportError::InvalidProxyDialerLink {
            link: raw.to_owned(),
            message: "VMess TLS raw links require a separate transport slice".to_owned(),
        });
    }
    let aid = query
        .iter()
        .find_map(|(key, value)| matches!(key.as_ref(), "alterId" | "aid").then(|| value.as_ref()))
        .unwrap_or("0");
    if !aid.is_empty() && aid != "0" {
        return Err(TransportError::InvalidProxyDialerLink {
            link: raw.to_owned(),
            message: format!(
                "VMess alterId {aid} is not supported; only AEAD alterId 0 is supported"
            ),
        });
    }
    Ok(ParsedVmessDialerLink {
        host: host.to_owned(),
        port,
        id: id.to_owned(),
    })
}

fn decode_vmess_base64(raw: &str, value: &str) -> Result<Vec<u8>, TransportError> {
    decode_padded_base64_bytes(&general_purpose::STANDARD, value)
        .or_else(|_| decode_padded_base64_bytes(&general_purpose::URL_SAFE, value))
        .map_err(|source| TransportError::InvalidProxyDialerLink {
            link: raw.to_owned(),
            message: format!("invalid VMess base64 payload: {source}"),
        })
}

/// Parsed VLESS outbound proxy endpoint for plain TCP target dials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessDialerLink {
    host: String,
    port: u16,
    user: String,
    key: [u8; 16],
}

impl VlessDialerLink {
    fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
        let host = parsed
            .host_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing VLESS host".to_owned(),
            })?
            .to_owned();
        let port = parsed
            .port()
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing VLESS port".to_owned(),
            })?;
        let transport_type = dialer_link_query_value(parsed, "type")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "tcp".to_owned());
        if transport_type != "tcp" {
            return Err(TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: format!(
                    "VLESS transport type {transport_type} is not supported; only plain TCP is supported"
                ),
            });
        }
        let header_type = dialer_link_query_value(parsed, "headerType")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "none".to_owned());
        if header_type != "none" {
            return Err(TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: format!(
                    "VLESS header type {header_type} is not supported; only none is supported"
                ),
            });
        }
        let security = dialer_link_query_value(parsed, "security")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "none".to_owned());
        if security != "none" {
            return Err(TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: format!(
                    "VLESS security {security} is not supported; only plain TCP without TLS or Reality is supported"
                ),
            });
        }
        let flow = dialer_link_query_value(parsed, "flow").unwrap_or_default();
        if !flow.is_empty() {
            return Err(TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: format!(
                    "VLESS flow {flow} is not supported; XTLS/Vision requires a separate slice"
                ),
            });
        }
        let user = percent_decode_utf8(raw, parsed.username(), "VLESS user")?;
        let key = vless_user_to_key(raw, &user)?;
        Ok(Self {
            host,
            port,
            user,
            key,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedShadowsocksRLink {
    host: String,
    port: u16,
    proto: String,
    cipher: String,
    obfs: String,
    password: String,
}

fn vless_user_to_key(raw: &str, user: &str) -> Result<[u8; 16], TransportError> {
    if user.len() < 32 || user.len() > 36 {
        return Ok(vless_uuid5_key(user));
    }
    let compact = user.replace('-', "");
    if compact.len() != 32 {
        return Err(TransportError::InvalidProxyDialerLink {
            link: raw.to_owned(),
            message: format!("invalid VLESS UUID: {compact}"),
        });
    }
    let mut key = [0_u8; 16];
    for index in 0..16 {
        let start = index * 2;
        key[index] = u8::from_str_radix(&compact[start..start + 2], 16).map_err(|source| {
            TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: format!("invalid VLESS UUID: {source}"),
            }
        })?;
    }
    Ok(key)
}

fn vless_uuid5_key(value: &str) -> [u8; 16] {
    let mut hasher = Sha1::new();
    sha2::Digest::update(&mut hasher, [0_u8; 16]);
    sha2::Digest::update(&mut hasher, value.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0_u8; 16];
    key.copy_from_slice(&digest[..16]);
    key[6] = (key[6] & 0x0f) | (5 << 4);
    key[8] = (key[8] & (0xff >> 2)) | (0x02 << 6);
    key
}

fn parse_shadowsocksr_link_content(
    raw: &str,
    content: &str,
) -> Result<ParsedShadowsocksRLink, TransportError> {
    if let Ok(parsed) = parse_shadowsocksr_plain_content(raw, content) {
        return Ok(parsed);
    }
    let decoded = decode_shadowsocksr_outer_content(raw, content)?;
    parse_shadowsocksr_plain_content(raw, &decoded)
}

fn parse_shadowsocksr_plain_content(
    raw: &str,
    content: &str,
) -> Result<ParsedShadowsocksRLink, TransportError> {
    let owned_content;
    let content = if content.contains(':') && !content.contains("/?") {
        owned_content = format!("{content}/?remarks=&protoparam=&obfsparam=");
        owned_content.as_str()
    } else {
        content
    };
    let (pre, query) =
        content
            .split_once("/?")
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "unrecognized ShadowsocksR address".to_owned(),
            })?;
    let _ = url::form_urlencoded::parse(query.as_bytes()).count();
    let mut fields = pre.split(':').map(str::to_owned).collect::<Vec<_>>();
    if fields.len() > 6 {
        let host_end = fields.len() - 5;
        let host = fields[..host_end].join(":");
        let mut collapsed = Vec::with_capacity(6);
        collapsed.push(host);
        collapsed.extend(fields[host_end..].iter().cloned());
        fields = collapsed;
    } else if fields.len() < 6 {
        return Err(TransportError::InvalidProxyDialerLink {
            link: raw.to_owned(),
            message: "unrecognized ShadowsocksR address".to_owned(),
        });
    }
    let port =
        fields[1]
            .parse::<u16>()
            .map_err(|source| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: source.to_string(),
            })?;
    Ok(ParsedShadowsocksRLink {
        host: decode_shadowsocksr_field(&fields[0]),
        port,
        proto: fields[2].clone(),
        cipher: fields[3].clone(),
        obfs: fields[4].clone(),
        password: decode_shadowsocksr_field(&fields[5]),
    })
}

fn decode_shadowsocksr_field(value: &str) -> String {
    let trimmed = value.trim();
    decode_padded_base64_bytes(&general_purpose::URL_SAFE, trimmed)
        .ok()
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .unwrap_or_else(|| trimmed.to_owned())
}

fn decode_shadowsocksr_outer_content(raw: &str, content: &str) -> Result<String, TransportError> {
    match decode_padded_base64_string(&general_purpose::STANDARD, content) {
        Ok(decoded) => Ok(decoded),
        Err(standard_error) => decode_padded_base64_string(&general_purpose::URL_SAFE, content)
            .map_err(|url_error| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: format!(
                    "invalid ShadowsocksR base64 payload: {standard_error}; {url_error}"
                ),
            }),
    }
}

fn percent_decode_utf8(
    raw: &str,
    value: &str,
    field: &'static str,
) -> Result<String, TransportError> {
    let bytes = percent_decode_bytes(raw, value, field)?;
    String::from_utf8(bytes).map_err(|source| TransportError::InvalidProxyDialerLink {
        link: raw.to_owned(),
        message: format!("invalid {field}: {source}"),
    })
}

fn dialer_link_query_value(parsed: &url::Url, name: &str) -> Option<String> {
    parsed
        .query_pairs()
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
}

fn decode_juicity_pinned_cert_chain_sha256(
    raw: &str,
    value: &str,
) -> Result<Vec<u8>, TransportError> {
    general_purpose::URL_SAFE
        .decode(value)
        .or_else(|_| general_purpose::STANDARD.decode(value))
        .or_else(|_| decode_hex_bytes(value))
        .map_err(|source| TransportError::InvalidProxyDialerLink {
            link: raw.to_owned(),
            message: format!("failed to decode Juicity pinned_certchain_sha256: {source}"),
        })
}

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    if !value.len().is_multiple_of(2) {
        return Err(base64::DecodeError::InvalidLength(value.len()));
    }
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(chunk)
            .map_err(|_| base64::DecodeError::InvalidByte(0, chunk[0]))?;
        let byte = u8::from_str_radix(text, 16)
            .map_err(|_| base64::DecodeError::InvalidByte(0, chunk[0]))?;
        decoded.push(byte);
    }
    Ok(decoded)
}

fn percent_decode_bytes(
    raw: &str,
    value: &str,
    field: &'static str,
) -> Result<Vec<u8>, TransportError> {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(hex) = bytes.get(index + 1..index + 3) else {
                return Err(TransportError::InvalidProxyDialerLink {
                    link: raw.to_owned(),
                    message: format!("invalid percent escape in {field}"),
                });
            };
            let hex = std::str::from_utf8(hex).map_err(|source| {
                TransportError::InvalidProxyDialerLink {
                    link: raw.to_owned(),
                    message: format!("invalid percent escape in {field}: {source}"),
                }
            })?;
            let byte = u8::from_str_radix(hex, 16).map_err(|source| {
                TransportError::InvalidProxyDialerLink {
                    link: raw.to_owned(),
                    message: format!("invalid percent escape in {field}: {source}"),
                }
            })?;
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Ok(decoded)
}

fn decode_padded_base64_string<E>(engine: &E, value: &str) -> Result<String, String>
where
    E: Engine + ?Sized,
{
    let decoded = decode_padded_base64_bytes(engine, value).map_err(|source| source.to_string())?;
    String::from_utf8(decoded).map_err(|source| source.to_string())
}

fn decode_padded_base64_bytes<E>(engine: &E, value: &str) -> Result<Vec<u8>, base64::DecodeError>
where
    E: Engine + ?Sized,
{
    let trimmed = value.trim();
    let mut padded = trimmed.to_owned();
    let padding = trimmed.len() % 4;
    if padding != 0 {
        padded.extend(std::iter::repeat_n('=', 4 - padding));
    }
    engine.decode(padded)
}

fn dialer_link_host_authority(host: &str) -> String {
    if host.starts_with('[') || !host.contains(':') {
        host.to_owned()
    } else {
        format!("[{host}]")
    }
}

fn dialer_link_query_bool(value: &str) -> bool {
    value.parse::<bool>().unwrap_or(value == "1")
}

fn dialer_link_query_bool_strict(
    raw: &str,
    parsed: &url::Url,
    name: &str,
    field: &'static str,
) -> Result<Option<bool>, TransportError> {
    let Some(value) = dialer_link_query_value(parsed, name) else {
        return Ok(None);
    };
    match value.as_str() {
        "true" | "1" => Ok(Some(true)),
        "false" | "0" => Ok(Some(false)),
        _ => Err(TransportError::InvalidProxyDialerLink {
            link: raw.to_owned(),
            message: format!("invalid {field}: {value}"),
        }),
    }
}

fn dialer_link_query_u64(
    raw: &str,
    parsed: &url::Url,
    name: &str,
    field: &'static str,
) -> Result<Option<u64>, TransportError> {
    dialer_link_query_value(parsed, name)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|source| TransportError::InvalidProxyDialerLink {
                    link: raw.to_owned(),
                    message: format!("invalid {field}: {source}"),
                })
        })
        .transpose()
}

fn normalize_shadowsocks_link(raw: &str, parsed: &url::Url) -> String {
    if parsed.scheme().eq_ignore_ascii_case("shadowsocks") {
        let Some((_, rest)) = raw.split_once(':') else {
            return raw.to_owned();
        };
        format!("ss:{rest}")
    } else {
        raw.to_owned()
    }
}

fn shadowsocks_server_addr_parts(addr: &shadowsocks::config::ServerAddr) -> (String, u16) {
    match addr {
        shadowsocks::config::ServerAddr::SocketAddr(address) => {
            (address.ip().to_string(), address.port())
        }
        shadowsocks::config::ServerAddr::DomainName(domain, port) => (domain.clone(), *port),
    }
}

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
    inner: quinn::TransportConfig,
    policy: QuicRuntimePolicy,
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

/// Selects whether the adaptive UDP socket may attempt Linux UDP GSO
/// (`UDP_SEGMENT`) on eligible egress, or always falls back to one datagram per
/// segment (the historical safe behaviour).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GsoMode {
    /// Never attempt GSO; send one datagram per segment. Always safe.
    Off,
    /// Attempt GSO on eligible short-header batched transmits, with per-message
    /// `UDP_SEGMENT` cmsg and same-call fallback to plain datagrams on the first
    /// `EINVAL`/`EIO` from a destination. Default in production.
    Auto,
}

impl GsoMode {
    /// Linux caps a single `UDP_SEGMENT` transmit at 64 datagrams
    /// (`UDP_MAX_SEGMENTS = 1 << 6`).
    const MAX_GSO_SEGMENTS: usize = 64;

    /// Resolves the production GSO mode from the environment, mirroring Go
    /// quic-go's `QUIC_GO_DISABLE_GSO`. `ZUICITY_DISABLE_GSO=1` (or `true`)
    /// forces [`GsoMode::Off`]; anything else (including unset) is
    /// [`GsoMode::Auto`]. On non-Linux targets GSO is always [`GsoMode::Off`].
    #[must_use]
    pub fn from_env() -> Self {
        if !cfg!(target_os = "linux") {
            return Self::Off;
        }
        match std::env::var("ZUICITY_DISABLE_GSO") {
            Ok(value) => {
                let value = value.trim();
                if value == "1" || value.eq_ignore_ascii_case("true") {
                    Self::Off
                } else {
                    Self::Auto
                }
            }
            Err(_) => Self::Auto,
        }
    }

    /// Maximum number of datagrams quinn may pack into one [`quinn::udp::Transmit`].
    const fn max_transmit_segments(self) -> usize {
        match self {
            Self::Off => 1,
            Self::Auto => Self::MAX_GSO_SEGMENTS,
        }
    }
}

/// Selects whether the adaptive UDP socket enables Linux UDP GRO
/// (`UDP_GRO`) on the receive path, coalescing several same-sized datagrams
/// into one `recvmsg` and splitting the super-buffer back into segments via the
/// kernel-reported `gso_size`, or always receives one datagram per `recvmsg`
/// (the historical safe behaviour).
///
/// GRO is wire-invisible: it changes only how the *local* kernel batches
/// already-received datagrams up to userspace. It enables exactly one extra
/// receive-side socket option (`UDP_GRO`); it never touches ECN
/// (`IP_RECVTOS`/`IP_TOS`), PMTUDISC (`IP_MTU_DISCOVER`), or `IP_PKTINFO`, so
/// the cross-host reliability profile of the plain receive path is preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroMode {
    /// Never enable GRO; receive one datagram per `recvmsg`. Always safe.
    Off,
    /// Enable `UDP_GRO` on the receive socket and split coalesced super-buffers
    /// by the kernel-reported segment size. Default in production on Linux.
    Auto,
}

impl GroMode {
    /// Linux caps GRO coalescing at `UDP_GRO_CNT_MAX = 64` segments per
    /// `recvmsg`. The receive buffer quinn allocates per slot is sized as
    /// `max_udp_payload_size * max_receive_segments()`, so this also bounds the
    /// per-slot buffer growth.
    const MAX_GRO_SEGMENTS: usize = 64;

    /// Resolves the production GRO mode from the environment, mirroring
    /// [`GsoMode::from_env`]. `ZUICITY_DISABLE_GRO=1` (or `true`) forces
    /// [`GroMode::Off`]; anything else (including unset) is [`GroMode::Auto`].
    /// On non-Linux targets GRO is always [`GroMode::Off`].
    #[must_use]
    pub fn from_env() -> Self {
        if !cfg!(target_os = "linux") {
            return Self::Off;
        }
        match std::env::var("ZUICITY_DISABLE_GRO") {
            Ok(value) => {
                let value = value.trim();
                if value == "1" || value.eq_ignore_ascii_case("true") {
                    Self::Off
                } else {
                    Self::Auto
                }
            }
            Err(_) => Self::Auto,
        }
    }

    /// Maximum number of datagrams a single [`quinn::udp::RecvMeta`] may
    /// describe. quinn uses this to size each receive buffer slot
    /// (`max_udp_payload_size * max_receive_segments`); it must be `> 1` for GRO
    /// coalescing to have room to land, and `1` keeps the historical per-slot
    /// buffer size when GRO is off.
    const fn max_receive_segments(self) -> usize {
        match self {
            Self::Off => 1,
            Self::Auto => Self::MAX_GRO_SEGMENTS,
        }
    }
}

/// Per-destination GSO capability learned at runtime. One hostile egress path
/// must not disable GSO for unrelated peers, so this is tracked per
/// destination [`SocketAddr`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GsoDestState {
    /// No GSO send has been attempted to this destination yet.
    Unknown,
    /// A GSO send to this destination has succeeded.
    Working,
    /// A GSO send to this destination failed with `EINVAL`/`EIO`; fall back to
    /// plain datagrams for this destination from now on.
    Disabled,
}

/// Counters for the adaptive GSO send path. Exposed as atomics so tests can
/// assert on engagement and fallback behaviour without scraping logs.
#[derive(Debug, Default)]
struct GsoCounters {
    /// GSO `sendmsg` attempts (eligible batched short-header transmits).
    attempt: AtomicCounter64,
    /// GSO `sendmsg` attempts that succeeded.
    success: AtomicCounter64,
    /// GSO `sendmsg` attempts that failed with `EINVAL`/`EIO`.
    fallback: AtomicCounter64,
    /// Plain chunked sends performed after a GSO fallback for a destination.
    plain_after_fallback: AtomicCounter64,
    /// GSO attempts that involved a long-header packet. Must always stay zero:
    /// the long-header guard routes Initial/Handshake packets to the plain path
    /// before any GSO attempt, so this is a tripwire for that invariant.
    long_header_gso_attempt: AtomicCounter64,
}

/// Counters for the GRO receive path. Exposed as atomics so tests can assert
/// that coalescing actually engaged without scraping logs.
#[derive(Debug, Default)]
struct GroCounters {
    /// `recvmsg` calls that returned a coalesced super-buffer (the kernel
    /// `UDP_GRO` cmsg reported a stride smaller than the received length, i.e.
    /// more than one datagram in a single read).
    gro_coalesced_recv: AtomicCounter64,
    /// Total datagrams delivered across all coalesced reads (sum of segment
    /// counts), so a test can confirm GRO carried real volume.
    gro_segments_total: AtomicCounter64,
}

/// Shared GRO receiver. `Some` only when GRO is enabled and the kernel/path
/// supports it; the `recv` it exposes parses the `UDP_GRO` segment-size cmsg.
/// `None` means the receive path is the plain per-datagram one.
type GroReceiver = Option<Arc<quinn::udp::UdpSocketState>>;

/// Test hook to force GSO `sendmsg` failures deterministically. Only present
/// in test builds; production has no hook and always attempts a real send.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GsoTestHook {
    /// No forced failures; behave normally.
    None,
    /// Force the first GSO attempt to any destination to fail with `EINVAL`.
    FirstEinval,
    /// Force every GSO attempt to fail with `EINVAL`.
    AlwaysEinval,
}

/// An adaptive tokio-only UDP socket for quinn.
///
/// The receive path is deliberately plain: no GRO, no ECN, no PMTUDISC. quinn's
/// default socket configures `UDP_GRO`, `IP_TOS` (ECN), and
/// `IP_MTU_DISCOVER=PROBE` plus per-packet receive control messages; several
/// network paths (veth/netns, tun/VPN, virtio, some cloud NICs) reject those
/// with `EINVAL`, stranding the QUIC handshake and timing out the connection —
/// invisible on loopback but fatal cross-host.
///
/// The send path is adaptive. In [`GsoMode::Auto`] eligible *batched
/// short-header* transmits attempt one `sendmsg` carrying a per-message
/// `UDP_SEGMENT` control message (never a persistent socket-level option, which
/// is the quinn-rs/quinn#2575 trap). Long-header packets (QUIC Initial /
/// Handshake, first byte `& 0x80 != 0`) are *never* segmented, so the handshake
/// always crosses GSO-hostile paths. On the first `EINVAL`/`EIO` from a
/// destination the socket marks that destination disabled and immediately
/// resends the same contents as plain datagrams in the same call, so no packet
/// is dropped. In [`GsoMode::Off`] every transmit is sent one datagram per
/// segment, matching the historical safe behaviour and upstream Go quic-go.
struct PlainUdpSocket {
    io: tokio::net::UdpSocket,
    /// GSO mode for this socket.
    mode: GsoMode,
    /// GRO mode for this socket's receive path.
    gro_mode: GroMode,
    /// The GRO receiver, `Some` only when `UDP_GRO` was successfully enabled on
    /// the real socket. Only then does [`poll_recv`] take the GRO batched path
    /// that parses the kernel segment-size cmsg; on a GRO-hostile path setup
    /// fails, this stays `None`, and the plain per-datagram path is used
    /// unchanged. It carries no per-socket fd (its `recv` takes the target fd as
    /// an argument), so it is safe to share by [`Arc`].
    ///
    /// [`poll_recv`]: PlainUdpSocket::poll_recv
    gro_recv: GroReceiver,
    /// Per-destination learned GSO capability.
    gso_state: Mutex<HashMap<SocketAddr, GsoDestState>>,
    /// Send-path counters, shareable with tests.
    counters: Arc<GsoCounters>,
    /// Receive-path GRO counters, shareable with tests.
    gro_counters: Arc<GroCounters>,
    /// Shared sender used only to emit the per-message `UDP_SEGMENT` cmsg via
    /// `sendmsg` on this socket's fd. Built from a throwaway socket so it never
    /// mutates the receive options of the real socket. Linux-only.
    #[cfg(target_os = "linux")]
    gso_sender: Option<Arc<quinn::udp::UdpSocketState>>,
    /// Test hook forcing GSO failures. Present only in test builds.
    #[cfg(test)]
    test_hook: GsoTestHook,
}

impl fmt::Debug for PlainUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlainUdpSocket")
            .field("mode", &self.mode)
            .field("gro_mode", &self.gro_mode)
            .field("gro_active", &self.gro_recv.is_some())
            .finish_non_exhaustive()
    }
}

impl PlainUdpSocket {
    /// Builds a socket using the production GSO mode resolved from the
    /// environment ([`GsoMode::from_env`]).
    fn new(socket: std::net::UdpSocket) -> std::io::Result<Self> {
        let mode = GsoMode::from_env();
        let gro_mode = GroMode::from_env();
        let (io, gro_recv) = Self::prepare_io(socket, gro_mode)?;
        #[cfg(target_os = "linux")]
        let gso_sender = Self::build_sender_for(mode);
        Ok(Self {
            io,
            mode,
            gro_mode,
            gro_recv,
            gso_state: Mutex::new(HashMap::new()),
            counters: Arc::new(GsoCounters::default()),
            gro_counters: Arc::new(GroCounters::default()),
            #[cfg(target_os = "linux")]
            gso_sender,
            #[cfg(test)]
            test_hook: GsoTestHook::None,
        })
    }

    /// Builds a socket with an explicit GSO mode and failure hook (used by tests).
    /// The GRO mode is resolved from the environment, matching production.
    #[cfg(test)]
    fn with_mode_and_hook(
        socket: std::net::UdpSocket,
        mode: GsoMode,
        test_hook: GsoTestHook,
    ) -> std::io::Result<Self> {
        Self::with_modes_and_hook(socket, mode, GroMode::from_env(), test_hook)
    }

    /// Builds a socket with explicit GSO and GRO modes and a failure hook (used
    /// by GRO tests that pin the receive-path mode independently of the env).
    #[cfg(test)]
    fn with_modes_and_hook(
        socket: std::net::UdpSocket,
        mode: GsoMode,
        gro_mode: GroMode,
        test_hook: GsoTestHook,
    ) -> std::io::Result<Self> {
        let (io, gro_recv) = Self::prepare_io(socket, gro_mode)?;
        #[cfg(target_os = "linux")]
        let gso_sender = Self::build_sender_for(mode);
        Ok(Self {
            io,
            mode,
            gro_mode,
            gro_recv,
            gso_state: Mutex::new(HashMap::new()),
            counters: Arc::new(GsoCounters::default()),
            gro_counters: Arc::new(GroCounters::default()),
            #[cfg(target_os = "linux")]
            gso_sender,
            test_hook,
        })
    }

    fn prepare_io(
        socket: std::net::UdpSocket,
        gro_mode: GroMode,
    ) -> std::io::Result<(tokio::net::UdpSocket, GroReceiver)> {
        socket.set_nonblocking(true)?;
        Self::configure_socket_buffers(&socket);
        let gro_recv = Self::build_gro_receiver(&socket, gro_mode);
        let io = tokio::net::UdpSocket::from_std(socket)?;
        Ok((io, gro_recv))
    }

    /// Requests a 4 MiB send and receive socket buffer, then reads back the
    /// effective sizes with `getsockopt` and logs them. The kernel silently
    /// clamps `SO_SNDBUF`/`SO_RCVBUF` to `net.core.wmem_max`/`net.core.rmem_max`
    /// (and doubles the stored value for bookkeeping), so the requested value is
    /// not the applied value; only the read-back is authoritative. A bigger
    /// receive buffer reduces drops under bursty GRO batches; a bigger send
    /// buffer lets quinn keep more in flight. Failures here are non-fatal: the
    /// socket simply keeps its default buffer sizes.
    fn configure_socket_buffers(socket: &std::net::UdpSocket) {
        const TARGET_BYTES: usize = 4 * 1024 * 1024;
        let socket = socket2::SockRef::from(socket);
        if let Err(error) = socket.set_recv_buffer_size(TARGET_BYTES) {
            tracing::debug!(%error, "udp set_recv_buffer_size failed; keeping default");
        }
        if let Err(error) = socket.set_send_buffer_size(TARGET_BYTES) {
            tracing::debug!(%error, "udp set_send_buffer_size failed; keeping default");
        }
        let applied_recv = socket.recv_buffer_size().unwrap_or(0);
        let applied_send = socket.send_buffer_size().unwrap_or(0);
        tracing::debug!(
            requested = TARGET_BYTES,
            applied_recv,
            applied_send,
            "udp socket buffers sized; kernel clamps to net.core rmem_max/wmem_max"
        );
    }

    /// Builds the GRO receiver for the real socket when GRO is in
    /// [`GroMode::Auto`]. It constructs a [`quinn::udp::UdpSocketState`] on the
    /// socket, which enables `UDP_GRO` and gives a `recv` that parses the GRO
    /// segment-size cmsg correctly (the unsafe `recvmsg`/cmsg work lives inside
    /// quinn-udp, so this crate stays `forbid(unsafe_code)`).
    ///
    /// If `UdpSocketState::new` fails — which is how GRO-hostile paths surface,
    /// since it also probes other receive options — the error is swallowed and
    /// `None` is returned, so [`poll_recv`] falls back to the historical plain
    /// per-datagram path and the cross-host handshake is never stranded. The ECN
    /// and dst-ip values quinn would parse are discarded in [`recv_gro_batch`],
    /// so this path stays wire- and reliability-equivalent to the plain one.
    ///
    /// [`poll_recv`]: PlainUdpSocket::poll_recv
    /// [`recv_gro_batch`]: PlainUdpSocket::recv_gro_batch
    #[cfg(target_os = "linux")]
    fn build_gro_receiver(socket: &std::net::UdpSocket, gro_mode: GroMode) -> GroReceiver {
        if !matches!(gro_mode, GroMode::Auto) {
            return None;
        }
        match quinn::udp::UdpSocketState::new(socket.into()) {
            Ok(state) if state.gro_segments() > 1 => {
                tracing::debug!(
                    gro_segments = state.gro_segments(),
                    "udp gro enabled on receive socket"
                );
                Some(Arc::new(state))
            }
            Ok(_) => {
                tracing::debug!("udp gro reports a single segment; receiving plain datagrams");
                None
            }
            Err(error) => {
                tracing::debug!(%error, "udp gro setup rejected by this path; receiving plain datagrams");
                None
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn build_gro_receiver(_socket: &std::net::UdpSocket, _gro_mode: GroMode) -> GroReceiver {
        None
    }

    // Build the per-message GSO sender from a throwaway socket so quinn-udp's
    // receive-path socket options (GRO, IP_TOS, IP_MTU_DISCOVER=PROBE,
    // IP_PKTINFO) land on the throwaway, never on the real socket. `try_send`
    // takes the target fd as a separate argument, so the real socket only ever
    // sees the per-message `UDP_SEGMENT` cmsg.
    #[cfg(target_os = "linux")]
    fn build_sender_for(mode: GsoMode) -> Option<Arc<quinn::udp::UdpSocketState>> {
        if matches!(mode, GsoMode::Auto) {
            build_gso_sender()
        } else {
            None
        }
    }

    /// Returns a shared handle to the send-path counters (used by tests).
    #[cfg(test)]
    fn counters(&self) -> Arc<GsoCounters> {
        Arc::clone(&self.counters)
    }

    /// Returns a shared handle to the receive-path GRO counters (used by tests).
    #[cfg(test)]
    fn gro_counters(&self) -> Arc<GroCounters> {
        Arc::clone(&self.gro_counters)
    }

    /// Returns the learned GSO state for a destination (used by tests).
    #[cfg(test)]
    fn gso_dest_state(&self, dest: SocketAddr) -> GsoDestState {
        self.gso_state
            .lock()
            .map(|map| map.get(&dest).copied().unwrap_or(GsoDestState::Unknown))
            .unwrap_or(GsoDestState::Unknown)
    }

    fn dest_state(&self, dest: SocketAddr) -> GsoDestState {
        self.gso_state
            .lock()
            .map(|map| map.get(&dest).copied().unwrap_or(GsoDestState::Unknown))
            .unwrap_or(GsoDestState::Disabled)
    }

    fn set_dest_state(&self, dest: SocketAddr, state: GsoDestState) {
        if let Ok(mut map) = self.gso_state.lock() {
            map.insert(dest, state);
        }
    }

    /// Sends `transmit` as plain datagrams, one per segment. Each datagram is
    /// written with a raw nonblocking `sendto` on the socket's fd (via
    /// `socket2`), deliberately bypassing tokio's cached write-readiness: a
    /// freshly registered socket reports `Ready::EMPTY` until the reactor
    /// delivers a writable event, so `UdpSocket::try_send_to`/`try_io` would
    /// short-circuit to a spurious `WouldBlock` without ever issuing the
    /// syscall. The raw send always attempts the syscall, so this path delivers
    /// every datagram when called outside quinn's `poll_writable` loop (e.g.
    /// directly from tests). On a genuine kernel `EAGAIN` (full send buffer) it
    /// returns `WouldBlock` to the caller: quinn then re-arms writable readiness
    /// through [`PlainUdpPoller::poll_writable`] (`poll_send_ready`) and retries
    /// the whole transmit, the documented quinn contract. It never sleeps the
    /// worker thread, so rapid concurrent connects are not starved. This is the
    /// historical safe path used for handshake/long-header packets,
    /// [`GsoMode::Off`], and after a GSO fallback; it never drops a datagram.
    fn send_plain_chunks(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        let segment = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        let socket = socket2::SockRef::from(&self.io);
        let destination = socket2::SockAddr::from(transmit.destination);
        for chunk in transmit.contents.chunks(segment) {
            socket.send_to(chunk, &destination)?;
        }
        Ok(())
    }

    /// Returns true if any segment in this transmit is a QUIC long-header
    /// packet (first byte high bit set), i.e. an Initial/Handshake/0-RTT/Retry
    /// packet that must never be segmented.
    fn has_long_header(transmit: &quinn::udp::Transmit, segment: usize) -> bool {
        transmit
            .contents
            .chunks(segment)
            .any(|chunk| chunk.first().is_some_and(|byte| byte & 0x80 != 0))
    }

    /// Attempts a single GSO `sendmsg` for an eligible batched short-header
    /// transmit. On `EINVAL`/`EIO` (or a forced test failure) returns the error
    /// for the caller to fall back; on `WouldBlock` returns it for quinn to
    /// retry; on success returns `Ok(())`.
    #[cfg(target_os = "linux")]
    fn try_send_gso(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        if let Some(forced) = self.forced_gso_failure() {
            return Err(forced);
        }
        let Some(sender) = self.gso_sender.as_ref() else {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        };
        // `try_send` emits the per-message `UDP_SEGMENT` cmsg on the target fd
        // and returns the raw `sendmsg` error (unlike `send`, which swallows
        // EINVAL/EIO), so we can run our own per-destination fallback.
        sender.try_send((&self.io).into(), transmit)
    }

    #[cfg(not(target_os = "linux"))]
    fn try_send_gso(&self, _transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    /// In test builds, consults the failure hook and returns a forced error
    /// when the hook demands it. Production builds always return `None`.
    #[cfg(all(test, target_os = "linux"))]
    fn forced_gso_failure(&self) -> Option<std::io::Error> {
        match self.test_hook {
            GsoTestHook::AlwaysEinval => Some(std::io::Error::from_raw_os_error(libc::EINVAL)),
            GsoTestHook::FirstEinval => {
                static FIRST_DONE: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                FIRST_DONE
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                    .then(|| std::io::Error::from_raw_os_error(libc::EINVAL))
            }
            GsoTestHook::None => None,
        }
    }

    #[cfg(all(not(test), target_os = "linux"))]
    fn forced_gso_failure(&self) -> Option<std::io::Error> {
        None
    }

    /// GRO batched receive: delegates to [`quinn::udp::UdpSocketState::recv`],
    /// which performs the `recvmsg`/`recvmmsg` and parses the kernel `UDP_GRO`
    /// control message into each [`quinn::udp::RecvMeta::stride`] (the
    /// per-segment size). quinn-proto then re-splits a coalesced super-buffer
    /// into `ceil(len / stride)` segments, so QUIC decode stays correct — the
    /// reason a coalesced buffer must never be handed over with `stride == len`.
    ///
    /// quinn's parser also fills `ecn` and `dst_ip` from their cmsgs; both are
    /// forced back to `None` here so this receive path stays wire- and
    /// reliability-equivalent to the plain path (no ECN feedback on the wire, no
    /// per-packet destination tracking). The send path is untouched and remains
    /// the adaptive GSO path. Only the GRO segment size is taken from quinn.
    ///
    /// Returns the number of [`quinn::udp::RecvMeta`] slots filled, and tallies
    /// coalescing (`stride < len`) into the GRO counters for test evidence.
    #[cfg(target_os = "linux")]
    fn recv_gro_batch(
        &self,
        gro_recv: &quinn::udp::UdpSocketState,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> std::io::Result<usize> {
        let filled = gro_recv.recv((&self.io).into(), bufs, meta)?;
        for slot in meta.iter_mut().take(filled) {
            if slot.stride > 0 && slot.stride < slot.len {
                let segments = slot.len.div_ceil(slot.stride) as u64;
                self.gro_counters
                    .gro_coalesced_recv
                    .fetch_add(1, Ordering::Relaxed);
                self.gro_counters
                    .gro_segments_total
                    .fetch_add(segments, Ordering::Relaxed);
            }
            slot.ecn = None;
            slot.dst_ip = None;
        }
        Ok(filled)
    }

    /// Readiness loop for the GRO receive path. Mirrors the plain path's
    /// structure: await readiness, then run one batched GRO read. A
    /// `WouldBlock` from the batched read means the queue drained between the
    /// readiness signal and the syscall, so it re-arms readiness and loops.
    #[cfg(target_os = "linux")]
    fn poll_recv_gro(
        &self,
        cx: &mut std::task::Context,
        gro_recv: &quinn::udp::UdpSocketState,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
        capacity: usize,
    ) -> std::task::Poll<std::io::Result<usize>> {
        loop {
            std::task::ready!(self.io.poll_recv_ready(cx))?;
            match self.io.try_io(tokio::io::Interest::READABLE, || {
                self.recv_gro_batch(gro_recv, &mut bufs[..capacity], &mut meta[..capacity])
            }) {
                Ok(0) => continue,
                Ok(received) => return std::task::Poll::Ready(Ok(received)),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(error) => return std::task::Poll::Ready(Err(error)),
            }
        }
    }
}

/// Returns true if `error` is a GSO-rejection (`EINVAL`/`EIO`) that should
/// disable GSO for the destination and trigger a plain-datagram fallback.
#[cfg(target_os = "linux")]
fn is_gso_rejection(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EINVAL) | Some(libc::EIO))
}

/// Returns the process-wide per-message GSO sender, building it at most once.
///
/// [`quinn::udp::UdpSocketState::new`] re-runs the kernel GSO/GRO capability
/// probes (binding throwaway sockets and issuing several `setsockopt` calls)
/// on every invocation, which can block for tens to hundreds of milliseconds
/// under socket-table contention. Doing that per connection stalls the async
/// worker on the connect hot path, so the sender is built once and shared by
/// [`Arc`]: it carries no per-socket fd (`try_send` takes the target fd as an
/// argument), so a single instance is correct for every socket. Returns `None`
/// when the kernel/path reports no GSO capability so the socket stays plain.
#[cfg(target_os = "linux")]
fn build_gso_sender() -> Option<Arc<quinn::udp::UdpSocketState>> {
    static CACHED_SENDER: std::sync::OnceLock<Option<Arc<quinn::udp::UdpSocketState>>> =
        std::sync::OnceLock::new();
    CACHED_SENDER
        .get_or_init(|| {
            let probe = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
                .or_else(|_| std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)))
                .ok()?;
            let state = quinn::udp::UdpSocketState::new((&probe).into()).ok()?;
            // If the kernel/probe reports no GSO capability, do not engage GSO at all.
            if state.max_gso_segments() <= 1 {
                return None;
            }
            Some(Arc::new(state))
        })
        .clone()
}

impl quinn::AsyncUdpSocket for PlainUdpSocket {
    fn create_io_poller(self: std::sync::Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(PlainUdpPoller { socket: self })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        let dest = transmit.destination;
        let segment = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        let batched = segment < transmit.contents.len();
        let long_header = Self::has_long_header(transmit, segment);

        // Send plainly when: GSO is off / unsupported, the transmit is not
        // batched, this destination already fell back, or ANY chunk is a QUIC
        // long-header (Initial/Handshake) packet that must never be segmented.
        let gso_eligible = matches!(self.mode, GsoMode::Auto)
            && batched
            && self.dest_state(dest) != GsoDestState::Disabled
            && !long_header;
        if !gso_eligible {
            return self.send_plain_chunks(transmit);
        }

        // Eligible batched short-header transmit: attempt one GSO sendmsg.
        // Tripwire: by the guard above `long_header` is false here; if a future
        // change ever lets a long-header packet reach this point, the counter
        // makes the regression observable (tests assert it stays zero).
        if long_header {
            self.counters
                .long_header_gso_attempt
                .fetch_add(1, Ordering::Relaxed);
        }
        self.counters.attempt.fetch_add(1, Ordering::Relaxed);
        match self.try_send_gso(transmit) {
            Ok(()) => {
                self.counters.success.fetch_add(1, Ordering::Relaxed);
                if self.dest_state(dest) != GsoDestState::Working {
                    self.set_dest_state(dest, GsoDestState::Working);
                    tracing::info!(%dest, "udp gso engaged");
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Err(error),
            #[cfg(target_os = "linux")]
            Err(error) if is_gso_rejection(&error) => {
                self.counters.fallback.fetch_add(1, Ordering::Relaxed);
                if self.dest_state(dest) != GsoDestState::Disabled {
                    self.set_dest_state(dest, GsoDestState::Disabled);
                    tracing::warn!(
                        %dest,
                        error = %error,
                        "udp gso rejected by egress path; disabling gso for destination and falling back to plain datagrams"
                    );
                }
                self.counters
                    .plain_after_fallback
                    .fetch_add(1, Ordering::Relaxed);
                self.send_plain_chunks(transmit)
            }
            Err(error) => {
                // Unexpected non-WouldBlock, non-rejection error. Fall back to
                // plain datagrams rather than dropping the transmit.
                self.counters.fallback.fetch_add(1, Ordering::Relaxed);
                self.set_dest_state(dest, GsoDestState::Disabled);
                tracing::warn!(
                    %dest,
                    error = %error,
                    "udp gso sendmsg failed; falling back to plain datagrams"
                );
                self.counters
                    .plain_after_fallback
                    .fetch_add(1, Ordering::Relaxed);
                self.send_plain_chunks(transmit)
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let capacity = bufs.len().min(meta.len());
        if capacity == 0 {
            return std::task::Poll::Ready(Ok(0));
        }

        #[cfg(target_os = "linux")]
        if let Some(gro_recv) = self.gro_recv.clone() {
            return self.poll_recv_gro(cx, gro_recv.as_ref(), bufs, meta, capacity);
        }

        loop {
            std::task::ready!(self.io.poll_recv_ready(cx))?;
            // Drain every datagram already queued on this readiness wake into
            // the buffers quinn provided, not just one. Reading a single
            // datagram per poll throttles the endpoint to one recvfrom per
            // wakeup, which stalls handshake progress when many connections
            // arrive at once (the server endpoint shares one socket). The
            // first read blocks on readiness above; the rest are nonblocking
            // until the queue drains or the buffers fill.
            let mut received = 0;
            while received < capacity {
                match self.io.try_io(tokio::io::Interest::READABLE, || {
                    self.io.try_recv_from(&mut bufs[received])
                }) {
                    Ok((len, src)) => {
                        meta[received] = quinn::udp::RecvMeta {
                            len,
                            stride: len,
                            addr: src,
                            ecn: None,
                            dst_ip: None,
                        };
                        received += 1;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return std::task::Poll::Ready(Err(error)),
                }
            }
            if received > 0 {
                return std::task::Poll::Ready(Ok(received));
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.mode.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        // Drives quinn's per-slot receive buffer size
        // (`max_udp_payload_size * max_receive_segments`). It must exceed one
        // for a coalesced GRO super-buffer to have room to land; otherwise GRO
        // is inert because the buffer holds only a single datagram.
        if self.gro_recv.is_some() {
            self.gro_mode.max_receive_segments()
        } else {
            1
        }
    }
}

/// Write-readiness poller for [`PlainUdpSocket`].
#[derive(Debug)]
struct PlainUdpPoller {
    socket: std::sync::Arc<PlainUdpSocket>,
}

impl quinn::UdpPoller for PlainUdpPoller {
    fn poll_writable(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.socket.io.poll_send_ready(cx)
    }
}

/// Builds a quinn endpoint bound to `addr` using the adaptive
/// [`PlainUdpSocket`]: no GRO/ECN/PMTUDISC on the receive path, optional
/// per-message UDP GSO on send (per [`GsoMode::from_env`]). With
/// `Some(server_config)` it is a server endpoint, otherwise a client endpoint.
fn build_ecn_safe_endpoint(
    addr: SocketAddr,
    server_config: Option<quinn::ServerConfig>,
) -> Result<quinn::Endpoint, TransportError> {
    let socket = std::net::UdpSocket::bind(addr)?;
    build_ecn_safe_endpoint_from_socket(socket, server_config)
}

/// Wraps an already-bound std UDP socket into an adaptive-GSO quinn endpoint.
fn build_ecn_safe_endpoint_from_socket(
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
        policy.receive_windows.initial_stream as u32,
    ));
    inner.receive_window(quinn::VarInt::from_u32(
        policy.receive_windows.initial_connection as u32,
    ));
    inner.keep_alive_interval(Some(policy.keep_alive));
    inner.datagram_receive_buffer_size(if policy.enable_datagrams {
        Some(usize::from(u16::MAX))
    } else {
        None
    });
    if policy.disable_path_mtu_discovery {
        inner.mtu_discovery_config(None);
    }
    // UDP GSO is gated by [`GsoMode`]. In [`GsoMode::Auto`] quinn-proto is
    // allowed to coalesce several datagrams into one segmented transmit
    // (`Transmit { segment_size: Some(..) }`); the adaptive [`PlainUdpSocket`]
    // then attempts a single per-message `UDP_SEGMENT` sendmsg with same-call
    // fallback, and never segments long-header (Initial/Handshake) packets, so
    // GSO-hostile paths (quinn-rs/quinn#2575, #2202) cannot strand the
    // handshake. In [`GsoMode::Off`] (or non-Linux, or `ZUICITY_DISABLE_GSO=1`)
    // segmentation is disabled and every transmit is one datagram, matching
    // upstream Go quic-go behaviour.
    inner.enable_segmentation_offload(matches!(GsoMode::from_env(), GsoMode::Auto));
    apply_congestion_controller(&mut inner, policy);
    BuiltTransportConfig {
        inner,
        policy: policy.clone(),
    }
}

/// Installs the policy's congestion controller on a quinn [`TransportConfig`].
///
/// Quinn defaults to CUBIC; upstream Juicity negotiates `congestion_control=bbr`,
/// so without this hook zuicity advertised BBR but ran CUBIC. Translates the
/// upstream packet-denominated window (`policy.cwnd`) into BBR's byte-denominated
/// `initial_window`.
fn apply_congestion_controller(inner: &mut quinn::TransportConfig, policy: &QuicRuntimePolicy) {
    match policy.congestion_controller {
        CongestionController::Bbr => {
            // policy.cwnd is in packets; BbrConfig::initial_window wants bytes.
            const CONSERVATIVE_DATAGRAM_BYTES: u64 = 1200;
            let mut bbr = quinn::congestion::BbrConfig::default();
            let requested = u64::from(policy.cwnd).saturating_mul(CONSERVATIVE_DATAGRAM_BYTES);
            // Never start below quinn-proto's own BBR default floor (14720).
            let initial_window = requested.max(14_720);
            bbr.initial_window(initial_window);
            inner.congestion_controller_factory(std::sync::Arc::new(bbr));
        }
    }
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
    let crypto = build_server_crypto_config_from_pem(cert_pem, key_pem)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
    ));
    config
        .transport_config(build_transport_config(&QuicRuntimePolicy::upstream_server()).into_arc());
    Ok(QuicServerConfig { inner: config })
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
    let crypto = build_client_crypto_config_with_roots(roots_pem, allow_insecure)?;
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    config
        .transport_config(build_transport_config(&QuicRuntimePolicy::upstream_client()).into_arc());
    Ok(QuicClientConfig { inner: config })
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

fn build_client_config_with_webpki_roots(
    allow_insecure: bool,
) -> Result<QuicClientConfig, TransportError> {
    let crypto = build_client_crypto_config_with_webpki_roots(allow_insecure)?;
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    config
        .transport_config(build_transport_config(&QuicRuntimePolicy::upstream_client()).into_arc());
    Ok(QuicClientConfig { inner: config })
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
    let crypto = build_client_crypto_config_with_cert_chain_pin(pinned_cert_chain_sha256)?;
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    config
        .transport_config(build_transport_config(&QuicRuntimePolicy::upstream_client()).into_arc());
    Ok(QuicClientConfig { inner: config })
}

/// Minimal Juicity QUIC server endpoint for authenticated runtime tests.
#[derive(Debug, Clone)]
pub struct JuicityQuicServer {
    endpoint: quinn::Endpoint,
}

impl JuicityQuicServer {
    /// Binds a server endpoint with upstream-compatible TLS/QUIC settings.
    pub fn bind_with_pem(
        addr: SocketAddr,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<Self, TransportError> {
        let config = build_server_config_from_pem(cert_pem, key_pem)?;
        let endpoint = build_ecn_safe_endpoint(addr, Some(config.inner))?;
        Ok(Self { endpoint })
    }

    /// Returns the local UDP socket address.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Accepts one QUIC connection and validates the first upstream authentication stream.
    pub async fn accept_authenticated(
        &self,
        uuid: uuid::Uuid,
        password: &[u8],
    ) -> Result<AuthenticatedConnection, TransportError> {
        self.accept_authenticated_with([(uuid, password)]).await
    }

    /// Accepts one QUIC connection and validates authentication against a credential set.
    pub async fn accept_authenticated_with<'a>(
        &self,
        credentials: impl IntoIterator<Item = (uuid::Uuid, &'a [u8])>,
    ) -> Result<AuthenticatedConnection, TransportError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(TransportError::EndpointClosed)?;
        let connection = incoming.accept()?.await?;
        let protocol = verify_authentication_stream_with(&connection, credentials).await?;
        Ok(AuthenticatedConnection {
            connection,
            protocol,
        })
    }
}

/// Minimal Juicity QUIC client endpoint for authenticated runtime tests.
#[derive(Debug, Clone)]
pub struct JuicityQuicClient {
    endpoint: quinn::Endpoint,
}

impl JuicityQuicClient {
    /// Binds a client endpoint to a local UDP socket address.
    pub fn bind(addr: SocketAddr) -> Result<Self, TransportError> {
        let endpoint = build_ecn_safe_endpoint(addr, None)?;
        Ok(Self { endpoint })
    }

    /// Returns the local UDP socket address.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Connects to a server, derives the upstream auth token, and sends the auth command stream.
    pub async fn connect_with_roots(
        &self,
        server_addr: SocketAddr,
        server_name: &str,
        roots_pem: &[u8],
        allow_insecure: bool,
        uuid: uuid::Uuid,
        password: &[u8],
    ) -> Result<AuthenticatedConnection, TransportError> {
        let config = build_client_config_with_roots(roots_pem, allow_insecure)?;
        let connection = self
            .endpoint
            .connect_with(config.inner, server_addr, server_name)?
            .await?;
        send_authentication_stream(&connection, uuid, password).await?;
        Ok(AuthenticatedConnection {
            connection,
            protocol: ProxyProtocol::Juicity,
        })
    }

    /// Connects using upstream-style pinned certificate-chain verification.
    pub async fn connect_with_cert_chain_pin(
        &self,
        server_addr: SocketAddr,
        server_name: &str,
        pinned_cert_chain_sha256: &[u8],
        uuid: uuid::Uuid,
        password: &[u8],
    ) -> Result<AuthenticatedConnection, TransportError> {
        let config = build_client_config_with_cert_chain_pin(pinned_cert_chain_sha256)?;
        let connection = self
            .endpoint
            .connect_with(config.inner, server_addr, server_name)?
            .await?;
        send_authentication_stream(&connection, uuid, password).await?;
        Ok(AuthenticatedConnection {
            connection,
            protocol: ProxyProtocol::Juicity,
        })
    }
}

/// Wire protocol negotiated on the authentication stream.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProxyProtocol {
    /// Juicity authentication frame (version byte `0x00`).
    Juicity,
    /// TUIC v5 authentication frame (version byte `0x05`).
    Tuic,
}

/// Authenticated Juicity QUIC connection wrapper.
#[derive(Debug, Clone)]
pub struct AuthenticatedConnection {
    connection: quinn::Connection,
    protocol: ProxyProtocol,
}

impl AuthenticatedConnection {
    /// Returns the peer UDP address.
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Returns the underlying Quinn connection.
    #[must_use]
    pub fn as_quinn(&self) -> &quinn::Connection {
        &self.connection
    }

    /// Returns the negotiated wire protocol for this connection.
    #[must_use]
    pub fn protocol(&self) -> ProxyProtocol {
        self.protocol
    }

    /// Opens one upstream-compatible TCP proxy bidirectional stream.
    pub async fn open_tcp_proxy_stream(
        &self,
        address: IpAddr,
        port: u16,
    ) -> Result<TcpProxyStream, TransportError> {
        let header = proxy_header_for_ip(Network::Tcp, address, port);
        self.open_tcp_proxy_stream_with_header(&header).await
    }

    /// Opens one upstream-compatible TCP proxy stream using a domain target header.
    pub async fn open_tcp_proxy_domain_stream(
        &self,
        domain: &str,
        port: u16,
    ) -> Result<TcpProxyStream, TransportError> {
        let header = ProxyHeader::new(Network::Tcp, ProxyAddress::Domain(domain.as_bytes()), port);
        self.open_tcp_proxy_stream_with_header(&header).await
    }

    async fn open_tcp_proxy_stream_with_header(
        &self,
        header: &ProxyHeader<'_>,
    ) -> Result<TcpProxyStream, TransportError> {
        let (mut send, recv) = self.connection.open_bi().await?;
        let mut encoded = Vec::with_capacity(header.encoded_len());
        header.encode_to(&mut encoded)?;
        send.write_all(&encoded).await?;
        Ok(TcpProxyStream { send, recv })
    }

    /// Accepts and relays one upstream-compatible TCP proxy stream to its requested target.
    pub async fn accept_tcp_proxy_once(&self) -> Result<TcpProxyRelayReport, TransportError> {
        self.accept_tcp_proxy_once_with_egress(ProxyEgressPolicy::direct())
            .await
    }

    /// Accepts and relays one upstream-compatible TCP proxy stream with an egress policy.
    pub async fn accept_tcp_proxy_once_with_egress(
        &self,
        egress: ProxyEgressPolicy,
    ) -> Result<TcpProxyRelayReport, TransportError> {
        let (send, mut recv) = self.connection.accept_bi().await?;
        let (header, initial_payload) = read_proxy_header_prefix(&mut recv).await?;
        let target_stream = connect_tcp_proxy_target_with_egress(&header, egress).await?;
        relay_tcp_proxy_stream(
            send,
            recv,
            target_stream,
            initial_payload,
            DEFAULT_NAT_TIMEOUT,
        )
        .await
    }

    /// Accepts one bidirectional proxy stream, classifies its network header, and relays it.
    pub async fn accept_proxy_once(&self) -> Result<ProxyRelayReport, TransportError> {
        self.accept_proxy_once_with_egress(ProxyEgressPolicy::direct())
            .await
    }

    /// Accepts one bidirectional proxy stream with an explicit egress policy.
    pub async fn accept_proxy_once_with_egress(
        &self,
        egress: ProxyEgressPolicy,
    ) -> Result<ProxyRelayReport, TransportError> {
        self.accept_proxy_once_with_idle_timeout_and_egress(DEFAULT_NAT_TIMEOUT, egress)
            .await
    }

    /// Accepts one bidirectional proxy stream with an explicit UDP idle timeout.
    pub async fn accept_proxy_once_with_idle_timeout(
        &self,
        idle_timeout: Duration,
    ) -> Result<ProxyRelayReport, TransportError> {
        self.accept_proxy_once_with_idle_timeout_and_egress(
            idle_timeout,
            ProxyEgressPolicy::direct(),
        )
        .await
    }

    /// Accepts one bidirectional proxy stream with an explicit UDP idle timeout and egress policy.
    pub async fn accept_proxy_once_with_idle_timeout_and_egress(
        &self,
        idle_timeout: Duration,
        egress: ProxyEgressPolicy,
    ) -> Result<ProxyRelayReport, TransportError> {
        let accepted = self.accept_proxy_stream().await?;
        accepted
            .relay_with_idle_timeout_and_egress(idle_timeout, egress)
            .await
    }

    /// Accepts one bidirectional proxy stream and reads its classification header.
    ///
    /// Returns the accepted stream so the caller can relay it on a separate task,
    /// letting one connection serve many proxy streams concurrently like the
    /// upstream Go server which spawns one goroutine per accepted stream.
    pub async fn accept_proxy_stream(&self) -> Result<AcceptedProxyStream, TransportError> {
        let (send, mut recv) = self.connection.accept_bi().await?;
        let (header, initial_payload) = match self.protocol {
            ProxyProtocol::Juicity => read_proxy_header_prefix(&mut recv).await?,
            ProxyProtocol::Tuic => read_tuic_connect_header_prefix(&mut recv).await?,
        };
        Ok(AcceptedProxyStream {
            send,
            recv,
            header,
            initial_payload,
        })
    }

    /// Opens one upstream-compatible UDP-over-stream bidirectional stream.
    pub async fn open_udp_over_stream(
        &self,
        address: IpAddr,
        port: u16,
    ) -> Result<UdpOverStream, TransportError> {
        let (mut send, recv) = self.connection.open_bi().await?;
        let header = OwnedProxyHeader::from_ip(Network::Udp, address, port);
        write_proxy_header(&mut send, &header).await?;
        Ok(UdpOverStream { send, recv, header })
    }

    /// Opens one upstream-compatible UDP-over-stream using a domain target header.
    pub async fn open_udp_over_domain_stream(
        &self,
        domain: &str,
        port: u16,
    ) -> Result<UdpOverStream, TransportError> {
        let (mut send, recv) = self.connection.open_bi().await?;
        let header = OwnedProxyHeader {
            network: Network::Udp,
            address: OwnedProxyAddress::Domain(domain.to_owned()),
            port,
        };
        write_proxy_header(&mut send, &header).await?;
        Ok(UdpOverStream { send, recv, header })
    }

    /// Accepts and relays one UDP-over-stream session using the upstream default NAT timeout.
    pub async fn accept_udp_over_stream_once(
        &self,
    ) -> Result<UdpOverStreamRelayReport, TransportError> {
        self.accept_udp_over_stream_once_with_egress(ProxyEgressPolicy::direct())
            .await
    }

    /// Accepts and relays one UDP-over-stream session using the upstream default NAT timeout and egress policy.
    pub async fn accept_udp_over_stream_once_with_egress(
        &self,
        egress: ProxyEgressPolicy,
    ) -> Result<UdpOverStreamRelayReport, TransportError> {
        self.accept_udp_over_stream_with_idle_timeout_and_egress(DEFAULT_NAT_TIMEOUT, egress)
            .await
    }

    /// Accepts and relays one UDP-over-stream session until the client closes or the session idles.
    pub async fn accept_udp_over_stream_with_idle_timeout(
        &self,
        idle_timeout: Duration,
    ) -> Result<UdpOverStreamRelayReport, TransportError> {
        self.accept_udp_over_stream_with_idle_timeout_and_egress(
            idle_timeout,
            ProxyEgressPolicy::direct(),
        )
        .await
    }

    /// Accepts and relays one UDP-over-stream session with an explicit idle timeout and egress policy.
    pub async fn accept_udp_over_stream_with_idle_timeout_and_egress(
        &self,
        idle_timeout: Duration,
        egress: ProxyEgressPolicy,
    ) -> Result<UdpOverStreamRelayReport, TransportError> {
        let idle_timeout = if idle_timeout.is_zero() {
            DEFAULT_NAT_TIMEOUT
        } else {
            idle_timeout
        };
        let (send, mut recv) = self.connection.accept_bi().await?;
        let (stream_header, _) = read_proxy_header_prefix(&mut recv).await?;
        relay_udp_over_stream_session(send, recv, stream_header, idle_timeout, egress).await
    }
}

fn udp_session_connection_lost(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::Connection(_)
            | TransportError::ReadExact(quinn::ReadExactError::ReadError(
                quinn::ReadError::ConnectionLost(_),
            ))
    )
}

/// Client-side TCP proxy stream over an authenticated Juicity QUIC connection.
#[derive(Debug)]
pub struct TcpProxyStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl TcpProxyStream {
    /// Splits the proxied TCP stream into its send and receive halves.
    #[must_use]
    pub fn into_split(self) -> (quinn::SendStream, quinn::RecvStream) {
        (self.send, self.recv)
    }

    /// Writes all bytes to the proxied TCP target.
    pub async fn write_all(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        Ok(self.send.write_all(payload).await?)
    }

    /// Finishes the client-to-target half of the proxied TCP stream.
    pub fn finish(&mut self) -> Result<(), TransportError> {
        Ok(self.send.finish()?)
    }

    /// Reads the target-to-client half to completion.
    pub async fn read_to_end(&mut self, size_limit: usize) -> Result<Vec<u8>, TransportError> {
        Ok(self.recv.read_to_end(size_limit).await?)
    }
}

/// Client-side UDP-over-stream proxy over an authenticated Juicity QUIC connection.
#[derive(Debug)]
pub struct UdpOverStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    header: OwnedProxyHeader,
}

impl UdpOverStream {
    /// Sends one UDP datagram frame to the configured proxied target.
    pub async fn send_datagram(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        let header = self.header.as_borrowed();
        let mut encoded =
            Vec::with_capacity(header.address.runtime_metadata_len() + 2 + payload.len());
        encode_udp_datagram(&header, payload, &mut encoded)?;
        Ok(self.send.write_all(&encoded).await?)
    }

    /// Receives one UDP datagram frame from the remote relay.
    pub async fn recv_datagram(
        &mut self,
        size_limit: usize,
    ) -> Result<UdpOverStreamDatagram, TransportError> {
        let frame = read_udp_datagram_frame(&mut self.recv).await?;
        if frame.payload.len() > size_limit {
            return Err(TransportError::UdpFrameTooLarge {
                size: frame.payload.len(),
                limit: size_limit,
            });
        }
        let target = udp_ip_header_target(&frame.header)?;
        Ok(UdpOverStreamDatagram {
            target,
            payload: frame.payload,
        })
    }

    /// Finishes the client-to-server half of this UDP-over-stream session.
    pub fn finish(&mut self) -> Result<(), TransportError> {
        Ok(self.send.finish()?)
    }
}

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

struct UdpFrame {
    header: OwnedProxyHeader,
    payload: Vec<u8>,
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

/// One accepted proxy stream whose classification header has been read.
///
/// Produced by [`AuthenticatedConnection::accept_proxy_stream`] and relayed with
/// [`AcceptedProxyStream::relay_with_idle_timeout_and_egress`].
#[derive(Debug)]
pub struct AcceptedProxyStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    header: OwnedProxyHeader,
    initial_payload: Vec<u8>,
}

impl AcceptedProxyStream {
    /// Relays this accepted stream to its target using the given UDP idle timeout and egress policy.
    pub async fn relay_with_idle_timeout_and_egress(
        self,
        idle_timeout: Duration,
        egress: ProxyEgressPolicy,
    ) -> Result<ProxyRelayReport, TransportError> {
        let idle_timeout = if idle_timeout.is_zero() {
            DEFAULT_NAT_TIMEOUT
        } else {
            idle_timeout
        };
        let AcceptedProxyStream {
            send,
            recv,
            header,
            initial_payload,
        } = self;
        match header.network {
            Network::Tcp => {
                let target_stream = connect_tcp_proxy_target_with_egress(&header, egress).await?;
                Ok(ProxyRelayReport::Tcp(
                    relay_tcp_proxy_stream(
                        send,
                        recv,
                        target_stream,
                        initial_payload,
                        idle_timeout,
                    )
                    .await?,
                ))
            }
            Network::Udp => Ok(ProxyRelayReport::Udp(
                relay_udp_over_stream_session(send, recv, header, idle_timeout, egress).await?,
            )),
        }
    }
}

fn proxy_header_for_ip(network: Network, address: IpAddr, port: u16) -> ProxyHeader<'static> {
    match address {
        IpAddr::V4(address) => ProxyHeader::new(network, ProxyAddress::Ipv4(address), port),
        IpAddr::V6(address) => ProxyHeader::new(network, ProxyAddress::Ipv6(address), port),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnedProxyHeader {
    network: Network,
    address: OwnedProxyAddress,
    port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum OwnedProxyAddress {
    Ipv4(std::net::Ipv4Addr),
    Ipv6(std::net::Ipv6Addr),
    Domain(String),
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

struct TcpProxyTargetStream {
    inner: Box<dyn AsyncReadWrite>,
    peer_addr: SocketAddr,
}

impl TcpProxyTargetStream {
    fn new<S>(stream: S, peer_addr: SocketAddr) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            inner: Box::new(stream),
            peer_addr,
        }
    }

    fn plain(stream: tokio::net::TcpStream) -> std::io::Result<Self> {
        let peer_addr = stream.peer_addr()?;
        // Disable Nagle on the outbound target socket: the relay writes in large
        // 64 KiB batches, so coalescing partial segments only adds round-trip
        // delay to the small request/response exchanges the proxy also carries.
        stream.set_nodelay(true)?;
        Ok(Self::new(stream, peer_addr))
    }

    const fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

impl AsyncRead for TcpProxyTargetStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpProxyTargetStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

impl OwnedProxyHeader {
    fn from_borrowed(header: ProxyHeader<'_>) -> Result<Self, TransportError> {
        let address = match header.address {
            ProxyAddress::Ipv4(address) => OwnedProxyAddress::Ipv4(address),
            ProxyAddress::Ipv6(address) => OwnedProxyAddress::Ipv6(address),
            ProxyAddress::Domain(domain) => {
                OwnedProxyAddress::Domain(std::str::from_utf8(domain)?.to_owned())
            }
        };
        Ok(Self {
            network: header.network,
            address,
            port: header.port,
        })
    }

    fn from_ip(network: Network, address: IpAddr, port: u16) -> Self {
        let address = match address {
            IpAddr::V4(address) => OwnedProxyAddress::Ipv4(address),
            IpAddr::V6(address) => OwnedProxyAddress::Ipv6(address),
        };
        Self {
            network,
            address,
            port,
        }
    }

    fn as_borrowed(&self) -> ProxyHeader<'_> {
        let address = match &self.address {
            OwnedProxyAddress::Ipv4(address) => ProxyAddress::Ipv4(*address),
            OwnedProxyAddress::Ipv6(address) => ProxyAddress::Ipv6(*address),
            OwnedProxyAddress::Domain(domain) => ProxyAddress::Domain(domain.as_bytes()),
        };
        ProxyHeader::new(self.network, address, self.port)
    }
}

async fn connect_tcp_proxy_target_with_egress(
    header: &OwnedProxyHeader,
    egress: ProxyEgressPolicy,
) -> Result<TcpProxyTargetStream, TransportError> {
    if header.network != Network::Tcp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    if let Some(dialer_link) = &egress.dialer_link {
        return connect_tcp_proxy_target_with_dialer_link(header, &egress, dialer_link).await;
    }
    let targets = tcp_header_targets(header).await?;
    let mut last_error = None;
    for target in targets {
        if egress_source_mismatches_target(&egress, target) {
            continue;
        }
        match connect_tcp_socket_to_target(target, &egress).await {
            Ok(stream) => return Ok(TcpProxyTargetStream::plain(stream)?),
            Err(error) => last_error = Some(error),
        }
    }
    if let Some(error) = last_error {
        return Err(error.into());
    }
    Err(TransportError::NoUsableTcpTarget)
}

async fn tcp_header_targets(header: &OwnedProxyHeader) -> Result<Vec<SocketAddr>, TransportError> {
    match &header.address {
        OwnedProxyAddress::Ipv4(address) => {
            Ok(vec![SocketAddr::new(IpAddr::V4(*address), header.port)])
        }
        OwnedProxyAddress::Ipv6(address) => {
            Ok(vec![SocketAddr::new(IpAddr::V6(*address), header.port)])
        }
        OwnedProxyAddress::Domain(domain) => {
            Ok(tokio::net::lookup_host((domain.as_str(), header.port))
                .await?
                .collect())
        }
    }
}
async fn connect_tcp_proxy_target_with_dialer_link(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    dialer_link: &ProxyDialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    match dialer_link {
        ProxyDialerLink::HttpConnect(link) => {
            connect_tcp_proxy_target_via_http_connect(header, egress, link).await
        }
        ProxyDialerLink::Socks5(link) => {
            connect_tcp_proxy_target_via_socks5(header, egress, link).await
        }
        ProxyDialerLink::Shadowsocks(link) => {
            connect_tcp_proxy_target_via_shadowsocks(header, egress, link).await
        }
        ProxyDialerLink::ShadowsocksR(link) => {
            connect_tcp_proxy_target_via_shadowsocks(header, egress, &link.shadowsocks).await
        }
        ProxyDialerLink::Trojan(link) => {
            connect_tcp_proxy_target_via_trojan(header, egress, link).await
        }
        ProxyDialerLink::Juicity(link) => {
            connect_tcp_proxy_target_via_juicity(header, egress, link).await
        }
        ProxyDialerLink::Tuic(link) => {
            connect_tcp_proxy_target_via_tuic(header, egress, link).await
        }
        ProxyDialerLink::Hysteria2(link) => {
            connect_tcp_proxy_target_via_hysteria2(header, egress, link).await
        }
        ProxyDialerLink::Vmess(link) => {
            connect_tcp_proxy_target_via_vmess(header, egress, link).await
        }
        ProxyDialerLink::Vless(link) => {
            connect_tcp_proxy_target_via_vless(header, egress, link).await
        }
        ProxyDialerLink::Chain(links) => {
            connect_tcp_proxy_target_via_dialer_chain(header, egress, links).await
        }
    }
}

async fn connect_tcp_proxy_target_via_dialer_chain(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    links: &[ProxyDialerLink],
) -> Result<TcpProxyTargetStream, TransportError> {
    let Some(last_link) = links.last() else {
        return Err(TransportError::InvalidProxyDialerLink {
            link: String::new(),
            message: "proxy chain requires at least one hop".to_owned(),
        });
    };
    let mut stream = connect_tcp_socket_to_dialer_link(egress, last_link).await?;
    for index in (0..links.len()).rev() {
        let target = if index == 0 {
            header.clone()
        } else {
            dialer_link_endpoint_header(&links[index - 1])?
        };
        stream = connect_tcp_dialer_link(stream, &target, &links[index]).await?;
    }
    Ok(stream)
}

async fn connect_tcp_socket_to_dialer_link(
    egress: &ProxyEgressPolicy,
    dialer_link: &ProxyDialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    let (host, port) =
        dialer_link
            .endpoint()
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: dialer_link.scheme_for_error().to_owned(),
                message: "proxy chain cannot be used as a chain endpoint".to_owned(),
            })?;
    let proxy_targets = tokio::net::lookup_host((host, port)).await?;
    let proxy_egress =
        ProxyEgressPolicy::with_send_through_and_fwmark(egress.send_through, egress.fwmark);
    let mut last_error = None;
    for proxy_target in proxy_targets {
        if egress_source_mismatches_target(&proxy_egress, proxy_target) {
            continue;
        }
        match connect_tcp_socket_to_target(proxy_target, &proxy_egress).await {
            Ok(stream) => return TcpProxyTargetStream::plain(stream).map_err(Into::into),
            Err(error) => last_error = Some(error),
        }
    }
    if let Some(error) = last_error {
        return Err(error.into());
    }
    Err(TransportError::NoUsableTcpTarget)
}

async fn connect_tcp_dialer_link(
    stream: TcpProxyTargetStream,
    header: &OwnedProxyHeader,
    dialer_link: &ProxyDialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    match dialer_link {
        ProxyDialerLink::HttpConnect(link) => {
            let mut stream = connect_http_connect_tls_if_needed(stream, link).await?;
            http_connect(&mut stream, header, link).await?;
            Ok(stream)
        }
        ProxyDialerLink::Socks5(link) => {
            let mut stream = stream;
            socks5_connect(&mut stream, header, link).await?;
            Ok(stream)
        }
        ProxyDialerLink::Shadowsocks(link) => connect_shadowsocks_stream(stream, header, link),
        ProxyDialerLink::ShadowsocksR(link) => {
            connect_shadowsocks_stream(stream, header, &link.shadowsocks)
        }
        ProxyDialerLink::Trojan(link) => connect_trojan_stream(stream, header, link).await,
        ProxyDialerLink::Juicity(_) => Err(TransportError::InvalidProxyDialerLink {
            link: dialer_link.scheme_for_error().to_owned(),
            message: "Juicity dialer_link cannot be used as a TCP chain hop".to_owned(),
        }),
        ProxyDialerLink::Tuic(_) => Err(TransportError::RuntimeNotImplemented),
        ProxyDialerLink::Hysteria2(_) => Err(TransportError::RuntimeNotImplemented),
        ProxyDialerLink::Vmess(link) => connect_vmess_stream(stream, header, link).await,
        ProxyDialerLink::Vless(link) => connect_vless_stream(stream, header, link).await,
        ProxyDialerLink::Chain(_) => Err(TransportError::InvalidProxyDialerLink {
            link: dialer_link.scheme_for_error().to_owned(),
            message: "proxy chain cannot be used as a single hop".to_owned(),
        }),
    }
}

fn proxy_endpoint_header(network: Network, host: &str, port: u16) -> OwnedProxyHeader {
    let address = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => OwnedProxyAddress::Ipv4(address),
        Ok(IpAddr::V6(address)) => OwnedProxyAddress::Ipv6(address),
        Err(_) => OwnedProxyAddress::Domain(host.to_owned()),
    };
    OwnedProxyHeader {
        network,
        address,
        port,
    }
}

fn dialer_link_endpoint_header(
    dialer_link: &ProxyDialerLink,
) -> Result<OwnedProxyHeader, TransportError> {
    let (host, port) =
        dialer_link
            .endpoint()
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: dialer_link.scheme_for_error().to_owned(),
                message: "proxy chain cannot be used as a chain endpoint".to_owned(),
            })?;
    let address = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => OwnedProxyAddress::Ipv4(address),
        Ok(IpAddr::V6(address)) => OwnedProxyAddress::Ipv6(address),
        Err(_) => OwnedProxyAddress::Domain(host.to_owned()),
    };
    Ok(OwnedProxyHeader {
        network: Network::Tcp,
        address,
        port,
    })
}

async fn connect_tcp_proxy_target_via_http_connect(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    link: &HttpConnectDialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    let proxy_targets = tokio::net::lookup_host((link.host.as_str(), link.port)).await?;
    let proxy_egress =
        ProxyEgressPolicy::with_send_through_and_fwmark(egress.send_through, egress.fwmark);
    let mut last_error = None;
    for proxy_target in proxy_targets {
        if egress_source_mismatches_target(&proxy_egress, proxy_target) {
            continue;
        }
        let stream = match connect_tcp_socket_to_target(proxy_target, &proxy_egress).await {
            Ok(stream) => stream,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let mut stream = TcpProxyTargetStream::plain(stream)?;
        stream = connect_http_connect_tls_if_needed(stream, link).await?;
        http_connect(&mut stream, header, link).await?;
        return Ok(stream);
    }
    if let Some(error) = last_error {
        return Err(error.into());
    }
    Err(TransportError::NoUsableTcpTarget)
}

async fn connect_http_connect_tls_if_needed(
    stream: TcpProxyTargetStream,
    link: &HttpConnectDialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    if !link.tls {
        return Ok(stream);
    }
    let peer_addr = stream.peer_addr();
    let mut config = build_http_connect_tls_client_config(link.allow_insecure)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = link.sni.as_deref().unwrap_or(link.host.as_str()).to_owned();
    let server_name = rustls::pki_types::ServerName::try_from(server_name).map_err(|source| {
        TransportError::HttpProxy {
            stage: "tls",
            message: format!("invalid server name: {source}"),
        }
    })?;
    let stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|source| TransportError::HttpProxy {
            stage: "tls",
            message: source.to_string(),
        })?;
    Ok(TcpProxyTargetStream::new(stream, peer_addr))
}

fn build_http_connect_tls_client_config(
    allow_insecure: bool,
) -> Result<rustls::ClientConfig, TransportError> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?;
    let config = if allow_insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    Ok(config)
}

async fn http_connect<S>(
    stream: &mut S,
    header: &OwnedProxyHeader,
    link: &HttpConnectDialerLink,
) -> Result<(), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let authority = http_connect_authority(header);
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(username) = &link.username {
        let password = link.password.as_deref().unwrap_or_default();
        let credentials = general_purpose::STANDARD.encode(format!("{username}:{password}"));
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&credentials);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
        if response.len() > 8192 {
            return Err(TransportError::HttpProxy {
                stage: "connect",
                message: "response header exceeds 8192 bytes".to_owned(),
            });
        }
    }
    let response = std::str::from_utf8(&response)?;
    let status_line = response
        .lines()
        .next()
        .ok_or_else(|| TransportError::HttpProxy {
            stage: "connect",
            message: "missing status line".to_owned(),
        })?;
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let status = parts.next().ok_or_else(|| TransportError::HttpProxy {
        stage: "connect",
        message: format!("malformed status line {status_line:?}"),
    })?;
    if status != "200" {
        return Err(TransportError::HttpProxy {
            stage: "connect",
            message: format!("unexpected status line {status_line:?}"),
        });
    }
    Ok(())
}

fn http_connect_authority(header: &OwnedProxyHeader) -> String {
    match &header.address {
        OwnedProxyAddress::Ipv4(address) => format!("{}:{}", address, header.port),
        OwnedProxyAddress::Ipv6(address) => format!("[{}]:{}", address, header.port),
        OwnedProxyAddress::Domain(domain) => format!("{}:{}", domain, header.port),
    }
}

async fn connect_tcp_proxy_target_via_trojan(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    link: &TrojanDialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    let proxy_targets = tokio::net::lookup_host((link.host.as_str(), link.port)).await?;
    let proxy_egress =
        ProxyEgressPolicy::with_send_through_and_fwmark(egress.send_through, egress.fwmark);
    let mut last_error = None;
    for proxy_target in proxy_targets {
        if egress_source_mismatches_target(&proxy_egress, proxy_target) {
            continue;
        }
        let stream = match connect_tcp_socket_to_target(proxy_target, &proxy_egress).await {
            Ok(stream) => stream,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let stream = TcpProxyTargetStream::plain(stream)?;
        return connect_trojan_stream(stream, header, link).await;
    }
    if let Some(error) = last_error {
        return Err(error.into());
    }
    Err(TransportError::NoUsableTcpTarget)
}

async fn connect_tcp_proxy_target_via_vmess(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    link: &VmessDialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    let proxy_targets = tokio::net::lookup_host((link.host.as_str(), link.port)).await?;
    let proxy_egress =
        ProxyEgressPolicy::with_send_through_and_fwmark(egress.send_through, egress.fwmark);
    let mut last_error = None;
    for proxy_target in proxy_targets {
        if egress_source_mismatches_target(&proxy_egress, proxy_target) {
            continue;
        }
        let stream = match connect_tcp_socket_to_target(proxy_target, &proxy_egress).await {
            Ok(stream) => stream,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let stream = TcpProxyTargetStream::plain(stream)?;
        return connect_vmess_stream(stream, header, link).await;
    }
    if let Some(error) = last_error {
        return Err(error.into());
    }
    Err(TransportError::NoUsableTcpTarget)
}

async fn connect_vmess_stream(
    mut stream: TcpProxyTargetStream,
    header: &OwnedProxyHeader,
    link: &VmessDialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    let peer_addr = stream.peer_addr();
    let context = VmessStreamContext::new(header)?;
    let request = context.encrypt_request_header(header, link)?;
    stream.write_all(&request).await?;
    let (client_side, proxy_side) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Err(error) = bridge_vmess_stream(stream, proxy_side, context).await {
            tracing::debug!(error = %error, "VMess dialer_link bridge closed");
        }
    });
    Ok(TcpProxyTargetStream::new(client_side, peer_addr))
}

const VMESS_OPTION_CHUNK_STREAM: u8 = 1;
const VMESS_OPTION_CHUNK_LENGTH_MASKING: u8 = 4;
const VMESS_OPTION_GLOBAL_PADDING: u8 = 8;
const VMESS_MAX_CHUNK_SIZE: usize = 1 << 14;

type HmacSha256 = Hmac<Sha256>;

struct VmessStreamContext {
    request_body_iv: [u8; 16],
    request_body_key: [u8; 16],
    response_body_iv: [u8; 16],
    response_body_key: [u8; 16],
    response_auth: u8,
    request_options: u8,
}

impl VmessStreamContext {
    fn new(_header: &OwnedProxyHeader) -> Result<Self, TransportError> {
        let mut request_body_iv = [0_u8; 16];
        let mut request_body_key = [0_u8; 16];
        let mut response_auth = [0_u8; 1];
        fill_random(&mut request_body_iv)?;
        fill_random(&mut request_body_key)?;
        fill_random(&mut response_auth)?;
        let response_body_iv = Sha256::digest(request_body_iv)[..16]
            .try_into()
            .expect("sha256 prefix has fixed length");
        let response_body_key = Sha256::digest(request_body_key)[..16]
            .try_into()
            .expect("sha256 prefix has fixed length");
        Ok(Self {
            request_body_iv,
            request_body_key,
            response_body_iv,
            response_body_key,
            response_auth: response_auth[0],
            request_options: VMESS_OPTION_CHUNK_STREAM
                | VMESS_OPTION_CHUNK_LENGTH_MASKING
                | VMESS_OPTION_GLOBAL_PADDING,
        })
    }

    fn encrypt_request_header(
        &self,
        header: &OwnedProxyHeader,
        link: &VmessDialerLink,
    ) -> Result<Vec<u8>, TransportError> {
        let instruction = self.request_instruction(header)?;
        let eauth_id = vmess_eauth_id(&link.cmd_key)?;
        let mut connection_nonce = [0_u8; 8];
        fill_random(&mut connection_nonce)?;
        let sealed_len = vmess_header_aead_seal(
            &link.cmd_key,
            b"VMess Header AEAD Key_Length",
            b"VMess Header AEAD Nonce_Length",
            &eauth_id,
            &connection_nonce,
            &(instruction.len() as u16).to_be_bytes(),
            &eauth_id,
        )?;
        let sealed_payload = vmess_header_aead_seal(
            &link.cmd_key,
            b"VMess Header AEAD Key",
            b"VMess Header AEAD Nonce",
            &eauth_id,
            &connection_nonce,
            &instruction,
            &eauth_id,
        )?;
        let mut request = Vec::with_capacity(
            16 + sealed_len.len() + connection_nonce.len() + sealed_payload.len(),
        );
        request.extend_from_slice(&eauth_id);
        request.extend_from_slice(&sealed_len);
        request.extend_from_slice(&connection_nonce);
        request.extend_from_slice(&sealed_payload);
        Ok(request)
    }

    fn request_instruction(&self, header: &OwnedProxyHeader) -> Result<Vec<u8>, TransportError> {
        let mut instruction = Vec::with_capacity(45 + 255);
        instruction.push(1);
        instruction.extend_from_slice(&self.request_body_iv);
        instruction.extend_from_slice(&self.request_body_key);
        instruction.push(self.response_auth);
        instruction.push(self.request_options);
        instruction.push(0x03);
        instruction.push(0);
        instruction.push(vmess_network_byte(header.network));
        encode_vmess_target_metadata(&mut instruction, header)?;
        let checksum = crc32fast::hash(&instruction).to_be_bytes();
        instruction.extend_from_slice(&checksum);
        Ok(instruction)
    }
}

fn encode_vmess_target_metadata(
    instruction: &mut Vec<u8>,
    header: &OwnedProxyHeader,
) -> Result<(), TransportError> {
    instruction.extend_from_slice(&header.port.to_be_bytes());
    match &header.address {
        OwnedProxyAddress::Ipv4(address) => {
            instruction.push(1);
            instruction.extend_from_slice(&address.octets());
        }
        OwnedProxyAddress::Domain(domain) => {
            let len = u8::try_from(domain.len()).map_err(|_| TransportError::VmessProxy {
                stage: "request",
                message: "domain target exceeds VMess metadata length".to_owned(),
            })?;
            instruction.push(2);
            instruction.push(len);
            instruction.extend_from_slice(domain.as_bytes());
        }
        OwnedProxyAddress::Ipv6(address) => {
            instruction.push(3);
            instruction.extend_from_slice(&address.octets());
        }
    }
    Ok(())
}

const fn vmess_network_byte(network: Network) -> u8 {
    match network {
        Network::Tcp => 1,
        Network::Udp => 2,
    }
}

fn vmess_header_aead_seal(
    command_key: &[u8; 16],
    key_path: &[u8],
    iv_path: &[u8],
    eauth_id: &[u8; 16],
    connection_nonce: &[u8; 8],
    message: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let key = vmess_kdf(command_key, &[key_path, eauth_id, connection_nonce]);
    let iv = vmess_kdf(command_key, &[iv_path, eauth_id, connection_nonce]);
    let cipher = aes_gcm_from_key(&key[..16])?;
    cipher
        .encrypt(Nonce::from_slice(&iv[..12]), Payload { msg: message, aad })
        .map_err(|_| TransportError::VmessProxy {
            stage: "request",
            message: "encrypt VMess AEAD header".to_owned(),
        })
}

fn vmess_cmd_key(key: &[u8; 16]) -> [u8; 16] {
    let mut hasher = md5::Md5::new();
    sha2::Digest::update(&mut hasher, key);
    sha2::Digest::update(&mut hasher, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    hasher.finalize().into()
}

fn vmess_eauth_id(cmd_key: &[u8; 16]) -> Result<[u8; 16], TransportError> {
    let mut auth_id = [0_u8; 16];
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|source| TransportError::VmessProxy {
            stage: "request",
            message: format!("system time before Unix epoch: {source}"),
        })?
        .as_secs();
    auth_id[..8].copy_from_slice(&seconds.to_be_bytes());
    fill_random(&mut auth_id[8..12])?;
    let checksum = crc32fast::hash(&auth_id[..12]).to_be_bytes();
    auth_id[12..].copy_from_slice(&checksum);
    let key = vmess_kdf(cmd_key, &[b"AES Auth ID Encryption".as_slice()]);
    let cipher = aes::Aes128::new(GenericArray::from_slice(&key[..16]));
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut auth_id));
    Ok(auth_id)
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

fn aes_gcm_from_key(key: &[u8]) -> Result<Aes128Gcm, TransportError> {
    Aes128Gcm::new_from_slice(key).map_err(|_| TransportError::VmessProxy {
        stage: "crypto",
        message: "invalid AES-128-GCM key length".to_owned(),
    })
}

fn fill_random(bytes: &mut [u8]) -> Result<(), TransportError> {
    getrandom::getrandom(bytes).map_err(|source| TransportError::VmessProxy {
        stage: "random",
        message: source.to_string(),
    })
}

struct ShakeSizeMask {
    reader: Box<dyn XofReader + Send>,
}

impl ShakeSizeMask {
    fn new(nonce: &[u8]) -> Self {
        let mut shake = Shake128::default();
        Sha3Update::update(&mut shake, nonce);
        Self {
            reader: Box::new(shake.finalize_xof()),
        }
    }

    fn next(&mut self) -> u16 {
        let mut bytes = [0_u8; 2];
        self.reader.read(&mut bytes);
        u16::from_be_bytes(bytes)
    }

    fn encode_size(&mut self, size: u16) -> [u8; 2] {
        (size ^ self.next()).to_be_bytes()
    }

    fn decode_size(&mut self, bytes: [u8; 2]) -> u16 {
        u16::from_be_bytes(bytes) ^ self.next()
    }

    fn padding_len(&mut self) -> usize {
        usize::from(self.next() % 64)
    }
}

async fn bridge_vmess_stream(
    encrypted: TcpProxyTargetStream,
    plaintext: tokio::io::DuplexStream,
    context: VmessStreamContext,
) -> Result<(), TransportError> {
    let request = VmessBodyContext::request(&context)?;
    let response = VmessBodyContext::response(&context)?;
    let (mut encrypted_read, mut encrypted_write) = tokio::io::split(encrypted);
    let (mut plaintext_read, mut plaintext_write) = tokio::io::split(plaintext);
    let upload = async move {
        copy_plain_to_vmess(&mut plaintext_read, &mut encrypted_write, request).await
    };
    let download = async move {
        read_vmess_response_header(&mut encrypted_read, &context).await?;
        copy_vmess_to_plain(&mut encrypted_read, &mut plaintext_write, response).await
    };
    let _ = tokio::try_join!(upload, download)?;
    Ok(())
}

struct VmessBodyContext {
    cipher: Aes128Gcm,
    size_mask: ShakeSizeMask,
    base_nonce: [u8; 16],
    nonce_counter: u16,
}

impl VmessBodyContext {
    fn request(context: &VmessStreamContext) -> Result<Self, TransportError> {
        Ok(Self {
            cipher: aes_gcm_from_key(&context.request_body_key)?,
            size_mask: ShakeSizeMask::new(&context.request_body_iv),
            base_nonce: context.request_body_iv,
            nonce_counter: 0,
        })
    }

    fn response(context: &VmessStreamContext) -> Result<Self, TransportError> {
        Ok(Self {
            cipher: aes_gcm_from_key(&context.response_body_key)?,
            size_mask: ShakeSizeMask::new(&context.response_body_iv),
            base_nonce: context.response_body_iv,
            nonce_counter: 0,
        })
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0_u8; 12];
        nonce[..2].copy_from_slice(&self.nonce_counter.to_be_bytes());
        nonce[2..].copy_from_slice(&self.base_nonce[2..12]);
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        nonce
    }

    fn encode_chunk(&mut self, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
        let padding_len = self.size_mask.padding_len();
        let encrypted_len = payload.len() + 16;
        let total_len = encrypted_len + padding_len;
        let total_len = u16::try_from(total_len).map_err(|_| TransportError::VmessProxy {
            stage: "payload",
            message: "VMess payload chunk exceeds u16 framing limit".to_owned(),
        })?;
        let nonce = self.next_nonce();
        let sealed = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), payload)
            .map_err(|_| TransportError::VmessProxy {
                stage: "payload",
                message: "encrypt VMess payload chunk".to_owned(),
            })?;
        let mut chunk = Vec::with_capacity(2 + usize::from(total_len));
        chunk.extend_from_slice(&self.size_mask.encode_size(total_len));
        chunk.extend_from_slice(&sealed);
        if padding_len != 0 {
            let start = chunk.len();
            chunk.resize(start + padding_len, 0);
            fill_random(&mut chunk[start..])?;
        }
        Ok(chunk)
    }

    fn decode_chunk(
        &mut self,
        mut encrypted: Vec<u8>,
        padding_len: usize,
    ) -> Result<Vec<u8>, TransportError> {
        if encrypted.len() < 16 + padding_len {
            return Err(TransportError::VmessProxy {
                stage: "payload",
                message: "invalid VMess payload chunk length".to_owned(),
            });
        }
        encrypted.truncate(encrypted.len() - padding_len);
        if encrypted.len() == 16 {
            return Ok(Vec::new());
        }
        let nonce = self.next_nonce();
        self.cipher
            .decrypt(Nonce::from_slice(&nonce), encrypted.as_slice())
            .map_err(|_| TransportError::VmessProxy {
                stage: "payload",
                message: "decrypt VMess payload chunk".to_owned(),
            })
    }
}

async fn copy_plain_to_vmess<R, W>(
    reader: &mut R,
    writer: &mut W,
    mut context: VmessBodyContext,
) -> Result<(), TransportError>
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
    mut context: VmessBodyContext,
) -> Result<(), TransportError>
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
            Err(error) => return Err(error.into()),
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

async fn read_vmess_response_header<R>(
    reader: &mut R,
    context: &VmessStreamContext,
) -> Result<(), TransportError>
where
    R: AsyncRead + Unpin,
{
    let mut sealed_len = [0_u8; 18];
    reader.read_exact(&mut sealed_len).await?;
    let len_key = vmess_kdf(
        &context.response_body_key,
        &[b"AEAD Resp Header Len Key".as_slice()],
    );
    let len_iv = vmess_kdf(
        &context.response_body_iv,
        &[b"AEAD Resp Header Len IV".as_slice()],
    );
    let len_cipher = aes_gcm_from_key(&len_key[..16])?;
    let opened_len = len_cipher
        .decrypt(Nonce::from_slice(&len_iv[..12]), sealed_len.as_slice())
        .map_err(|_| TransportError::VmessProxy {
            stage: "response",
            message: "decrypt VMess response header length".to_owned(),
        })?;
    if opened_len.len() != 2 {
        return Err(TransportError::VmessProxy {
            stage: "response",
            message: "invalid VMess response header length".to_owned(),
        });
    }
    let header_len = usize::from(u16::from_be_bytes([opened_len[0], opened_len[1]]));
    let mut sealed_header = vec![0_u8; header_len + 16];
    reader.read_exact(&mut sealed_header).await?;
    let header_key = vmess_kdf(
        &context.response_body_key,
        &[b"AEAD Resp Header Key".as_slice()],
    );
    let header_iv = vmess_kdf(
        &context.response_body_iv,
        &[b"AEAD Resp Header IV".as_slice()],
    );
    let header_cipher = aes_gcm_from_key(&header_key[..16])?;
    let header = header_cipher
        .decrypt(
            Nonce::from_slice(&header_iv[..12]),
            sealed_header.as_slice(),
        )
        .map_err(|_| TransportError::VmessProxy {
            stage: "response",
            message: "decrypt VMess response header".to_owned(),
        })?;
    if header.len() < 4 || header[0] != context.response_auth || header[2] != 0 {
        return Err(TransportError::VmessProxy {
            stage: "response",
            message: "invalid VMess response header".to_owned(),
        });
    }
    Ok(())
}

async fn connect_tcp_proxy_target_via_vless(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    link: &VlessDialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    let proxy_targets = tokio::net::lookup_host((link.host.as_str(), link.port)).await?;
    let proxy_egress =
        ProxyEgressPolicy::with_send_through_and_fwmark(egress.send_through, egress.fwmark);
    let mut last_error = None;
    for proxy_target in proxy_targets {
        if egress_source_mismatches_target(&proxy_egress, proxy_target) {
            continue;
        }
        let stream = match connect_tcp_socket_to_target(proxy_target, &proxy_egress).await {
            Ok(stream) => stream,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let stream = TcpProxyTargetStream::plain(stream)?;
        return connect_vless_stream(stream, header, link).await;
    }
    if let Some(error) = last_error {
        return Err(error.into());
    }
    Err(TransportError::NoUsableTcpTarget)
}

async fn connect_vless_stream(
    mut stream: TcpProxyTargetStream,
    header: &OwnedProxyHeader,
    link: &VlessDialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    let peer_addr = stream.peer_addr();
    write_vless_request_header(&mut stream, header, link).await?;
    Ok(TcpProxyTargetStream::new(
        VlessTcpProxyTargetStream::new(stream),
        peer_addr,
    ))
}

async fn write_vless_request_header<S>(
    stream: &mut S,
    header: &OwnedProxyHeader,
    link: &VlessDialerLink,
) -> Result<(), TransportError>
where
    S: AsyncWrite + Unpin,
{
    let mut request = Vec::with_capacity(1 + 16 + 1 + 1 + 2 + 1 + 255);
    request.push(0);
    request.extend_from_slice(&link.key);
    request.push(0);
    request.push(vless_network_byte(header.network));
    encode_vless_target_metadata(&mut request, header)?;
    stream.write_all(&request).await?;
    Ok(())
}

const fn vless_network_byte(network: Network) -> u8 {
    match network {
        Network::Tcp => 1,
        Network::Udp => 2,
    }
}

fn encode_vless_target_metadata(
    request: &mut Vec<u8>,
    header: &OwnedProxyHeader,
) -> Result<(), TransportError> {
    request.extend_from_slice(&header.port.to_be_bytes());
    match &header.address {
        OwnedProxyAddress::Ipv4(address) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        OwnedProxyAddress::Domain(domain) => {
            let len = u8::try_from(domain.len()).map_err(|_| TransportError::VlessProxy {
                stage: "request",
                message: "domain target exceeds VLESS metadata length".to_owned(),
            })?;
            request.push(2);
            request.push(len);
            request.extend_from_slice(domain.as_bytes());
        }
        OwnedProxyAddress::Ipv6(address) => {
            request.push(3);
            request.extend_from_slice(&address.octets());
        }
    }
    Ok(())
}

struct VlessTcpProxyTargetStream {
    inner: TcpProxyTargetStream,
    response_header: VlessResponseHeaderState,
}

impl VlessTcpProxyTargetStream {
    const fn new(inner: TcpProxyTargetStream) -> Self {
        Self {
            inner,
            response_header: VlessResponseHeaderState::Prefix {
                bytes: [0; 2],
                read: 0,
            },
        }
    }
}

enum VlessResponseHeaderState {
    Prefix { bytes: [u8; 2], read: usize },
    Addons { remaining: usize },
    Ready,
}

impl VlessResponseHeaderState {
    const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

impl AsyncRead for VlessTcpProxyTargetStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while !this.response_header.is_ready() {
            match &mut this.response_header {
                VlessResponseHeaderState::Prefix { bytes, read } => {
                    let before = *read;
                    let mut response_buf = ReadBuf::new(&mut bytes[*read..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut response_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            *read += response_buf.filled().len();
                            if *read == before {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "truncated VLESS response header",
                                )));
                            }
                            if *read == 2 {
                                if bytes[0] != 0 {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        format!("invalid VLESS response version {}", bytes[0]),
                                    )));
                                }
                                let remaining = usize::from(bytes[1]);
                                this.response_header = if remaining == 0 {
                                    VlessResponseHeaderState::Ready
                                } else {
                                    VlessResponseHeaderState::Addons { remaining }
                                };
                            }
                        }
                    }
                }
                VlessResponseHeaderState::Addons { remaining } => {
                    let mut discard = [0_u8; 64];
                    let len = (*remaining).min(discard.len());
                    let mut response_buf = ReadBuf::new(&mut discard[..len]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut response_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            let read = response_buf.filled().len();
                            if read == 0 {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "truncated VLESS response addons",
                                )));
                            }
                            *remaining -= read;
                            if *remaining == 0 {
                                this.response_header = VlessResponseHeaderState::Ready;
                            }
                        }
                    }
                }
                VlessResponseHeaderState::Ready => {}
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VlessTcpProxyTargetStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

async fn connect_tcp_proxy_target_via_tuic(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    link: &TuicDialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    if header.network != Network::Tcp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    let uuid = uuid::Uuid::parse_str(&link.user).map_err(|source| {
        TransportError::InvalidProxyDialerLink {
            link: "tuic".to_owned(),
            message: format!("parse TUIC UUID: {source}"),
        }
    })?;
    let proxy_targets = tokio::net::lookup_host((link.host.as_str(), link.port)).await?;
    let proxy_egress =
        ProxyEgressPolicy::with_send_through_and_fwmark(egress.send_through, egress.fwmark);
    let mut last_error = None;
    for proxy_target in proxy_targets {
        if egress_source_mismatches_target(&proxy_egress, proxy_target) {
            continue;
        }
        let endpoint = match bind_quic_dialer_endpoint(proxy_target, &proxy_egress) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let connection = match connect_tuic_dialer_link(&endpoint, proxy_target, link, uuid).await {
            Ok(connection) => connection,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let (mut send, recv) = match connection.open_bi().await {
            Ok(streams) => streams,
            Err(error) => {
                last_error = Some(error.into());
                continue;
            }
        };
        if let Err(error) = write_tuic_tcp_connect(&mut send, header).await {
            last_error = Some(error);
            continue;
        }
        return Ok(TcpProxyTargetStream::new(
            TuicTcpProxyTargetStream {
                _endpoint: endpoint,
                _connection: connection,
                send,
                recv,
            },
            proxy_target,
        ));
    }
    if let Some(error) = last_error {
        return Err(error);
    }
    Err(TransportError::NoUsableTcpTarget)
}

fn bind_quic_dialer_endpoint(
    proxy_target: SocketAddr,
    egress: &ProxyEgressPolicy,
) -> Result<quinn::Endpoint, TransportError> {
    let bind_addr = egress.send_through.map_or_else(
        || {
            if proxy_target.is_ipv4() {
                SocketAddr::from(([0, 0, 0, 0], 0))
            } else {
                SocketAddr::from(([0_u16; 8], 0))
            }
        },
        |source| SocketAddr::new(source, 0),
    );
    let socket = std::net::UdpSocket::bind(bind_addr)?;
    apply_socket_fwmark(&socket, egress)?;
    build_ecn_safe_endpoint_from_socket(socket, None)
}

async fn connect_tuic_dialer_link(
    endpoint: &quinn::Endpoint,
    proxy_target: SocketAddr,
    link: &TuicDialerLink,
    uuid: uuid::Uuid,
) -> Result<quinn::Connection, TransportError> {
    let Some(server_name) = link.sni.as_deref() else {
        return Err(TransportError::TuicProxy {
            stage: "tls",
            message: "disable_sni TUIC links cannot be represented by the Quinn client".to_owned(),
        });
    };
    let config = build_tuic_client_config(link)?;
    let connection = endpoint
        .connect_with(config, proxy_target, server_name)?
        .await?;
    send_tuic_authentication_stream(&connection, uuid, link.password.as_bytes()).await?;
    Ok(connection)
}

fn build_tuic_client_config(link: &TuicDialerLink) -> Result<quinn::ClientConfig, TransportError> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut crypto = if link.allow_insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    crypto.alpn_protocols = link
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    let mut policy = QuicRuntimePolicy::upstream_client();
    policy.keep_alive = TUIC_CLIENT_KEEP_ALIVE;
    policy.enable_datagrams = true;
    config.transport_config(build_transport_config(&policy).into_arc());
    Ok(config)
}

async fn send_tuic_authentication_stream(
    connection: &quinn::Connection,
    uuid: uuid::Uuid,
    password: &[u8],
) -> Result<(), TransportError> {
    let token = export_connection_authentication_token(connection, uuid, password)?;
    let mut payload = Vec::with_capacity(2 + uuid.as_bytes().len() + token.len());
    payload.push(TUIC_VERSION_5);
    payload.push(TUIC_COMMAND_AUTHENTICATE);
    payload.extend_from_slice(uuid.as_bytes());
    payload.extend_from_slice(&token);
    let mut stream = connection.open_uni().await?;
    stream.write_all(&payload).await?;
    stream.finish()?;
    Ok(())
}

async fn write_tuic_tcp_connect<S>(
    stream: &mut S,
    header: &OwnedProxyHeader,
) -> Result<(), TransportError>
where
    S: AsyncWrite + Unpin,
{
    let mut request = Vec::with_capacity(2 + 1 + 255 + 2);
    request.push(TUIC_VERSION_5);
    request.push(TUIC_COMMAND_CONNECT);
    encode_tuic_target(header, &mut request)?;
    stream.write_all(&request).await?;
    Ok(())
}

fn encode_tuic_target(
    header: &OwnedProxyHeader,
    output: &mut Vec<u8>,
) -> Result<(), TransportError> {
    match &header.address {
        OwnedProxyAddress::Ipv4(address) => {
            output.push(TUIC_ADDR_IPV4);
            output.extend_from_slice(&address.octets());
        }
        OwnedProxyAddress::Ipv6(address) => {
            output.push(TUIC_ADDR_IPV6);
            output.extend_from_slice(&address.octets());
        }
        OwnedProxyAddress::Domain(domain) => {
            let bytes = domain.as_bytes();
            let len = u8::try_from(bytes.len()).map_err(|_| TransportError::TuicProxy {
                stage: "connect",
                message: "domain target exceeds 255 bytes".to_owned(),
            })?;
            output.push(TUIC_ADDR_DOMAIN);
            output.push(len);
            output.extend_from_slice(bytes);
        }
    }
    output.extend_from_slice(&header.port.to_be_bytes());
    Ok(())
}

struct TuicTcpProxyTargetStream {
    _endpoint: quinn::Endpoint,
    _connection: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for TuicTcpProxyTargetStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for TuicTcpProxyTargetStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        map_quinn_stream_poll(Pin::new(&mut self.get_mut().send).poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        map_quinn_stream_poll(Pin::new(&mut self.get_mut().send).poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        map_quinn_stream_poll(Pin::new(&mut self.get_mut().send).poll_shutdown(cx))
    }
}

fn map_quinn_stream_poll<T, E: fmt::Display>(poll: Poll<Result<T, E>>) -> Poll<std::io::Result<T>> {
    match poll {
        Poll::Ready(Ok(value)) => Poll::Ready(Ok(value)),
        Poll::Ready(Err(error)) => Poll::Ready(Err(std::io::Error::other(error.to_string()))),
        Poll::Pending => Poll::Pending,
    }
}

async fn connect_tcp_proxy_target_via_hysteria2(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    link: &Hysteria2DialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    if header.network != Network::Tcp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    let proxy_targets = tokio::net::lookup_host((link.host.as_str(), link.port)).await?;
    let proxy_egress =
        ProxyEgressPolicy::with_send_through_and_fwmark(egress.send_through, egress.fwmark);
    let mut last_error = None;
    for proxy_target in proxy_targets {
        if egress_source_mismatches_target(&proxy_egress, proxy_target) {
            continue;
        }
        let endpoint = match bind_quic_dialer_endpoint(proxy_target, &proxy_egress) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let connection = match connect_hysteria2_dialer_link(&endpoint, proxy_target, link).await {
            Ok(connection) => connection,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let (h3_driver, h3_send_request) =
            match authenticate_hysteria2_dialer_link(&connection, link).await {
                Ok(auth) => auth,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
        let (mut send, mut recv) = match connection.open_bi().await {
            Ok(streams) => streams,
            Err(error) => {
                last_error = Some(error.into());
                continue;
            }
        };
        if let Err(error) = write_hysteria2_tcp_request(&mut send, header).await {
            last_error = Some(error);
            continue;
        }
        if let Err(error) = read_hysteria2_tcp_response(&mut recv).await {
            last_error = Some(error);
            continue;
        }
        return Ok(TcpProxyTargetStream::new(
            Hysteria2TcpProxyTargetStream {
                _endpoint: endpoint,
                _connection: connection,
                _h3_driver: h3_driver,
                _h3_send_request: h3_send_request,
                send,
                recv,
            },
            proxy_target,
        ));
    }
    if let Some(error) = last_error {
        return Err(error);
    }
    Err(TransportError::NoUsableTcpTarget)
}

async fn connect_hysteria2_dialer_link(
    endpoint: &quinn::Endpoint,
    proxy_target: SocketAddr,
    link: &Hysteria2DialerLink,
) -> Result<quinn::Connection, TransportError> {
    let server_name = link.sni.as_deref().unwrap_or(link.host.as_str());
    let config = build_hysteria2_client_config(link)?;
    endpoint
        .connect_with(config, proxy_target, server_name)?
        .await
        .map_err(Into::into)
}

fn build_hysteria2_client_config(
    link: &Hysteria2DialerLink,
) -> Result<quinn::ClientConfig, TransportError> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut crypto = if let Some(pin_sha256) = link.pin_sha256.as_deref() {
        let pinned = decode_hysteria2_pin_sha256(pin_sha256)?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedLeafSha256Verification::new(&pinned)))
            .with_no_client_auth()
    } else if link.insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    crypto.alpn_protocols = vec![ALPN_H3.as_bytes().to_vec()];
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    config.transport_config(build_transport_config(&hysteria2_client_policy()).into_arc());
    Ok(config)
}

fn hysteria2_client_policy() -> QuicRuntimePolicy {
    let mut policy = QuicRuntimePolicy::upstream_client();
    policy.receive_windows = ReceiveWindowPolicy {
        initial_stream: HYSTERIA2_STREAM_RECEIVE_WINDOW,
        max_stream: HYSTERIA2_STREAM_RECEIVE_WINDOW,
        initial_connection: HYSTERIA2_CONNECTION_RECEIVE_WINDOW,
        max_connection: HYSTERIA2_CONNECTION_RECEIVE_WINDOW,
    };
    policy.keep_alive = HYSTERIA2_KEEP_ALIVE;
    policy.enable_datagrams = true;
    policy
}

async fn authenticate_hysteria2_dialer_link(
    connection: &quinn::Connection,
    link: &Hysteria2DialerLink,
) -> Result<
    (
        tokio::task::JoinHandle<()>,
        h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    ),
    TransportError,
> {
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut h3_driver, mut send_request) =
        h3::client::new(h3_connection)
            .await
            .map_err(|source| TransportError::Hysteria2Proxy {
                stage: "auth",
                message: source.to_string(),
            })?;
    let h3_driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_driver.poll_close(cx)).await;
    });

    let auth = hysteria2_auth_value(link);
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!(
            "https://{HYSTERIA2_AUTHORITY}{HYSTERIA2_AUTH_PATH}"
        ))
        .header("Hysteria-Auth", auth)
        .header("Hysteria-CC-RX", link.max_rx.unwrap_or(0).to_string())
        .header(
            "Hysteria-Padding",
            hysteria2_padding(HYSTERIA2_AUTH_PADDING_RANGE)?,
        )
        .body(())
        .map_err(|source| TransportError::Hysteria2Proxy {
            stage: "auth",
            message: source.to_string(),
        })?;
    let mut request_stream = send_request.send_request(request).await.map_err(|source| {
        TransportError::Hysteria2Proxy {
            stage: "auth",
            message: source.to_string(),
        }
    })?;
    request_stream
        .finish()
        .await
        .map_err(|source| TransportError::Hysteria2Proxy {
            stage: "auth",
            message: source.to_string(),
        })?;
    let response =
        request_stream
            .recv_response()
            .await
            .map_err(|source| TransportError::Hysteria2Proxy {
                stage: "auth",
                message: source.to_string(),
            })?;
    if response.status().as_u16() != HYSTERIA2_AUTH_STATUS_OK {
        return Err(TransportError::Hysteria2Proxy {
            stage: "auth",
            message: format!("unexpected status {}", response.status()),
        });
    }
    while request_stream
        .recv_data()
        .await
        .map_err(|source| TransportError::Hysteria2Proxy {
            stage: "auth",
            message: source.to_string(),
        })?
        .is_some()
    {}
    Ok((h3_driver, send_request))
}

fn hysteria2_auth_value(link: &Hysteria2DialerLink) -> String {
    if link.password.is_empty() {
        link.user.clone()
    } else {
        format!("{}:{}", link.user, link.password)
    }
}

fn hysteria2_padding(range: std::ops::Range<usize>) -> Result<String, TransportError> {
    let mut len_seed = [0_u8; 8];
    fill_random(&mut len_seed)?;
    let span = range.end - range.start;
    let len = range.start + (u64::from_le_bytes(len_seed) as usize % span);
    let mut output = Vec::with_capacity(len);
    let mut random = vec![0_u8; len];
    fill_random(&mut random)?;
    for byte in random {
        output.push(HYSTERIA2_PADDING_CHARS[usize::from(byte) % HYSTERIA2_PADDING_CHARS.len()]);
    }
    String::from_utf8(output).map_err(|source| TransportError::Hysteria2Proxy {
        stage: "padding",
        message: source.to_string(),
    })
}

async fn write_hysteria2_tcp_request(
    send: &mut quinn::SendStream,
    header: &OwnedProxyHeader,
) -> Result<(), TransportError> {
    let target = http_connect_authority(header);
    if target.len() > 2048 {
        return Err(TransportError::Hysteria2Proxy {
            stage: "connect",
            message: "target address exceeds Hysteria2 metadata length".to_owned(),
        });
    }
    let padding = hysteria2_padding(HYSTERIA2_TCP_REQUEST_PADDING_RANGE)?;
    let mut request = Vec::with_capacity(16 + target.len() + padding.len());
    write_hysteria2_varint(HYSTERIA2_TCP_REQUEST_FRAME_TYPE, &mut request)?;
    write_hysteria2_varint(target.len() as u64, &mut request)?;
    request.extend_from_slice(target.as_bytes());
    write_hysteria2_varint(padding.len() as u64, &mut request)?;
    request.extend_from_slice(padding.as_bytes());
    send.write_all(&request).await?;
    Ok(())
}

async fn read_hysteria2_tcp_response(recv: &mut quinn::RecvStream) -> Result<(), TransportError> {
    let mut status = [0_u8; 1];
    recv.read_exact(&mut status).await?;
    let message_len = read_hysteria2_varint(recv).await?;
    if message_len > 2048 {
        return Err(TransportError::Hysteria2Proxy {
            stage: "connect",
            message: "response message exceeds Hysteria2 metadata length".to_owned(),
        });
    }
    let mut message = vec![0_u8; message_len as usize];
    if !message.is_empty() {
        recv.read_exact(&mut message).await?;
    }
    let padding_len = read_hysteria2_varint(recv).await?;
    if padding_len > 4096 {
        return Err(TransportError::Hysteria2Proxy {
            stage: "connect",
            message: "response padding exceeds Hysteria2 metadata length".to_owned(),
        });
    }
    if padding_len != 0 {
        let mut padding = vec![0_u8; padding_len as usize];
        recv.read_exact(&mut padding).await?;
    }
    if status[0] != 0 {
        let message = String::from_utf8_lossy(&message).into_owned();
        return Err(TransportError::Hysteria2Proxy {
            stage: "connect",
            message,
        });
    }
    Ok(())
}

async fn read_hysteria2_varint(recv: &mut quinn::RecvStream) -> Result<u64, TransportError> {
    let mut first = [0_u8; 1];
    recv.read_exact(&mut first).await?;
    let tag = first[0] >> 6;
    let len = 1usize << tag;
    let mut value = u64::from(first[0] & 0x3f);
    for _ in 1..len {
        let mut byte = [0_u8; 1];
        recv.read_exact(&mut byte).await?;
        value = (value << 8) | u64::from(byte[0]);
    }
    Ok(value)
}

fn write_hysteria2_varint(value: u64, output: &mut Vec<u8>) -> Result<(), TransportError> {
    if value <= 63 {
        output.push(value as u8);
    } else if value <= 16_383 {
        output.push(((value >> 8) as u8) | 0x40);
        output.push(value as u8);
    } else if value <= 1_073_741_823 {
        output.push(((value >> 24) as u8) | 0x80);
        output.extend_from_slice(&[(value >> 16) as u8, (value >> 8) as u8, value as u8]);
    } else if value <= 4_611_686_018_427_387_903 {
        output.push(((value >> 56) as u8) | 0xc0);
        output.extend_from_slice(&[
            (value >> 48) as u8,
            (value >> 40) as u8,
            (value >> 32) as u8,
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ]);
    } else {
        return Err(TransportError::Hysteria2Proxy {
            stage: "varint",
            message: format!("value {value} exceeds QUIC varint range"),
        });
    }
    Ok(())
}

fn decode_hysteria2_pin_sha256(value: &str) -> Result<Vec<u8>, TransportError> {
    let decoded = match decode_padded_base64_bytes(&general_purpose::STANDARD, value) {
        Ok(decoded) => decoded,
        Err(standard_error) => match decode_padded_base64_bytes(&general_purpose::URL_SAFE, value) {
            Ok(decoded) => decoded,
            Err(url_safe_error) => decode_hex_sha256(value).map_err(|hex_error| {
                TransportError::Hysteria2Proxy {
                    stage: "tls",
                    message: format!(
                        "invalid pinSHA256: standard base64 {standard_error}; url-safe base64 {url_safe_error}; hex {hex_error}"
                    ),
                }
            })?,
        },
    };
    if decoded.len() != 32 {
        return Err(TransportError::Hysteria2Proxy {
            stage: "tls",
            message: format!("pinSHA256 decoded to {} bytes, expected 32", decoded.len()),
        });
    }
    Ok(decoded)
}

fn decode_hex_sha256(value: &str) -> Result<Vec<u8>, String> {
    if value.len() != 64 {
        return Err(format!("hex length {} is not 64", value.len()));
    }
    if !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err("hex contains non-hex characters".to_owned());
    }
    let mut output = Vec::with_capacity(32);
    for index in (0..value.len()).step_by(2) {
        let byte = u8::from_str_radix(&value[index..index + 2], 16)
            .map_err(|source| source.to_string())?;
        output.push(byte);
    }
    Ok(output)
}

struct Hysteria2TcpProxyTargetStream {
    _endpoint: quinn::Endpoint,
    _connection: quinn::Connection,
    _h3_driver: tokio::task::JoinHandle<()>,
    _h3_send_request: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for Hysteria2TcpProxyTargetStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Hysteria2TcpProxyTargetStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        map_quinn_stream_poll(Pin::new(&mut self.get_mut().send).poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        map_quinn_stream_poll(Pin::new(&mut self.get_mut().send).poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        map_quinn_stream_poll(Pin::new(&mut self.get_mut().send).poll_shutdown(cx))
    }
}

async fn connect_tcp_proxy_target_via_juicity(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    link: &JuicityDialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    let proxy_targets = tokio::net::lookup_host((link.host.as_str(), link.port)).await?;
    let proxy_egress =
        ProxyEgressPolicy::with_send_through_and_fwmark(egress.send_through, egress.fwmark);
    let mut last_error = None;
    for proxy_target in proxy_targets {
        if egress_source_mismatches_target(&proxy_egress, proxy_target) {
            continue;
        }
        let client = match bind_juicity_dialer_client(proxy_target, &proxy_egress) {
            Ok(client) => client,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let connection = match connect_juicity_dialer_link(&client, proxy_target, link).await {
            Ok(connection) => connection,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let stream = match open_juicity_tcp_proxy_stream(&connection, header).await {
            Ok(stream) => stream,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        return Ok(TcpProxyTargetStream::new(
            JuicityTcpProxyTargetStream {
                _client: client,
                _connection: connection,
                stream,
            },
            proxy_target,
        ));
    }
    if let Some(error) = last_error {
        return Err(error);
    }
    Err(TransportError::NoUsableTcpTarget)
}

fn bind_juicity_dialer_client(
    proxy_target: SocketAddr,
    egress: &ProxyEgressPolicy,
) -> Result<JuicityQuicClient, TransportError> {
    let bind_addr = egress.send_through.map_or_else(
        || {
            if proxy_target.is_ipv4() {
                SocketAddr::from(([0, 0, 0, 0], 0))
            } else {
                SocketAddr::from(([0_u16; 8], 0))
            }
        },
        |source| SocketAddr::new(source, 0),
    );
    let socket = std::net::UdpSocket::bind(bind_addr)?;
    apply_socket_fwmark(&socket, egress)?;
    let endpoint = build_ecn_safe_endpoint_from_socket(socket, None)?;
    Ok(JuicityQuicClient { endpoint })
}

async fn connect_juicity_dialer_link(
    client: &JuicityQuicClient,
    proxy_target: SocketAddr,
    link: &JuicityDialerLink,
) -> Result<AuthenticatedConnection, TransportError> {
    if let Some(pinned) = &link.pinned_cert_chain_sha256 {
        return client
            .connect_with_cert_chain_pin(
                proxy_target,
                &link.sni,
                pinned,
                link.uuid,
                link.password.as_bytes(),
            )
            .await;
    }
    let config = build_client_config_with_webpki_roots(link.allow_insecure)?;
    let connection = client
        .endpoint
        .connect_with(config.inner, proxy_target, &link.sni)?
        .await?;
    send_authentication_stream(&connection, link.uuid, link.password.as_bytes()).await?;
    Ok(AuthenticatedConnection {
        connection,
        protocol: ProxyProtocol::Juicity,
    })
}

async fn open_juicity_tcp_proxy_stream(
    connection: &AuthenticatedConnection,
    header: &OwnedProxyHeader,
) -> Result<TcpProxyStream, TransportError> {
    match &header.address {
        OwnedProxyAddress::Ipv4(address) => {
            connection
                .open_tcp_proxy_stream(IpAddr::V4(*address), header.port)
                .await
        }
        OwnedProxyAddress::Ipv6(address) => {
            connection
                .open_tcp_proxy_stream(IpAddr::V6(*address), header.port)
                .await
        }
        OwnedProxyAddress::Domain(domain) => {
            connection
                .open_tcp_proxy_domain_stream(domain, header.port)
                .await
        }
    }
}

async fn open_juicity_udp_proxy_stream(
    connection: &AuthenticatedConnection,
    header: &OwnedProxyHeader,
) -> Result<UdpOverStream, TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    match &header.address {
        OwnedProxyAddress::Ipv4(address) => {
            connection
                .open_udp_over_stream(IpAddr::V4(*address), header.port)
                .await
        }
        OwnedProxyAddress::Ipv6(address) => {
            connection
                .open_udp_over_stream(IpAddr::V6(*address), header.port)
                .await
        }
        OwnedProxyAddress::Domain(domain) => {
            connection
                .open_udp_over_domain_stream(domain, header.port)
                .await
        }
    }
}

struct JuicityTcpProxyTargetStream {
    _client: JuicityQuicClient,
    _connection: AuthenticatedConnection,
    stream: TcpProxyStream,
}

impl AsyncRead for JuicityTcpProxyTargetStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for JuicityTcpProxyTargetStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.get_mut().stream.send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().stream.send), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().stream.send), cx)
    }
}

async fn connect_trojan_stream(
    stream: TcpProxyTargetStream,
    header: &OwnedProxyHeader,
    link: &TrojanDialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    let peer_addr = stream.peer_addr();
    let config = build_http_connect_tls_client_config(link.allow_insecure)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name =
        rustls::pki_types::ServerName::try_from(link.sni.clone()).map_err(|source| {
            TransportError::TrojanProxy {
                stage: "tls",
                message: format!("invalid server name: {source}"),
            }
        })?;
    let mut stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|source| TransportError::TrojanProxy {
            stage: "tls",
            message: source.to_string(),
        })?;
    write_trojan_tcp_request_header(&mut stream, header, link).await?;
    Ok(TcpProxyTargetStream::new(stream, peer_addr))
}

async fn write_trojan_tcp_request_header<S>(
    stream: &mut S,
    header: &OwnedProxyHeader,
    link: &TrojanDialerLink,
) -> Result<(), TransportError>
where
    S: AsyncWrite + Unpin,
{
    let mut request = Vec::with_capacity(96);
    request.extend_from_slice(&trojan_password_sha224_hex(&link.password));
    request.extend_from_slice(b"\r\n");
    request.push(trojan_network_byte(header.network)?);
    encode_trojan_metadata(&mut request, header)?;
    request.extend_from_slice(b"\r\n");
    stream.write_all(&request).await?;
    Ok(())
}

fn trojan_password_sha224_hex(password: &str) -> [u8; 56] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha224::digest(password.as_bytes());
    let mut output = [0_u8; 56];
    for (index, byte) in digest.iter().enumerate() {
        output[index * 2] = HEX[(byte >> 4) as usize];
        output[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    output
}

fn trojan_network_byte(network: Network) -> Result<u8, TransportError> {
    match network {
        Network::Tcp => Ok(1),
        Network::Udp => Ok(3),
    }
}

fn encode_trojan_metadata(
    request: &mut Vec<u8>,
    header: &OwnedProxyHeader,
) -> Result<(), TransportError> {
    match &header.address {
        OwnedProxyAddress::Ipv4(address) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        OwnedProxyAddress::Ipv6(address) => {
            request.push(4);
            request.extend_from_slice(&address.octets());
        }
        OwnedProxyAddress::Domain(domain) => {
            let len = u8::try_from(domain.len()).map_err(|_| TransportError::TrojanProxy {
                stage: "request",
                message: "domain target exceeds Trojan metadata length".to_owned(),
            })?;
            request.push(3);
            request.push(len);
            request.extend_from_slice(domain.as_bytes());
        }
    }
    request.extend_from_slice(&header.port.to_be_bytes());
    Ok(())
}

async fn write_trojan_udp_packet_frame<S>(
    stream: &mut S,
    header: &OwnedProxyHeader,
    payload: &[u8],
) -> Result<(), TransportError>
where
    S: AsyncWrite + Unpin,
{
    let payload_len = u16::try_from(payload.len()).map_err(|_| TransportError::TrojanProxy {
        stage: "udp packet",
        message: "UDP payload exceeds Trojan packet length".to_owned(),
    })?;
    let mut frame = Vec::with_capacity(32 + payload.len());
    encode_trojan_metadata(&mut frame, header)?;
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(b"\r\n");
    frame.extend_from_slice(payload);
    stream.write_all(&frame).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_trojan_udp_packet_frame<S>(
    stream: &mut S,
    payload: &mut [u8],
) -> Result<(SocketAddr, usize), TransportError>
where
    S: AsyncRead + Unpin,
{
    let peer = read_trojan_udp_metadata(stream, "udp response").await?;
    let mut payload_len = [0_u8; 2];
    stream.read_exact(&mut payload_len).await?;
    let payload_len = usize::from(u16::from_be_bytes(payload_len));
    let mut crlf = [0_u8; 2];
    stream.read_exact(&mut crlf).await?;
    if crlf != *b"\r\n" {
        return Err(TransportError::TrojanProxy {
            stage: "udp response",
            message: "missing Trojan UDP packet CRLF".to_owned(),
        });
    }
    if payload_len > payload.len() {
        return Err(TransportError::TrojanProxy {
            stage: "udp response",
            message: "Trojan UDP response exceeds receive buffer".to_owned(),
        });
    }
    stream.read_exact(&mut payload[..payload_len]).await?;
    Ok((peer, payload_len))
}

async fn read_trojan_udp_metadata<S>(
    stream: &mut S,
    stage: &'static str,
) -> Result<SocketAddr, TransportError>
where
    S: AsyncRead + Unpin,
{
    let mut address_type = [0_u8; 1];
    stream.read_exact(&mut address_type).await?;
    match address_type[0] {
        1 => {
            let mut raw = [0_u8; 4];
            stream.read_exact(&mut raw).await?;
            let port = read_trojan_udp_port(stream).await?;
            Ok(SocketAddr::new(IpAddr::from(raw), port))
        }
        3 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0_u8; usize::from(len[0])];
            stream.read_exact(&mut domain).await?;
            let domain = std::str::from_utf8(&domain)?.to_owned();
            let port = read_trojan_udp_port(stream).await?;
            tokio::net::lookup_host((domain.as_str(), port))
                .await?
                .next()
                .ok_or(TransportError::NoUsableUdpTarget)
        }
        4 => {
            let mut raw = [0_u8; 16];
            stream.read_exact(&mut raw).await?;
            let port = read_trojan_udp_port(stream).await?;
            Ok(SocketAddr::new(IpAddr::from(raw), port))
        }
        value => Err(TransportError::TrojanProxy {
            stage,
            message: format!("unsupported Trojan UDP metadata type {value}"),
        }),
    }
}

async fn read_trojan_udp_port<S>(stream: &mut S) -> Result<u16, TransportError>
where
    S: AsyncRead + Unpin,
{
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(u16::from_be_bytes(port))
}

async fn connect_tcp_proxy_target_via_shadowsocks(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    link: &ShadowsocksDialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    let proxy_targets = tokio::net::lookup_host((link.host.as_str(), link.port)).await?;
    let proxy_egress =
        ProxyEgressPolicy::with_send_through_and_fwmark(egress.send_through, egress.fwmark);
    let mut last_error = None;
    for proxy_target in proxy_targets {
        if egress_source_mismatches_target(&proxy_egress, proxy_target) {
            continue;
        }
        let stream = match connect_tcp_socket_to_target(proxy_target, &proxy_egress).await {
            Ok(stream) => stream,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let stream = TcpProxyTargetStream::plain(stream)?;
        return connect_shadowsocks_stream(stream, header, link);
    }
    if let Some(error) = last_error {
        return Err(error.into());
    }
    Err(TransportError::NoUsableTcpTarget)
}

fn connect_shadowsocks_stream(
    stream: TcpProxyTargetStream,
    header: &OwnedProxyHeader,
    link: &ShadowsocksDialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    let server_config = link.server_config()?;
    let context = shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Local);
    let target = shadowsocks_target_address(header);
    let peer_addr = stream.peer_addr();
    let stream =
        shadowsocks::ProxyClientStream::from_stream(context, stream, &server_config, target);
    Ok(TcpProxyTargetStream::new(stream, peer_addr))
}

fn shadowsocks_target_address(header: &OwnedProxyHeader) -> shadowsocks::relay::socks5::Address {
    match &header.address {
        OwnedProxyAddress::Ipv4(address) => shadowsocks::relay::socks5::Address::SocketAddress(
            SocketAddr::new(IpAddr::V4(*address), header.port),
        ),
        OwnedProxyAddress::Ipv6(address) => shadowsocks::relay::socks5::Address::SocketAddress(
            SocketAddr::new(IpAddr::V6(*address), header.port),
        ),
        OwnedProxyAddress::Domain(domain) => {
            shadowsocks::relay::socks5::Address::DomainNameAddress(domain.clone(), header.port)
        }
    }
}

async fn connect_tcp_proxy_target_via_socks5(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    link: &Socks5DialerLink,
) -> Result<TcpProxyTargetStream, TransportError> {
    let proxy_targets = tokio::net::lookup_host((link.host.as_str(), link.port)).await?;
    let proxy_egress =
        ProxyEgressPolicy::with_send_through_and_fwmark(egress.send_through, egress.fwmark);
    let mut last_error = None;
    for proxy_target in proxy_targets {
        if egress_source_mismatches_target(&proxy_egress, proxy_target) {
            continue;
        }
        let stream = match connect_tcp_socket_to_target(proxy_target, &proxy_egress).await {
            Ok(stream) => stream,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let mut stream = TcpProxyTargetStream::plain(stream)?;
        socks5_connect(&mut stream, header, link).await?;
        return Ok(stream);
    }
    if let Some(error) = last_error {
        return Err(error.into());
    }
    Err(TransportError::NoUsableTcpTarget)
}

async fn socks5_negotiate_auth<S>(
    stream: &mut S,
    link: &Socks5DialerLink,
) -> Result<(), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let method = if link.username.is_some() || link.password.is_some() {
        0x02
    } else {
        0x00
    };
    stream.write_all(&[0x05, 0x01, method]).await?;
    let mut method_response = [0_u8; 2];
    stream.read_exact(&mut method_response).await?;
    if method_response[0] != 0x05 || method_response[1] == 0xff {
        return Err(TransportError::Socks5Proxy {
            stage: "method selection",
            message: format!("unexpected response {method_response:?}"),
        });
    }
    if method_response[1] == 0x02 {
        socks5_username_password_auth(stream, link).await?;
    } else if method_response[1] != method {
        return Err(TransportError::Socks5Proxy {
            stage: "method selection",
            message: format!(
                "proxy selected unsupported method {:#x}",
                method_response[1]
            ),
        });
    }
    Ok(())
}

async fn socks5_connect<S>(
    stream: &mut S,
    header: &OwnedProxyHeader,
    link: &Socks5DialerLink,
) -> Result<(), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    socks5_negotiate_auth(stream, link).await?;

    let mut request = Vec::with_capacity(4 + 1 + 255 + 2);
    request.extend_from_slice(&[0x05, 0x01, 0x00]);
    encode_socks5_target(header, &mut request)?;
    stream.write_all(&request).await?;

    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(TransportError::Socks5Proxy {
            stage: "connect",
            message: format!("unexpected response {response:?}"),
        });
    }
    let address_len = match response[3] {
        0x01 => 4,
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0])
        }
        0x04 => 16,
        other => {
            return Err(TransportError::Socks5Proxy {
                stage: "connect",
                message: format!("unsupported bind address type {other:#x}"),
            });
        }
    };
    let mut ignored = vec![0_u8; address_len + 2];
    stream.read_exact(&mut ignored).await?;
    Ok(())
}

async fn socks5_username_password_auth<S>(
    stream: &mut S,
    link: &Socks5DialerLink,
) -> Result<(), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let username = link.username.as_deref().unwrap_or_default().as_bytes();
    let password = link.password.as_deref().unwrap_or_default().as_bytes();
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err(TransportError::Socks5Proxy {
            stage: "username/password auth",
            message: "credential field exceeds 255 bytes".to_owned(),
        });
    }
    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.push(0x01);
    request.push(username.len() as u8);
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream.write_all(&request).await?;
    let mut response = [0_u8; 2];
    stream.read_exact(&mut response).await?;
    if response != [0x01, 0x00] {
        return Err(TransportError::Socks5Proxy {
            stage: "username/password auth",
            message: format!("unexpected response {response:?}"),
        });
    }
    Ok(())
}

fn encode_socks5_target(
    header: &OwnedProxyHeader,
    output: &mut Vec<u8>,
) -> Result<(), TransportError> {
    output.reserve(1 + 255 + 2);
    match &header.address {
        OwnedProxyAddress::Ipv4(address) => {
            output.push(0x01);
            output.extend_from_slice(&address.octets());
        }
        OwnedProxyAddress::Ipv6(address) => {
            output.push(0x04);
            output.extend_from_slice(&address.octets());
        }
        OwnedProxyAddress::Domain(domain) => {
            let bytes = domain.as_bytes();
            let len = u8::try_from(bytes.len()).map_err(|_| TransportError::Socks5Proxy {
                stage: "connect",
                message: "domain target exceeds 255 bytes".to_owned(),
            })?;
            output.push(0x03);
            output.push(len);
            output.extend_from_slice(bytes);
        }
    }
    output.extend_from_slice(&header.port.to_be_bytes());
    Ok(())
}

async fn connect_tcp_socket_to_target(
    target: SocketAddr,
    egress: &ProxyEgressPolicy,
) -> std::io::Result<tokio::net::TcpStream> {
    if egress.send_through.is_none() && egress.fwmark.is_none() {
        return tokio::net::TcpStream::connect(target).await;
    }
    let socket = if target.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    if let Some(source_ip) = egress.send_through {
        socket.bind(SocketAddr::new(source_ip, 0))?;
    }
    apply_socket_fwmark(&socket, egress)?;
    socket.connect(target).await
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn apply_socket_fwmark<S>(socket: &S, egress: &ProxyEgressPolicy) -> std::io::Result<()>
where
    S: std::os::fd::AsFd,
{
    if let Some(fwmark) = egress.fwmark {
        socket2::SockRef::from(socket).set_mark(fwmark)?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
fn apply_socket_fwmark<S>(_socket: &S, egress: &ProxyEgressPolicy) -> std::io::Result<()> {
    if egress.fwmark.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "fwmark requires SO_MARK-compatible target OS",
        ));
    }
    Ok(())
}

fn egress_source_mismatches_target(egress: &ProxyEgressPolicy, target: SocketAddr) -> bool {
    egress
        .send_through
        .is_some_and(|source| source.is_ipv4() != target.is_ipv4())
}

fn udp_relay_bind_addr(target_is_ipv4: bool, egress: &ProxyEgressPolicy) -> SocketAddr {
    if let Some(source_ip) = egress.send_through {
        return SocketAddr::new(source_ip, 0);
    }
    if target_is_ipv4 {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0_u16; 8], 0))
    }
}

fn udp_ip_header_target(header: &OwnedProxyHeader) -> Result<SocketAddr, TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    match &header.address {
        OwnedProxyAddress::Ipv4(address) => Ok(SocketAddr::new(IpAddr::V4(*address), header.port)),
        OwnedProxyAddress::Ipv6(address) => match address.to_ipv4_mapped() {
            Some(mapped) => Ok(SocketAddr::new(IpAddr::V4(mapped), header.port)),
            None => Ok(SocketAddr::new(IpAddr::V6(*address), header.port)),
        },
        OwnedProxyAddress::Domain(_) => Err(TransportError::UnsupportedDomainTarget),
    }
}

async fn udp_header_targets(header: &OwnedProxyHeader) -> Result<Vec<SocketAddr>, TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    match &header.address {
        OwnedProxyAddress::Ipv4(address) => {
            Ok(vec![SocketAddr::new(IpAddr::V4(*address), header.port)])
        }
        OwnedProxyAddress::Ipv6(address) => {
            Ok(vec![SocketAddr::new(IpAddr::V6(*address), header.port)])
        }
        OwnedProxyAddress::Domain(domain) => {
            Ok(tokio::net::lookup_host((domain.as_str(), header.port))
                .await?
                .collect())
        }
    }
}

async fn relay_udp_payload_to_target_with_socket(
    relay_socket: &mut Option<(bool, tokio::net::UdpSocket)>,
    header: &OwnedProxyHeader,
    payload: &[u8],
    egress: &ProxyEgressPolicy,
) -> Result<(SocketAddr, SocketAddr, Vec<u8>), TransportError> {
    let targets = udp_header_targets(header).await?;
    for target in targets {
        if egress_source_mismatches_target(&egress, target) {
            continue;
        }
        let target_is_ipv4 = target.is_ipv4();
        let needs_socket = match relay_socket {
            Some((socket_is_ipv4, _)) => *socket_is_ipv4 != target_is_ipv4,
            None => true,
        };
        if needs_socket {
            let bind_addr = udp_relay_bind_addr(target_is_ipv4, egress);
            let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
            apply_socket_fwmark(&socket, egress)?;
            *relay_socket = Some((target_is_ipv4, socket));
        }

        let socket = &relay_socket
            .as_ref()
            .ok_or(TransportError::NoUsableUdpTarget)?
            .1;
        socket.send_to(payload, target).await?;
        let mut response = vec![0_u8; 65_535];
        let received =
            tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut response)).await;
        let Ok(received) = received else {
            continue;
        };
        let (received, peer) = received?;
        response.truncate(received);
        return Ok((target, peer, response));
    }
    Err(TransportError::NoUsableUdpTarget)
}

enum UdpEgressRelayState {
    Direct(Option<(bool, tokio::net::UdpSocket)>),
    Socks5(Option<Socks5UdpAssociation>),
    Shadowsocks(Option<ShadowsocksUdpAssociation>),
    Juicity(Option<JuicityUdpAssociation>),
    Tuic(Option<TuicUdpAssociation>),
    Hysteria2(Option<Hysteria2UdpAssociation>),
    Trojan(Option<TrojanUdpAssociation>),
    Vless(Option<VlessUdpAssociation>),
    Vmess(Option<VmessUdpAssociation>),
}

impl Default for UdpEgressRelayState {
    fn default() -> Self {
        Self::Direct(None)
    }
}

struct Socks5UdpAssociation {
    _control: TcpProxyTargetStream,
    socket: Socks5UdpRelaySocket,
    relay_addr: SocketAddr,
}

enum Socks5UdpRelaySocket {
    Direct(tokio::net::UdpSocket),
    Shadowsocks(shadowsocks::ProxySocket<shadowsocks::net::UdpSocket>),
}

impl Socks5UdpRelaySocket {
    async fn send_to(&self, datagram: &[u8], relay_addr: SocketAddr) -> Result<(), TransportError> {
        match self {
            Self::Direct(socket) => {
                socket.send_to(datagram, relay_addr).await?;
                Ok(())
            }
            Self::Shadowsocks(socket) => {
                socket
                    .send(
                        &shadowsocks::relay::socks5::Address::SocketAddress(relay_addr),
                        datagram,
                    )
                    .await
                    .map_err(std::io::Error::from)?;
                Ok(())
            }
        }
    }

    async fn recv_from(&self, response: &mut [u8]) -> Result<(usize, SocketAddr), TransportError> {
        match self {
            Self::Direct(socket) => Ok(socket.recv_from(response).await?),
            Self::Shadowsocks(socket) => {
                let (received, peer, _packet_len) =
                    socket.recv(response).await.map_err(std::io::Error::from)?;
                Ok((received, shadowsocks_address_to_socket_addr(&peer).await?))
            }
        }
    }
}

struct ShadowsocksUdpAssociation {
    socket: ShadowsocksUdpRelaySocket,
}

enum ShadowsocksUdpRelaySocket {
    Direct(shadowsocks::ProxySocket<shadowsocks::net::UdpSocket>),
    Socks5(shadowsocks::ProxySocket<Socks5UdpPacketSocket>),
}

impl ShadowsocksUdpRelaySocket {
    async fn send(
        &self,
        target: &shadowsocks::relay::socks5::Address,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        match self {
            Self::Direct(socket) => {
                socket
                    .send(target, payload)
                    .await
                    .map_err(std::io::Error::from)?;
                Ok(())
            }
            Self::Socks5(socket) => {
                socket
                    .send(target, payload)
                    .await
                    .map_err(std::io::Error::from)?;
                Ok(())
            }
        }
    }

    async fn recv(
        &self,
        response: &mut [u8],
    ) -> Result<(usize, shadowsocks::relay::socks5::Address, usize), TransportError> {
        match self {
            Self::Direct(socket) => socket
                .recv(response)
                .await
                .map_err(std::io::Error::from)
                .map_err(Into::into),
            Self::Socks5(socket) => socket
                .recv(response)
                .await
                .map_err(std::io::Error::from)
                .map_err(Into::into),
        }
    }
}

struct Socks5UdpPacketSocket {
    _control: Arc<tokio::sync::Mutex<TcpProxyTargetStream>>,
    socket: tokio::net::UdpSocket,
    relay_addr: SocketAddr,
    target_header: OwnedProxyHeader,
}

impl shadowsocks::relay::udprelay::DatagramSocket for Socks5UdpPacketSocket {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

impl shadowsocks::relay::udprelay::DatagramSend for Socks5UdpPacketSocket {
    fn poll_send(&self, cx: &mut Context<'_>, payload: &[u8]) -> Poll<std::io::Result<usize>> {
        self.poll_send_socks5_datagram(cx, &self.target_header, payload)
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        payload: &[u8],
        target: SocketAddr,
    ) -> Poll<std::io::Result<usize>> {
        let target_header = OwnedProxyHeader::from_ip(Network::Udp, target.ip(), target.port());
        self.poll_send_socks5_datagram(cx, &target_header, payload)
    }

    fn poll_send_ready(&self, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl shadowsocks::relay::udprelay::DatagramReceive for Socks5UdpPacketSocket {
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.poll_recv_socks5_datagram(cx, output) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SocketAddr>> {
        self.poll_recv_socks5_datagram(cx, output)
    }

    fn poll_recv_ready(&self, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Socks5UdpPacketSocket {
    fn poll_send_socks5_datagram(
        &self,
        cx: &mut Context<'_>,
        target: &OwnedProxyHeader,
        payload: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let datagram = encode_socks5_udp_datagram(target, payload).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
        })?;
        match self.socket.poll_send_to(cx, &datagram, self.relay_addr) {
            Poll::Ready(Ok(sent)) if sent == datagram.len() => Poll::Ready(Ok(payload.len())),
            Poll::Ready(Ok(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "partial SOCKS5 UDP datagram write",
            ))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_recv_socks5_datagram(
        &self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SocketAddr>> {
        let mut packet = vec![0_u8; 65_535];
        let mut packet_buf = ReadBuf::new(packet.as_mut_slice());
        let relay_peer = match self.socket.poll_recv_from(cx, &mut packet_buf) {
            Poll::Ready(Ok(peer)) => peer,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        };
        let received = packet_buf.filled().len();
        let (peer, payload_offset) = decode_socks5_udp_response_header(&packet[..received])
            .map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
            })?;
        let payload = &packet[payload_offset..received];
        if output.remaining() < payload.len() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS5 UDP payload exceeded receive buffer",
            )));
        }
        output.put_slice(payload);
        let _ = relay_peer;
        Poll::Ready(Ok(peer))
    }
}

struct JuicityUdpAssociation {
    _client: JuicityQuicClient,
    _connection: AuthenticatedConnection,
    header: OwnedProxyHeader,
    stream: UdpOverStream,
}

impl Drop for JuicityUdpAssociation {
    fn drop(&mut self) {
        let _ = self.stream.finish();
    }
}

struct TuicUdpAssociation {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    header: OwnedProxyHeader,
    association_id: u16,
    next_packet_id: u16,
}

struct TuicUdpPacket {
    association_id: u16,
    packet_id: u16,
    target: SocketAddr,
    payload: Vec<u8>,
}

struct Hysteria2UdpAssociation {
    _endpoint: quinn::Endpoint,
    _h3_driver: tokio::task::JoinHandle<()>,
    _h3_send_request: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    connection: quinn::Connection,
    header: OwnedProxyHeader,
    session_id: u32,
}

struct Hysteria2UdpPacket {
    addr: String,
    payload: Vec<u8>,
}

struct TrojanUdpAssociation {
    stream: TcpProxyTargetStream,
}

struct VlessUdpAssociation {
    header: OwnedProxyHeader,
    stream: TcpProxyTargetStream,
}

struct VmessUdpAssociation {
    header: OwnedProxyHeader,
    stream: TcpProxyTargetStream,
    context: VmessStreamContext,
    request: VmessBodyContext,
    response: VmessBodyContext,
    response_header_read: bool,
}

async fn relay_udp_payload_to_target_with_egress(
    relay_state: &mut UdpEgressRelayState,
    header: &OwnedProxyHeader,
    payload: &[u8],
    egress: &ProxyEgressPolicy,
) -> Result<(SocketAddr, SocketAddr, Vec<u8>), TransportError> {
    match &egress.dialer_link {
        Some(ProxyDialerLink::HttpConnect(link)) => {
            Err(TransportError::UnsupportedProxyDialerLinkNetwork {
                scheme: link.scheme(),
                network: Network::Udp,
            })
        }
        Some(ProxyDialerLink::Chain(links)) => {
            relay_udp_payload_to_target_via_dialer_chain(
                relay_state,
                header,
                payload,
                egress,
                links,
            )
            .await
        }
        Some(ProxyDialerLink::Shadowsocks(link)) => {
            relay_udp_payload_to_target_via_shadowsocks(relay_state, header, payload, egress, link)
                .await
        }
        Some(ProxyDialerLink::ShadowsocksR(link)) => {
            relay_udp_payload_to_target_via_shadowsocks(
                relay_state,
                header,
                payload,
                egress,
                &link.shadowsocks,
            )
            .await
        }
        Some(ProxyDialerLink::Trojan(link)) => {
            relay_udp_payload_to_target_via_trojan(relay_state, header, payload, egress, link).await
        }
        Some(ProxyDialerLink::Juicity(link)) => {
            relay_udp_payload_to_target_via_juicity(relay_state, header, payload, egress, link)
                .await
        }
        Some(ProxyDialerLink::Tuic(link)) => {
            relay_udp_payload_to_target_via_tuic(relay_state, header, payload, egress, link).await
        }
        Some(ProxyDialerLink::Hysteria2(link)) => {
            relay_udp_payload_to_target_via_hysteria2(relay_state, header, payload, egress, link)
                .await
        }
        Some(ProxyDialerLink::Vmess(link)) => {
            relay_udp_payload_to_target_via_vmess(relay_state, header, payload, egress, link).await
        }
        Some(ProxyDialerLink::Vless(link)) => {
            relay_udp_payload_to_target_via_vless(relay_state, header, payload, egress, link).await
        }
        Some(ProxyDialerLink::Socks5(link)) => {
            relay_udp_payload_to_target_via_socks5(relay_state, header, payload, egress, link).await
        }
        None => {
            if !matches!(relay_state, UdpEgressRelayState::Direct(_)) {
                *relay_state = UdpEgressRelayState::Direct(None);
            }
            let UdpEgressRelayState::Direct(relay_socket) = relay_state else {
                unreachable!("relay state was reset to direct")
            };
            relay_udp_payload_to_target_with_socket(relay_socket, header, payload, egress).await
        }
    }
}

async fn relay_udp_payload_to_target_via_socks5(
    relay_state: &mut UdpEgressRelayState,
    header: &OwnedProxyHeader,
    payload: &[u8],
    egress: &ProxyEgressPolicy,
    link: &Socks5DialerLink,
) -> Result<(SocketAddr, SocketAddr, Vec<u8>), TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    if !matches!(relay_state, UdpEgressRelayState::Socks5(_)) {
        *relay_state = UdpEgressRelayState::Socks5(None);
    }
    let UdpEgressRelayState::Socks5(association) = relay_state else {
        unreachable!("relay state was reset to SOCKS5")
    };
    if association.is_none() {
        *association = Some(connect_socks5_udp_association(egress, link).await?);
    }
    let association = association
        .as_ref()
        .ok_or(TransportError::NoUsableUdpTarget)?;
    relay_udp_payload_to_target_with_socks5_association(
        header,
        payload,
        &association.socket,
        association.relay_addr,
    )
    .await
}

async fn relay_udp_payload_to_target_via_dialer_chain(
    relay_state: &mut UdpEgressRelayState,
    header: &OwnedProxyHeader,
    payload: &[u8],
    egress: &ProxyEgressPolicy,
    links: &[ProxyDialerLink],
) -> Result<(SocketAddr, SocketAddr, Vec<u8>), TransportError> {
    match links {
        [
            ProxyDialerLink::Socks5(socks5),
            ProxyDialerLink::Shadowsocks(shadowsocks),
        ] => {
            relay_udp_payload_to_target_via_socks5_shadowsocks_chain(
                relay_state,
                header,
                payload,
                egress,
                socks5,
                shadowsocks,
            )
            .await
        }
        [
            ProxyDialerLink::Shadowsocks(shadowsocks),
            ProxyDialerLink::Socks5(socks5),
        ] => {
            relay_udp_payload_to_target_via_shadowsocks_socks5_chain(
                relay_state,
                header,
                payload,
                egress,
                shadowsocks,
                socks5,
            )
            .await
        }
        _ => Err(TransportError::UnsupportedProxyDialerLinkNetwork {
            scheme: "chain",
            network: Network::Udp,
        }),
    }
}

async fn relay_udp_payload_to_target_via_shadowsocks_socks5_chain(
    relay_state: &mut UdpEgressRelayState,
    header: &OwnedProxyHeader,
    payload: &[u8],
    egress: &ProxyEgressPolicy,
    shadowsocks: &ShadowsocksDialerLink,
    socks5: &Socks5DialerLink,
) -> Result<(SocketAddr, SocketAddr, Vec<u8>), TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    if !matches!(relay_state, UdpEgressRelayState::Shadowsocks(_)) {
        *relay_state = UdpEgressRelayState::Shadowsocks(None);
    }
    let UdpEgressRelayState::Shadowsocks(association) = relay_state else {
        unreachable!("relay state was reset to Shadowsocks")
    };
    if association.is_none() {
        *association = Some(
            connect_shadowsocks_udp_association_via_socks5(egress, shadowsocks, socks5).await?,
        );
    }
    let association = association
        .as_ref()
        .ok_or(TransportError::NoUsableUdpTarget)?;
    relay_udp_payload_to_target_with_shadowsocks_association(header, payload, association).await
}

async fn relay_udp_payload_to_target_via_socks5_shadowsocks_chain(
    relay_state: &mut UdpEgressRelayState,
    header: &OwnedProxyHeader,
    payload: &[u8],
    egress: &ProxyEgressPolicy,
    socks5: &Socks5DialerLink,
    shadowsocks: &ShadowsocksDialerLink,
) -> Result<(SocketAddr, SocketAddr, Vec<u8>), TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    if !matches!(relay_state, UdpEgressRelayState::Socks5(_)) {
        *relay_state = UdpEgressRelayState::Socks5(None);
    }
    let UdpEgressRelayState::Socks5(association) = relay_state else {
        unreachable!("relay state was reset to SOCKS5")
    };
    if association.is_none() {
        *association = Some(
            connect_socks5_udp_association_via_shadowsocks(egress, socks5, shadowsocks).await?,
        );
    }
    let association = association
        .as_ref()
        .ok_or(TransportError::NoUsableUdpTarget)?;
    relay_udp_payload_to_target_with_socks5_association(
        header,
        payload,
        &association.socket,
        association.relay_addr,
    )
    .await
}

async fn relay_udp_payload_to_target_with_socks5_association(
    header: &OwnedProxyHeader,
    payload: &[u8],
    socket: &Socks5UdpRelaySocket,
    relay_addr: SocketAddr,
) -> Result<(SocketAddr, SocketAddr, Vec<u8>), TransportError> {
    let datagram = encode_socks5_udp_datagram(header, payload)?;
    socket.send_to(&datagram, relay_addr).await?;

    let mut response = vec![0_u8; 65_535];
    let received =
        tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut response)).await;
    let Ok(received) = received else {
        return Err(TransportError::NoUsableUdpTarget);
    };
    let (received, _relay_peer) = received?;
    response.truncate(received);
    let (peer, payload_offset) = decode_socks5_udp_response_header(&response)?;
    let target = match udp_ip_header_target(header) {
        Ok(target) => target,
        Err(TransportError::UnsupportedDomainTarget) => peer,
        Err(error) => return Err(error),
    };
    Ok((target, peer, response[payload_offset..].to_vec()))
}

async fn connect_socks5_udp_association(
    egress: &ProxyEgressPolicy,
    link: &Socks5DialerLink,
) -> Result<Socks5UdpAssociation, TransportError> {
    let proxy_targets = tokio::net::lookup_host((link.host.as_str(), link.port)).await?;
    let proxy_egress =
        ProxyEgressPolicy::with_send_through_and_fwmark(egress.send_through, egress.fwmark);
    let mut last_error = None;
    for proxy_target in proxy_targets {
        if egress_source_mismatches_target(&proxy_egress, proxy_target) {
            continue;
        }
        let control = match connect_tcp_socket_to_target(proxy_target, &proxy_egress).await {
            Ok(control) => control,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let mut control = TcpProxyTargetStream::plain(control)?;
        let bind_addr = udp_relay_bind_addr(proxy_target.is_ipv4(), &proxy_egress);
        let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
        apply_socket_fwmark(&socket, &proxy_egress)?;
        let relay_addr = socks5_udp_associate(&mut control, link, proxy_target).await?;
        return Ok(Socks5UdpAssociation {
            _control: control,
            socket: Socks5UdpRelaySocket::Direct(socket),
            relay_addr,
        });
    }
    if let Some(error) = last_error {
        return Err(error.into());
    }
    Err(TransportError::NoUsableUdpTarget)
}

async fn connect_socks5_udp_association_via_shadowsocks(
    egress: &ProxyEgressPolicy,
    socks5: &Socks5DialerLink,
    shadowsocks: &ShadowsocksDialerLink,
) -> Result<Socks5UdpAssociation, TransportError> {
    let proxy_targets = tokio::net::lookup_host((socks5.host.as_str(), socks5.port)).await?;
    let mut last_error = None;
    for proxy_target in proxy_targets {
        let proxy_header =
            OwnedProxyHeader::from_ip(Network::Tcp, proxy_target.ip(), proxy_target.port());
        let mut control = match connect_tcp_proxy_target_via_shadowsocks(
            &proxy_header,
            egress,
            shadowsocks,
        )
        .await
        {
            Ok(control) => control,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let ShadowsocksUdpAssociation { socket } =
            match connect_shadowsocks_udp_association(egress, shadowsocks).await {
                Ok(association) => association,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
        let ShadowsocksUdpRelaySocket::Direct(socket) = socket else {
            last_error = Some(TransportError::UnsupportedProxyDialerLinkNetwork {
                scheme: "chain",
                network: Network::Udp,
            });
            continue;
        };
        let relay_addr = match socks5_udp_associate(&mut control, socks5, proxy_target).await {
            Ok(relay_addr) => relay_addr,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        return Ok(Socks5UdpAssociation {
            _control: control,
            socket: Socks5UdpRelaySocket::Shadowsocks(socket),
            relay_addr,
        });
    }
    if let Some(error) = last_error {
        return Err(error);
    }
    Err(TransportError::NoUsableUdpTarget)
}

async fn relay_udp_payload_to_target_via_trojan(
    relay_state: &mut UdpEgressRelayState,
    header: &OwnedProxyHeader,
    payload: &[u8],
    egress: &ProxyEgressPolicy,
    link: &TrojanDialerLink,
) -> Result<(SocketAddr, SocketAddr, Vec<u8>), TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    if !matches!(relay_state, UdpEgressRelayState::Trojan(_)) {
        *relay_state = UdpEgressRelayState::Trojan(None);
    }
    let UdpEgressRelayState::Trojan(association) = relay_state else {
        unreachable!("relay state was reset to Trojan")
    };
    if association.is_none() {
        *association = Some(connect_trojan_udp_association(header, egress, link).await?);
    }
    let association = association
        .as_mut()
        .ok_or(TransportError::NoUsableUdpTarget)?;
    write_trojan_udp_packet_frame(&mut association.stream, header, payload).await?;

    let mut response = vec![0_u8; 65_535];
    let received = tokio::time::timeout(
        Duration::from_secs(1),
        read_trojan_udp_packet_frame(&mut association.stream, &mut response),
    )
    .await;
    let Ok(received) = received else {
        return Err(TransportError::NoUsableUdpTarget);
    };
    let (peer, received) = received?;
    response.truncate(received);
    let target = match udp_ip_header_target(header) {
        Ok(target) => target,
        Err(TransportError::UnsupportedDomainTarget) => peer,
        Err(error) => return Err(error),
    };
    Ok((target, peer, response))
}

async fn connect_trojan_udp_association(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    link: &TrojanDialerLink,
) -> Result<TrojanUdpAssociation, TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    let stream = connect_tcp_proxy_target_via_trojan(header, egress, link).await?;
    Ok(TrojanUdpAssociation { stream })
}

async fn relay_udp_payload_to_target_via_vless(
    relay_state: &mut UdpEgressRelayState,
    header: &OwnedProxyHeader,
    payload: &[u8],
    egress: &ProxyEgressPolicy,
    link: &VlessDialerLink,
) -> Result<(SocketAddr, SocketAddr, Vec<u8>), TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    if !matches!(relay_state, UdpEgressRelayState::Vless(_)) {
        *relay_state = UdpEgressRelayState::Vless(None);
    }
    let UdpEgressRelayState::Vless(association) = relay_state else {
        unreachable!("relay state was reset to VLESS")
    };
    if association
        .as_ref()
        .is_none_or(|current| current.header != *header)
    {
        *association = Some(connect_vless_udp_association(header, egress, link).await?);
    }
    let association = association
        .as_mut()
        .ok_or(TransportError::NoUsableUdpTarget)?;
    write_vless_udp_packet_frame(&mut association.stream, payload).await?;

    let mut response = vec![0_u8; 65_535];
    let received = tokio::time::timeout(
        Duration::from_secs(1),
        read_vless_udp_packet_frame(&mut association.stream, &mut response),
    )
    .await;
    let Ok(received) = received else {
        return Err(TransportError::NoUsableUdpTarget);
    };
    let received = received?;
    response.truncate(received);
    let peer = match udp_ip_header_target(header) {
        Ok(target) => target,
        Err(TransportError::UnsupportedDomainTarget) => udp_header_targets(header)
            .await?
            .into_iter()
            .next()
            .ok_or(TransportError::NoUsableUdpTarget)?,
        Err(error) => return Err(error),
    };
    Ok((peer, peer, response))
}

async fn connect_vless_udp_association(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    link: &VlessDialerLink,
) -> Result<VlessUdpAssociation, TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    let stream = connect_tcp_proxy_target_via_vless(header, egress, link).await?;
    Ok(VlessUdpAssociation {
        header: header.clone(),
        stream,
    })
}

async fn write_vless_udp_packet_frame<S>(
    stream: &mut S,
    payload: &[u8],
) -> Result<(), TransportError>
where
    S: AsyncWrite + Unpin,
{
    let length = u16::try_from(payload.len()).map_err(|_| TransportError::VlessProxy {
        stage: "udp packet",
        message: "payload exceeds VLESS UDP frame length".to_owned(),
    })?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    Ok(())
}

async fn read_vless_udp_packet_frame<S>(
    stream: &mut S,
    payload: &mut [u8],
) -> Result<usize, TransportError>
where
    S: AsyncRead + Unpin,
{
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length).await?;
    let length = usize::from(u16::from_be_bytes(length));
    if length > payload.len() {
        return Err(TransportError::VlessProxy {
            stage: "udp packet",
            message: "payload exceeds receive buffer".to_owned(),
        });
    }
    stream.read_exact(&mut payload[..length]).await?;
    Ok(length)
}

async fn relay_udp_payload_to_target_via_vmess(
    relay_state: &mut UdpEgressRelayState,
    header: &OwnedProxyHeader,
    payload: &[u8],
    egress: &ProxyEgressPolicy,
    link: &VmessDialerLink,
) -> Result<(SocketAddr, SocketAddr, Vec<u8>), TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    if !matches!(relay_state, UdpEgressRelayState::Vmess(_)) {
        *relay_state = UdpEgressRelayState::Vmess(None);
    }
    let UdpEgressRelayState::Vmess(association) = relay_state else {
        unreachable!("relay state was reset to VMess")
    };
    if association
        .as_ref()
        .is_none_or(|current| current.header != *header)
    {
        *association = Some(connect_vmess_udp_association(header, egress, link).await?);
    }
    let association = association
        .as_mut()
        .ok_or(TransportError::NoUsableUdpTarget)?;
    write_vmess_udp_packet_chunk(&mut association.stream, &mut association.request, payload)
        .await?;
    if !association.response_header_read {
        read_vmess_response_header(&mut association.stream, &association.context).await?;
        association.response_header_read = true;
    }
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        read_vmess_udp_packet_chunk(&mut association.stream, &mut association.response),
    )
    .await;
    let Ok(response) = response else {
        return Err(TransportError::NoUsableUdpTarget);
    };
    let response = response?;
    let peer = match udp_ip_header_target(header) {
        Ok(target) => target,
        Err(TransportError::UnsupportedDomainTarget) => udp_header_targets(header)
            .await?
            .into_iter()
            .next()
            .ok_or(TransportError::NoUsableUdpTarget)?,
        Err(error) => return Err(error),
    };
    Ok((peer, peer, response))
}

async fn connect_vmess_udp_association(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    link: &VmessDialerLink,
) -> Result<VmessUdpAssociation, TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    let proxy_targets = tokio::net::lookup_host((link.host.as_str(), link.port)).await?;
    let proxy_egress =
        ProxyEgressPolicy::with_send_through_and_fwmark(egress.send_through, egress.fwmark);
    let mut last_error = None;
    for proxy_target in proxy_targets {
        if egress_source_mismatches_target(&proxy_egress, proxy_target) {
            continue;
        }
        let stream = match connect_tcp_socket_to_target(proxy_target, &proxy_egress).await {
            Ok(stream) => stream,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let mut stream = TcpProxyTargetStream::plain(stream)?;
        let context = VmessStreamContext::new(header)?;
        let request_header = context.encrypt_request_header(header, link)?;
        stream.write_all(&request_header).await?;
        let request = VmessBodyContext::request(&context)?;
        let response = VmessBodyContext::response(&context)?;
        return Ok(VmessUdpAssociation {
            header: header.clone(),
            stream,
            context,
            request,
            response,
            response_header_read: false,
        });
    }
    if let Some(error) = last_error {
        return Err(error.into());
    }
    Err(TransportError::NoUsableTcpTarget)
}

async fn write_vmess_udp_packet_chunk<S>(
    stream: &mut S,
    context: &mut VmessBodyContext,
    payload: &[u8],
) -> Result<(), TransportError>
where
    S: AsyncWrite + Unpin,
{
    let chunk = context.encode_chunk(payload)?;
    stream.write_all(&chunk).await?;
    Ok(())
}

async fn read_vmess_udp_packet_chunk<S>(
    stream: &mut S,
    context: &mut VmessBodyContext,
) -> Result<Vec<u8>, TransportError>
where
    S: AsyncRead + Unpin,
{
    let mut size = [0_u8; 2];
    stream.read_exact(&mut size).await?;
    let padding_len = context.size_mask.padding_len();
    let size = usize::from(context.size_mask.decode_size(size));
    let mut encrypted = vec![0_u8; size];
    stream.read_exact(&mut encrypted).await?;
    let payload = context.decode_chunk(encrypted, padding_len)?;
    if payload.is_empty() {
        return Err(TransportError::NoUsableUdpTarget);
    }
    Ok(payload)
}

async fn relay_udp_payload_to_target_via_tuic(
    relay_state: &mut UdpEgressRelayState,
    header: &OwnedProxyHeader,
    payload: &[u8],
    egress: &ProxyEgressPolicy,
    link: &TuicDialerLink,
) -> Result<(SocketAddr, SocketAddr, Vec<u8>), TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    if !matches!(relay_state, UdpEgressRelayState::Tuic(_)) {
        *relay_state = UdpEgressRelayState::Tuic(None);
    }
    let UdpEgressRelayState::Tuic(association) = relay_state else {
        unreachable!("relay state was reset to TUIC")
    };
    let needs_new_association = match association.as_ref() {
        Some(existing) => existing.header != *header,
        None => true,
    };
    if needs_new_association {
        if let Some(existing) = association.take() {
            send_tuic_dissociate(&existing.connection, existing.association_id).await?;
        }
        *association = Some(connect_tuic_udp_association(header, egress, link).await?);
    }
    let association = association
        .as_mut()
        .ok_or(TransportError::NoUsableUdpTarget)?;
    let packet_id = association.next_packet_id;
    association.next_packet_id = association.next_packet_id.wrapping_add(1);
    let datagram = encode_tuic_udp_packet(header, payload, association.association_id, packet_id)?;
    association
        .connection
        .send_datagram(bytes::Bytes::from(datagram))
        .map_err(tuic_send_datagram_error)?;
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        association.connection.read_datagram(),
    )
    .await;
    let Ok(response) = response else {
        return Err(TransportError::NoUsableUdpTarget);
    };
    let response = response?;
    let response = decode_tuic_udp_packet(&response, association.association_id)?;
    let target = match udp_ip_header_target(header) {
        Ok(target) => target,
        Err(TransportError::UnsupportedDomainTarget) => response.target,
        Err(error) => return Err(error),
    };
    Ok((target, response.target, response.payload))
}

async fn connect_tuic_udp_association(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    link: &TuicDialerLink,
) -> Result<TuicUdpAssociation, TransportError> {
    if matches!(link.udp_relay_mode.as_deref(), Some("quic")) {
        return Err(TransportError::TuicProxy {
            stage: "udp relay",
            message: "TUIC QUIC-stream UDP relay mode is not implemented".to_owned(),
        });
    }
    let uuid = uuid::Uuid::parse_str(&link.user).map_err(|source| {
        TransportError::InvalidProxyDialerLink {
            link: "tuic".to_owned(),
            message: format!("parse TUIC UUID: {source}"),
        }
    })?;
    let proxy_targets = tokio::net::lookup_host((link.host.as_str(), link.port)).await?;
    let proxy_egress =
        ProxyEgressPolicy::with_send_through_and_fwmark(egress.send_through, egress.fwmark);
    let mut last_error = None;
    for proxy_target in proxy_targets {
        if egress_source_mismatches_target(&proxy_egress, proxy_target) {
            continue;
        }
        let endpoint = match bind_quic_dialer_endpoint(proxy_target, &proxy_egress) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let connection = match connect_tuic_dialer_link(&endpoint, proxy_target, link, uuid).await {
            Ok(connection) => connection,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let association_id = random_u16("association")?;
        let next_packet_id = random_u16("packet")?;
        return Ok(TuicUdpAssociation {
            _endpoint: endpoint,
            connection,
            header: header.clone(),
            association_id,
            next_packet_id,
        });
    }
    if let Some(error) = last_error {
        return Err(error);
    }
    Err(TransportError::NoUsableUdpTarget)
}

fn random_u16(stage: &'static str) -> Result<u16, TransportError> {
    let mut raw = [0_u8; 2];
    getrandom::getrandom(&mut raw).map_err(|source| TransportError::TuicProxy {
        stage,
        message: format!("random id: {source}"),
    })?;
    Ok(u16::from_be_bytes(raw))
}

async fn send_tuic_dissociate(
    connection: &quinn::Connection,
    association_id: u16,
) -> Result<(), TransportError> {
    let payload = [
        TUIC_VERSION_5,
        TUIC_COMMAND_DISSOCIATE,
        association_id.to_be_bytes()[0],
        association_id.to_be_bytes()[1],
    ];
    let mut stream = connection.open_uni().await?;
    stream.write_all(&payload).await?;
    stream.finish()?;
    Ok(())
}

fn encode_tuic_udp_packet(
    header: &OwnedProxyHeader,
    payload: &[u8],
    association_id: u16,
    packet_id: u16,
) -> Result<Vec<u8>, TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    let payload_len = u16::try_from(payload.len()).map_err(|_| TransportError::TuicProxy {
        stage: "packet",
        message: "UDP payload exceeds TUIC u16 packet size".to_owned(),
    })?;
    let mut packet = Vec::with_capacity(
        TUIC_UDP_PACKET_FIXED_LEN + tuic_target_encoded_len(header)? + payload.len(),
    );
    packet.push(TUIC_VERSION_5);
    packet.push(TUIC_COMMAND_PACKET);
    packet.extend_from_slice(&association_id.to_be_bytes());
    packet.extend_from_slice(&packet_id.to_be_bytes());
    packet.push(1);
    packet.push(0);
    packet.extend_from_slice(&payload_len.to_be_bytes());
    encode_tuic_target(header, &mut packet)?;
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn encode_tuic_udp_fragment(
    header: &OwnedProxyHeader,
    payload: &[u8],
    association_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    include_address: bool,
) -> Result<Vec<u8>, TransportError> {
    let payload_len = u16::try_from(payload.len()).map_err(|_| TransportError::TuicProxy {
        stage: "packet",
        message: "UDP payload exceeds TUIC u16 packet size".to_owned(),
    })?;
    let mut packet = Vec::with_capacity(TUIC_UDP_PACKET_FIXED_LEN + 1 + payload.len());
    packet.push(TUIC_VERSION_5);
    packet.push(TUIC_COMMAND_PACKET);
    packet.extend_from_slice(&association_id.to_be_bytes());
    packet.extend_from_slice(&packet_id.to_be_bytes());
    packet.push(fragment_total);
    packet.push(fragment_id);
    packet.extend_from_slice(&payload_len.to_be_bytes());
    if include_address {
        encode_tuic_target(header, &mut packet)?;
    } else {
        packet.push(TUIC_ADDR_NONE);
    }
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn encode_tuic_udp_fragments(
    header: &OwnedProxyHeader,
    payload: &[u8],
    association_id: u16,
    packet_id: u16,
    max_datagram_size: usize,
) -> Result<Vec<Vec<u8>>, TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    let first_budget = max_datagram_size
        .saturating_sub(TUIC_UDP_PACKET_FIXED_LEN + tuic_target_encoded_len(header)?);
    let other_budget = max_datagram_size.saturating_sub(TUIC_UDP_PACKET_FIXED_LEN + 1);
    if first_budget == 0 || other_budget == 0 {
        return Err(tuic_packet_error("datagram size too small for TUIC packet"));
    }

    if payload.len() <= first_budget {
        return Ok(vec![encode_tuic_udp_fragment(
            header,
            payload,
            association_id,
            packet_id,
            1,
            0,
            true,
        )?]);
    }

    let extra_fragments = (payload.len() - first_budget).div_ceil(other_budget);
    let fragment_total_usize = 1 + extra_fragments;
    let fragment_total = u8::try_from(fragment_total_usize)
        .map_err(|_| tuic_packet_error("TUIC reply needs more than 255 fragments"))?;

    let mut fragments = Vec::with_capacity(fragment_total_usize);
    let mut offset = 0;
    for fragment_id in 0..fragment_total {
        let budget = if fragment_id == 0 {
            first_budget
        } else {
            other_budget
        };
        let end = (offset + budget).min(payload.len());
        fragments.push(encode_tuic_udp_fragment(
            header,
            &payload[offset..end],
            association_id,
            packet_id,
            fragment_total,
            fragment_id,
            fragment_id == 0,
        )?);
        offset = end;
    }
    Ok(fragments)
}

fn tuic_target_encoded_len(header: &OwnedProxyHeader) -> Result<usize, TransportError> {
    Ok(match &header.address {
        OwnedProxyAddress::Ipv4(_) => 1 + 4 + 2,
        OwnedProxyAddress::Ipv6(_) => 1 + 16 + 2,
        OwnedProxyAddress::Domain(domain) => {
            u8::try_from(domain.len()).map_err(|_| TransportError::TuicProxy {
                stage: "packet",
                message: "domain target exceeds 255 bytes".to_owned(),
            })?;
            1 + 1 + domain.len() + 2
        }
    })
}

fn decode_tuic_udp_packet(
    datagram: &[u8],
    expected_association_id: u16,
) -> Result<TuicUdpPacket, TransportError> {
    if datagram.len() < TUIC_UDP_PACKET_FIXED_LEN {
        return Err(tuic_packet_error("truncated packet header"));
    }
    if datagram[0] != TUIC_VERSION_5 || datagram[1] != TUIC_COMMAND_PACKET {
        return Err(tuic_packet_error(format!(
            "unexpected packet head {:02x?}",
            &datagram[..2]
        )));
    }
    let association_id = u16::from_be_bytes([datagram[2], datagram[3]]);
    if association_id != expected_association_id {
        return Err(tuic_packet_error("packet association id mismatch"));
    }
    let packet_id = u16::from_be_bytes([datagram[4], datagram[5]]);
    if datagram[6] != 1 || datagram[7] != 0 {
        return Err(tuic_packet_error(
            "fragmented TUIC UDP packets are not implemented",
        ));
    }
    let payload_len = usize::from(u16::from_be_bytes([datagram[8], datagram[9]]));
    let (target, payload_offset) = decode_tuic_udp_target(datagram, TUIC_UDP_PACKET_FIXED_LEN)?;
    let end = payload_offset
        .checked_add(payload_len)
        .ok_or_else(|| tuic_packet_error("packet payload length overflow"))?;
    if datagram.len() != end {
        return Err(tuic_packet_error("packet payload length mismatch"));
    }
    Ok(TuicUdpPacket {
        association_id,
        packet_id,
        target,
        payload: datagram[payload_offset..end].to_vec(),
    })
}

struct TuicUdpFragment {
    association_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    target: Option<SocketAddr>,
    payload: Vec<u8>,
}

fn decode_tuic_udp_fragment(datagram: &[u8]) -> Result<TuicUdpFragment, TransportError> {
    if datagram.len() < TUIC_UDP_PACKET_FIXED_LEN {
        return Err(tuic_packet_error("truncated packet header"));
    }
    if datagram[0] != TUIC_VERSION_5 || datagram[1] != TUIC_COMMAND_PACKET {
        return Err(tuic_packet_error(format!(
            "unexpected packet head {:02x?}",
            &datagram[..2]
        )));
    }
    let association_id = u16::from_be_bytes([datagram[2], datagram[3]]);
    let packet_id = u16::from_be_bytes([datagram[4], datagram[5]]);
    let fragment_total = datagram[6];
    let fragment_id = datagram[7];
    if fragment_total == 0 || fragment_id >= fragment_total {
        return Err(tuic_packet_error("invalid TUIC fragment index"));
    }
    let payload_len = usize::from(u16::from_be_bytes([datagram[8], datagram[9]]));
    let (target, payload_offset) = if fragment_id == 0 {
        let (target, offset) = decode_tuic_udp_target(datagram, TUIC_UDP_PACKET_FIXED_LEN)?;
        (Some(target), offset)
    } else {
        if datagram.get(TUIC_UDP_PACKET_FIXED_LEN) != Some(&TUIC_ADDR_NONE) {
            return Err(tuic_packet_error(
                "non-first TUIC fragment must use the none address",
            ));
        }
        (None, TUIC_UDP_PACKET_FIXED_LEN + 1)
    };
    let end = payload_offset
        .checked_add(payload_len)
        .ok_or_else(|| tuic_packet_error("packet payload length overflow"))?;
    if datagram.len() != end {
        return Err(tuic_packet_error("packet payload length mismatch"));
    }
    Ok(TuicUdpFragment {
        association_id,
        packet_id,
        fragment_total,
        fragment_id,
        target,
        payload: datagram[payload_offset..end].to_vec(),
    })
}

fn decode_tuic_udp_target(
    datagram: &[u8],
    offset: usize,
) -> Result<(SocketAddr, usize), TransportError> {
    let address_type = *datagram
        .get(offset)
        .ok_or_else(|| tuic_packet_error("missing packet address type"))?;
    match address_type {
        TUIC_ADDR_IPV4 => {
            let end = offset + 1 + 4 + 2;
            if datagram.len() < end {
                return Err(tuic_packet_error("truncated IPv4 packet address"));
            }
            Ok((
                SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::new(
                        datagram[offset + 1],
                        datagram[offset + 2],
                        datagram[offset + 3],
                        datagram[offset + 4],
                    )),
                    u16::from_be_bytes([datagram[offset + 5], datagram[offset + 6]]),
                ),
                end,
            ))
        }
        TUIC_ADDR_IPV6 => {
            let end = offset + 1 + 16 + 2;
            if datagram.len() < end {
                return Err(tuic_packet_error("truncated IPv6 packet address"));
            }
            let mut raw = [0_u8; 16];
            raw.copy_from_slice(&datagram[offset + 1..offset + 17]);
            Ok((
                SocketAddr::new(
                    IpAddr::V6(std::net::Ipv6Addr::from(raw)),
                    u16::from_be_bytes([datagram[offset + 17], datagram[offset + 18]]),
                ),
                end,
            ))
        }
        TUIC_ADDR_DOMAIN => {
            let len = usize::from(
                *datagram
                    .get(offset + 1)
                    .ok_or_else(|| tuic_packet_error("truncated domain packet address length"))?,
            );
            let end = offset + 1 + 1 + len + 2;
            if datagram.len() < end {
                return Err(tuic_packet_error("truncated domain packet address"));
            }
            let domain = std::str::from_utf8(&datagram[offset + 2..offset + 2 + len])?;
            let port = u16::from_be_bytes([datagram[end - 2], datagram[end - 1]]);
            let target = std::net::ToSocketAddrs::to_socket_addrs(&(domain, port))?
                .next()
                .ok_or(TransportError::NoUsableUdpTarget)?;
            Ok((target, end))
        }
        TUIC_ADDR_NONE => Err(tuic_packet_error(
            "packet address type none is not valid here",
        )),
        other => Err(tuic_packet_error(format!(
            "unsupported packet address type {other:#x}"
        ))),
    }
}

fn tuic_packet_error(message: impl Into<String>) -> TransportError {
    TransportError::TuicProxy {
        stage: "packet",
        message: message.into(),
    }
}

fn tuic_send_datagram_error(error: quinn::SendDatagramError) -> TransportError {
    TransportError::TuicProxy {
        stage: "datagram",
        message: error.to_string(),
    }
}

struct TuicUdpAssocHandle {
    sender: tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
    task: tokio::task::JoinHandle<()>,
}

struct TuicUdpReassemblyBuffer {
    fragments: Vec<Option<Vec<u8>>>,
    received: u8,
    target: Option<SocketAddr>,
    created: tokio::time::Instant,
}

#[derive(Default)]
struct TuicUdpReassembler {
    buffers: HashMap<(u16, u16), TuicUdpReassemblyBuffer>,
}

impl TuicUdpReassembler {
    fn accept(
        &mut self,
        fragment: TuicUdpFragment,
    ) -> Result<Option<(Vec<u8>, SocketAddr)>, TransportError> {
        if fragment.fragment_total == 1 {
            let target = fragment
                .target
                .ok_or_else(|| tuic_packet_error("first TUIC fragment is missing its address"))?;
            return Ok(Some((fragment.payload, target)));
        }

        let key = (fragment.association_id, fragment.packet_id);
        let buffer = self
            .buffers
            .entry(key)
            .or_insert_with(|| TuicUdpReassemblyBuffer {
                fragments: vec![None; fragment.fragment_total as usize],
                received: 0,
                target: None,
                created: tokio::time::Instant::now(),
            });
        if buffer.fragments.len() != fragment.fragment_total as usize {
            self.buffers.remove(&key);
            return Err(tuic_packet_error("TUIC fragment total changed mid-packet"));
        }
        let slot = &mut buffer.fragments[fragment.fragment_id as usize];
        if slot.is_some() {
            return Err(tuic_packet_error("duplicate TUIC fragment"));
        }
        if fragment.fragment_id == 0 {
            buffer.target =
                Some(fragment.target.ok_or_else(|| {
                    tuic_packet_error("first TUIC fragment is missing its address")
                })?);
        }
        *slot = Some(fragment.payload);
        buffer.received += 1;

        if usize::from(buffer.received) == buffer.fragments.len() {
            let buffer = self.buffers.remove(&key).expect("buffer present");
            let target = buffer
                .target
                .ok_or_else(|| tuic_packet_error("reassembled TUIC packet has no address"))?;
            let mut payload = Vec::new();
            for chunk in buffer.fragments {
                payload.extend_from_slice(&chunk.expect("all fragments present"));
            }
            return Ok(Some((payload, target)));
        }
        Ok(None)
    }

    fn collect_garbage(&mut self) {
        self.buffers
            .retain(|_, buffer| buffer.created.elapsed() < DEFAULT_NAT_TIMEOUT);
    }
}

/// Relays TUIC v5 native-UDP datagrams for one authenticated connection until
/// the connection closes or `shutdown` resolves.
pub async fn run_tuic_udp_datagram_relay(
    connection: quinn::Connection,
    egress: ProxyEgressPolicy,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), TransportError> {
    tokio::pin!(shutdown);
    let mut associations: HashMap<u16, TuicUdpAssocHandle> = HashMap::new();
    let mut reassembler = TuicUdpReassembler::default();
    let mut logged_decode_drop = false;
    let mut gc = tokio::time::interval(DEFAULT_NAT_TIMEOUT);
    gc.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            _ = gc.tick() => {
                reassembler.collect_garbage();
            }
            uni = connection.accept_uni() => {
                let Ok(mut recv) = uni else { break };
                let Ok(raw) = recv.read_to_end(TUIC_UNI_STREAM_MAX_LEN).await else {
                    continue;
                };
                if raw.len() < 2 || raw[0] != TUIC_VERSION_5 {
                    continue;
                }
                match raw[1] {
                    TUIC_COMMAND_DISSOCIATE if raw.len() >= 4 => {
                        let association_id = u16::from_be_bytes([raw[2], raw[3]]);
                        if let Some(handle) = associations.remove(&association_id) {
                            handle.task.abort();
                        }
                    }
                    TUIC_COMMAND_PACKET => {
                        let fragment = match decode_tuic_udp_fragment(&raw) {
                            Ok(fragment) => fragment,
                            Err(error) => {
                                if !logged_decode_drop {
                                    logged_decode_drop = true;
                                    tracing::debug!(error = %error, "tuicUdpDropStream");
                                }
                                continue;
                            }
                        };
                        let association_id = fragment.association_id;
                        match reassembler.accept(fragment) {
                            Ok(Some(forward)) => {
                                forward_tuic_udp(
                                    &connection,
                                    &egress,
                                    &mut associations,
                                    association_id,
                                    forward,
                                )
                                .await;
                            }
                            Ok(None) => {}
                            Err(error) => {
                                if !logged_decode_drop {
                                    logged_decode_drop = true;
                                    tracing::debug!(error = %error, "tuicUdpDropStream");
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            datagram = connection.read_datagram() => {
                let datagram = match datagram {
                    Ok(datagram) => datagram,
                    Err(_) => break,
                };
                if datagram.len() >= 2
                    && datagram[0] == TUIC_VERSION_5
                    && datagram[1] == TUIC_COMMAND_HEARTBEAT
                {
                    continue;
                }
                let fragment = match decode_tuic_udp_fragment(&datagram) {
                    Ok(fragment) => fragment,
                    Err(error) => {
                        if !logged_decode_drop {
                            logged_decode_drop = true;
                            tracing::debug!(error = %error, "tuicUdpDropDatagram");
                        }
                        continue;
                    }
                };
                let association_id = fragment.association_id;
                let forward = match reassembler.accept(fragment) {
                    Ok(Some(forward)) => forward,
                    Ok(None) => continue,
                    Err(error) => {
                        if !logged_decode_drop {
                            logged_decode_drop = true;
                            tracing::debug!(error = %error, "tuicUdpDropDatagram");
                        }
                        continue;
                    }
                };
                forward_tuic_udp(
                    &connection,
                    &egress,
                    &mut associations,
                    association_id,
                    forward,
                )
                .await;
            }
        }
    }
    for (_, handle) in associations.drain() {
        handle.task.abort();
    }
    Ok(())
}

async fn forward_tuic_udp(
    connection: &quinn::Connection,
    egress: &ProxyEgressPolicy,
    associations: &mut HashMap<u16, TuicUdpAssocHandle>,
    association_id: u16,
    forward: (Vec<u8>, SocketAddr),
) {
    if let Some(handle) = associations.get(&association_id) {
        if handle.sender.send(forward.clone()).await.is_ok() {
            return;
        }
        if let Some(stale) = associations.remove(&association_id) {
            stale.task.abort();
        }
    }
    let (sender, receiver) = tokio::sync::mpsc::channel(64);
    let task = tokio::spawn(run_tuic_udp_association(
        connection.clone(),
        egress.clone(),
        association_id,
        receiver,
    ));
    let _ = sender.send(forward).await;
    associations.insert(association_id, TuicUdpAssocHandle { sender, task });
}

async fn run_tuic_udp_association(
    connection: quinn::Connection,
    egress: ProxyEgressPolicy,
    association_id: u16,
    mut receiver: tokio::sync::mpsc::Receiver<(Vec<u8>, SocketAddr)>,
) {
    let mut relay_socket: Option<(bool, tokio::net::UdpSocket)> = None;
    let mut packet_id: u16 = 0;
    let mut response = vec![0_u8; 65_535];
    let mut logged_oversize = false;
    loop {
        let socket_recv = async {
            match relay_socket.as_ref() {
                Some((_, socket)) => socket.recv_from(&mut response).await.map(Some),
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            biased;
            inbound = receiver.recv() => {
                let Some((payload, target)) = inbound else {
                    break;
                };
                if egress_source_mismatches_target(&egress, target) {
                    continue;
                }
                let target_is_ipv4 = target.is_ipv4();
                let needs_socket = match relay_socket {
                    Some((socket_is_ipv4, _)) => socket_is_ipv4 != target_is_ipv4,
                    None => true,
                };
                if needs_socket {
                    let bind_addr = udp_relay_bind_addr(target_is_ipv4, &egress);
                    let Ok(socket) = tokio::net::UdpSocket::bind(bind_addr).await else {
                        continue;
                    };
                    if apply_socket_fwmark(&socket, &egress).is_err() {
                        continue;
                    }
                    relay_socket = Some((target_is_ipv4, socket));
                }
                if let Some((_, socket)) = relay_socket.as_ref() {
                    let _ = socket.send_to(&payload, target).await;
                }
            }
            received = socket_recv => {
                let Ok(Some((length, peer))) = received else {
                    break;
                };
                let Some(max_datagram_size) = connection.max_datagram_size() else {
                    if !logged_oversize {
                        logged_oversize = true;
                        tracing::debug!("tuicUdpDatagramDisabled");
                    }
                    continue;
                };
                let response_header = OwnedProxyHeader::from_ip(Network::Udp, peer.ip(), peer.port());
                let Ok(fragments) = encode_tuic_udp_fragments(
                    &response_header,
                    &response[..length],
                    association_id,
                    packet_id,
                    max_datagram_size,
                ) else {
                    continue;
                };
                packet_id = packet_id.wrapping_add(1);
                let mut send_failed = false;
                for fragment in fragments {
                    if connection.send_datagram(bytes::Bytes::from(fragment)).is_err() {
                        send_failed = true;
                        break;
                    }
                }
                if send_failed {
                    break;
                }
            }
            () = tokio::time::sleep(DEFAULT_NAT_TIMEOUT) => break,
        }
    }
}

async fn relay_udp_payload_to_target_via_hysteria2(
    relay_state: &mut UdpEgressRelayState,
    header: &OwnedProxyHeader,
    payload: &[u8],
    egress: &ProxyEgressPolicy,
    link: &Hysteria2DialerLink,
) -> Result<(SocketAddr, SocketAddr, Vec<u8>), TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    if !matches!(relay_state, UdpEgressRelayState::Hysteria2(_)) {
        *relay_state = UdpEgressRelayState::Hysteria2(None);
    }
    let UdpEgressRelayState::Hysteria2(association) = relay_state else {
        unreachable!("relay state was reset to Hysteria2")
    };
    let needs_new_association = match association.as_ref() {
        Some(existing) => existing.header != *header,
        None => true,
    };
    if needs_new_association {
        *association = Some(connect_hysteria2_udp_association(header, egress, link).await?);
    }
    let association = association
        .as_mut()
        .ok_or(TransportError::NoUsableUdpTarget)?;
    let target = hysteria2_udp_target_string(header)?;
    let datagram = encode_hysteria2_udp_packet(
        association.session_id,
        HYSTERIA2_UNFRAGMENTED_PACKET_ID,
        0,
        1,
        target.as_str(),
        payload,
    )?;
    association
        .connection
        .send_datagram(bytes::Bytes::from(datagram))
        .map_err(hysteria2_send_datagram_error)?;
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        association.connection.read_datagram(),
    )
    .await;
    let Ok(response) = response else {
        return Err(TransportError::NoUsableUdpTarget);
    };
    let response = response?;
    let response = decode_hysteria2_udp_packet(&response, association.session_id)?;
    let peer =
        response
            .addr
            .parse::<SocketAddr>()
            .map_err(|source| TransportError::Hysteria2Proxy {
                stage: "udp",
                message: format!("invalid UDP response address: {source}"),
            })?;
    let target = match udp_ip_header_target(header) {
        Ok(target) => target,
        Err(TransportError::UnsupportedDomainTarget) => peer,
        Err(error) => return Err(error),
    };
    Ok((target, peer, response.payload))
}

async fn connect_hysteria2_udp_association(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    link: &Hysteria2DialerLink,
) -> Result<Hysteria2UdpAssociation, TransportError> {
    let proxy_targets = tokio::net::lookup_host((link.host.as_str(), link.port)).await?;
    let proxy_egress =
        ProxyEgressPolicy::with_send_through_and_fwmark(egress.send_through, egress.fwmark);
    let mut last_error = None;
    for proxy_target in proxy_targets {
        if egress_source_mismatches_target(&proxy_egress, proxy_target) {
            continue;
        }
        let endpoint = match bind_quic_dialer_endpoint(proxy_target, &proxy_egress) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let connection = match connect_hysteria2_dialer_link(&endpoint, proxy_target, link).await {
            Ok(connection) => connection,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let (h3_driver, h3_send_request) =
            match authenticate_hysteria2_dialer_link(&connection, link).await {
                Ok(auth) => auth,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
        return Ok(Hysteria2UdpAssociation {
            _endpoint: endpoint,
            _h3_driver: h3_driver,
            _h3_send_request: h3_send_request,
            connection,
            header: header.clone(),
            session_id: HYSTERIA2_INITIAL_UDP_SESSION_ID,
        });
    }
    if let Some(error) = last_error {
        return Err(error);
    }
    Err(TransportError::NoUsableUdpTarget)
}

fn hysteria2_udp_target_string(header: &OwnedProxyHeader) -> Result<String, TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    Ok(match &header.address {
        OwnedProxyAddress::Ipv4(address) => {
            SocketAddr::new(IpAddr::V4(*address), header.port).to_string()
        }
        OwnedProxyAddress::Ipv6(address) => {
            SocketAddr::new(IpAddr::V6(*address), header.port).to_string()
        }
        OwnedProxyAddress::Domain(domain) => format!("{domain}:{}", header.port),
    })
}

fn encode_hysteria2_udp_packet(
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    addr: &str,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    if addr.is_empty() || addr.len() > HYSTERIA2_MAX_UDP_ADDRESS_LEN {
        return Err(hysteria2_udp_packet_error("invalid UDP address length"));
    }
    let mut packet =
        Vec::with_capacity(HYSTERIA2_UDP_PACKET_FIXED_LEN + 8 + addr.len() + payload.len());
    packet.extend_from_slice(&session_id.to_be_bytes());
    packet.extend_from_slice(&packet_id.to_be_bytes());
    packet.push(frag_id);
    packet.push(frag_count);
    write_hysteria2_varint(addr.len() as u64, &mut packet)?;
    packet.extend_from_slice(addr.as_bytes());
    packet.extend_from_slice(payload);
    if packet.len() > HYSTERIA2_MAX_UDP_SIZE {
        return Err(hysteria2_udp_packet_error(
            "fragmented Hysteria2 UDP packets are not implemented",
        ));
    }
    Ok(packet)
}

fn decode_hysteria2_udp_packet(
    datagram: &[u8],
    expected_session_id: u32,
) -> Result<Hysteria2UdpPacket, TransportError> {
    if datagram.len() < HYSTERIA2_UDP_PACKET_FIXED_LEN {
        return Err(hysteria2_udp_packet_error("truncated UDP datagram header"));
    }
    let session_id = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
    if session_id != expected_session_id {
        return Err(hysteria2_udp_packet_error("UDP session id mismatch"));
    }
    let packet_id = u16::from_be_bytes([datagram[4], datagram[5]]);
    let frag_id = datagram[6];
    let frag_count = datagram[7];
    if frag_id != 0 || frag_count != 1 {
        return Err(hysteria2_udp_packet_error(
            "fragmented Hysteria2 UDP packets are not implemented",
        ));
    }
    let mut offset = HYSTERIA2_UDP_PACKET_FIXED_LEN;
    let address_len = usize::try_from(read_hysteria2_datagram_varint(datagram, &mut offset)?)
        .map_err(|source| TransportError::Hysteria2Proxy {
            stage: "udp",
            message: source.to_string(),
        })?;
    if address_len == 0 || address_len > HYSTERIA2_MAX_UDP_ADDRESS_LEN {
        return Err(hysteria2_udp_packet_error("invalid UDP address length"));
    }
    let address_end = offset
        .checked_add(address_len)
        .ok_or_else(|| hysteria2_udp_packet_error("UDP address length overflow"))?;
    if datagram.len() <= address_end {
        return Err(hysteria2_udp_packet_error("invalid UDP payload length"));
    }
    let addr = std::str::from_utf8(&datagram[offset..address_end])?.to_owned();
    let _packet_id = packet_id;
    Ok(Hysteria2UdpPacket {
        addr,
        payload: datagram[address_end..].to_vec(),
    })
}

fn read_hysteria2_datagram_varint(
    datagram: &[u8],
    offset: &mut usize,
) -> Result<u64, TransportError> {
    let first = *datagram
        .get(*offset)
        .ok_or_else(|| hysteria2_udp_packet_error("missing UDP varint"))?;
    *offset += 1;
    let tag = first >> 6;
    let len = 1usize << tag;
    if datagram.len() < *offset + len - 1 {
        return Err(hysteria2_udp_packet_error("truncated UDP varint"));
    }
    let mut value = u64::from(first & 0x3f);
    for _ in 1..len {
        value = (value << 8) | u64::from(datagram[*offset]);
        *offset += 1;
    }
    Ok(value)
}

fn hysteria2_udp_packet_error(message: impl Into<String>) -> TransportError {
    TransportError::Hysteria2Proxy {
        stage: "udp",
        message: message.into(),
    }
}

fn hysteria2_send_datagram_error(error: quinn::SendDatagramError) -> TransportError {
    TransportError::Hysteria2Proxy {
        stage: "datagram",
        message: error.to_string(),
    }
}

async fn relay_udp_payload_to_target_via_juicity(
    relay_state: &mut UdpEgressRelayState,
    header: &OwnedProxyHeader,
    payload: &[u8],
    egress: &ProxyEgressPolicy,
    link: &JuicityDialerLink,
) -> Result<(SocketAddr, SocketAddr, Vec<u8>), TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    if !matches!(relay_state, UdpEgressRelayState::Juicity(_)) {
        *relay_state = UdpEgressRelayState::Juicity(None);
    }
    let UdpEgressRelayState::Juicity(association) = relay_state else {
        unreachable!("relay state was reset to Juicity")
    };
    let needs_new_association = match association.as_ref() {
        Some(existing) => existing.header != *header,
        None => true,
    };
    if needs_new_association {
        *association = Some(connect_juicity_udp_association(header, egress, link).await?);
    }
    let association = association
        .as_mut()
        .ok_or(TransportError::NoUsableUdpTarget)?;
    association.stream.send_datagram(payload).await?;
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        association.stream.recv_datagram(65_535),
    )
    .await;
    let Ok(response) = response else {
        return Err(TransportError::NoUsableUdpTarget);
    };
    let response = response?;
    let target = match udp_ip_header_target(header) {
        Ok(target) => target,
        Err(TransportError::UnsupportedDomainTarget) => response.target,
        Err(error) => return Err(error),
    };
    Ok((target, response.target, response.payload))
}

async fn connect_juicity_udp_association(
    header: &OwnedProxyHeader,
    egress: &ProxyEgressPolicy,
    link: &JuicityDialerLink,
) -> Result<JuicityUdpAssociation, TransportError> {
    let proxy_targets = tokio::net::lookup_host((link.host.as_str(), link.port)).await?;
    let proxy_egress =
        ProxyEgressPolicy::with_send_through_and_fwmark(egress.send_through, egress.fwmark);
    let mut last_error = None;
    for proxy_target in proxy_targets {
        if egress_source_mismatches_target(&proxy_egress, proxy_target) {
            continue;
        }
        let client = match bind_juicity_dialer_client(proxy_target, &proxy_egress) {
            Ok(client) => client,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let connection = match connect_juicity_dialer_link(&client, proxy_target, link).await {
            Ok(connection) => connection,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let stream = match open_juicity_udp_proxy_stream(&connection, header).await {
            Ok(stream) => stream,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        return Ok(JuicityUdpAssociation {
            _client: client,
            _connection: connection,
            header: header.clone(),
            stream,
        });
    }
    if let Some(error) = last_error {
        return Err(error);
    }
    Err(TransportError::NoUsableUdpTarget)
}

async fn relay_udp_payload_to_target_via_shadowsocks(
    relay_state: &mut UdpEgressRelayState,
    header: &OwnedProxyHeader,
    payload: &[u8],
    egress: &ProxyEgressPolicy,
    link: &ShadowsocksDialerLink,
) -> Result<(SocketAddr, SocketAddr, Vec<u8>), TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    if !matches!(relay_state, UdpEgressRelayState::Shadowsocks(_)) {
        *relay_state = UdpEgressRelayState::Shadowsocks(None);
    }
    let UdpEgressRelayState::Shadowsocks(association) = relay_state else {
        unreachable!("relay state was reset to Shadowsocks")
    };
    if association.is_none() {
        *association = Some(connect_shadowsocks_udp_association(egress, link).await?);
    }
    let association = association
        .as_ref()
        .ok_or(TransportError::NoUsableUdpTarget)?;

    relay_udp_payload_to_target_with_shadowsocks_association(header, payload, association).await
}

async fn relay_udp_payload_to_target_with_shadowsocks_association(
    header: &OwnedProxyHeader,
    payload: &[u8],
    association: &ShadowsocksUdpAssociation,
) -> Result<(SocketAddr, SocketAddr, Vec<u8>), TransportError> {
    let target_address = shadowsocks_udp_target_address(header)?;
    association.socket.send(&target_address, payload).await?;

    let mut response = vec![0_u8; 65_535];
    let received = tokio::time::timeout(
        Duration::from_secs(1),
        association.socket.recv(&mut response),
    )
    .await;
    let Ok(received) = received else {
        return Err(TransportError::NoUsableUdpTarget);
    };
    let (received, peer, _packet_len) = received?;
    response.truncate(received);
    let peer = shadowsocks_address_to_socket_addr(&peer).await?;
    let target = match udp_ip_header_target(header) {
        Ok(target) => target,
        Err(TransportError::UnsupportedDomainTarget) => peer,
        Err(error) => return Err(error),
    };
    Ok((target, peer, response))
}

async fn connect_shadowsocks_udp_association(
    egress: &ProxyEgressPolicy,
    link: &ShadowsocksDialerLink,
) -> Result<ShadowsocksUdpAssociation, TransportError> {
    let server_config = link.server_config()?;
    let mut options = shadowsocks::net::ConnectOpts::default();
    options.bind_local_addr = egress.send_through.map(|source| SocketAddr::new(source, 0));
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        options.fwmark = egress.fwmark;
    }
    let context = shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Local);
    let socket = shadowsocks::ProxySocket::connect_with_opts(context, &server_config, &options)
        .await
        .map_err(std::io::Error::from)?;
    Ok(ShadowsocksUdpAssociation {
        socket: ShadowsocksUdpRelaySocket::Direct(socket),
    })
}

async fn connect_shadowsocks_udp_association_via_socks5(
    egress: &ProxyEgressPolicy,
    shadowsocks: &ShadowsocksDialerLink,
    socks5: &Socks5DialerLink,
) -> Result<ShadowsocksUdpAssociation, TransportError> {
    let server_config = shadowsocks.server_config()?;
    let context = shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Local);
    let association = connect_socks5_udp_association(egress, socks5).await?;
    let Socks5UdpAssociation {
        _control,
        socket,
        relay_addr,
    } = association;
    let Socks5UdpRelaySocket::Direct(socket) = socket else {
        return Err(TransportError::UnsupportedProxyDialerLinkNetwork {
            scheme: "chain",
            network: Network::Udp,
        });
    };
    let target_header =
        proxy_endpoint_header(Network::Udp, shadowsocks.host.as_str(), shadowsocks.port);
    let socket = Socks5UdpPacketSocket {
        _control: Arc::new(tokio::sync::Mutex::new(_control)),
        socket,
        relay_addr,
        target_header,
    };
    Ok(ShadowsocksUdpAssociation {
        socket: ShadowsocksUdpRelaySocket::Socks5(shadowsocks::ProxySocket::from_socket(
            shadowsocks::relay::udprelay::proxy_socket::UdpSocketType::Client,
            context,
            &server_config,
            socket,
        )),
    })
}

fn shadowsocks_udp_target_address(
    header: &OwnedProxyHeader,
) -> Result<shadowsocks::relay::socks5::Address, TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    Ok(match &header.address {
        OwnedProxyAddress::Ipv4(address) => shadowsocks::relay::socks5::Address::SocketAddress(
            SocketAddr::new(IpAddr::V4(*address), header.port),
        ),
        OwnedProxyAddress::Ipv6(address) => shadowsocks::relay::socks5::Address::SocketAddress(
            SocketAddr::new(IpAddr::V6(*address), header.port),
        ),
        OwnedProxyAddress::Domain(domain) => {
            shadowsocks::relay::socks5::Address::DomainNameAddress(domain.clone(), header.port)
        }
    })
}

async fn shadowsocks_address_to_socket_addr(
    address: &shadowsocks::relay::socks5::Address,
) -> Result<SocketAddr, TransportError> {
    match address {
        shadowsocks::relay::socks5::Address::SocketAddress(address) => Ok(*address),
        shadowsocks::relay::socks5::Address::DomainNameAddress(domain, port) => {
            tokio::net::lookup_host((domain.as_str(), *port))
                .await?
                .next()
                .ok_or(TransportError::NoUsableUdpTarget)
        }
    }
}

async fn socks5_udp_associate<S>(
    stream: &mut S,
    link: &Socks5DialerLink,
    proxy_target: SocketAddr,
) -> Result<SocketAddr, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    socks5_negotiate_auth(stream, link).await?;
    let mut request = Vec::with_capacity(4 + 16 + 2);
    request.extend_from_slice(&[0x05, 0x03, 0x00]);
    if proxy_target.is_ipv4() {
        request.push(0x01);
        request.extend_from_slice(&[0, 0, 0, 0]);
    } else {
        request.push(0x04);
        request.extend_from_slice(&[0; 16]);
    }
    request.extend_from_slice(&0_u16.to_be_bytes());
    stream.write_all(&request).await?;
    let mut relay_addr = read_socks5_reply_addr(stream, "udp associate").await?;
    if relay_addr.ip().is_unspecified() {
        relay_addr = SocketAddr::new(proxy_target.ip(), relay_addr.port());
    }
    Ok(relay_addr)
}

async fn read_socks5_reply_addr<S>(
    stream: &mut S,
    stage: &'static str,
) -> Result<SocketAddr, TransportError>
where
    S: AsyncRead + Unpin,
{
    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(TransportError::Socks5Proxy {
            stage,
            message: format!("unexpected response {response:?}"),
        });
    }
    match response[3] {
        0x01 => {
            let mut raw = [0_u8; 6];
            stream.read_exact(&mut raw).await?;
            Ok(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
                u16::from_be_bytes([raw[4], raw[5]]),
            ))
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            let mut raw = vec![0_u8; usize::from(len[0]) + 2];
            stream.read_exact(&mut raw).await?;
            let domain = std::str::from_utf8(&raw[..usize::from(len[0])])?;
            let port = u16::from_be_bytes([raw[usize::from(len[0])], raw[usize::from(len[0]) + 1]]);
            tokio::net::lookup_host((domain, port))
                .await?
                .next()
                .ok_or(TransportError::NoUsableUdpTarget)
        }
        0x04 => {
            let mut raw = [0_u8; 18];
            stream.read_exact(&mut raw).await?;
            let mut addr = [0_u8; 16];
            addr.copy_from_slice(&raw[..16]);
            Ok(SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(addr)),
                u16::from_be_bytes([raw[16], raw[17]]),
            ))
        }
        other => Err(TransportError::Socks5Proxy {
            stage,
            message: format!("unsupported bind address type {other:#x}"),
        }),
    }
}

fn encode_socks5_udp_datagram(
    header: &OwnedProxyHeader,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    if header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(header.network));
    }
    let mut datagram = Vec::with_capacity(3 + 1 + 255 + 2 + payload.len());
    datagram.extend_from_slice(&[0x00, 0x00, 0x00]);
    encode_socks5_target(header, &mut datagram)?;
    datagram.extend_from_slice(payload);
    Ok(datagram)
}

fn decode_socks5_udp_response_header(
    datagram: &[u8],
) -> Result<(SocketAddr, usize), TransportError> {
    if datagram.len() < 4 || datagram[0] != 0 || datagram[1] != 0 || datagram[2] != 0 {
        return Err(TransportError::Socks5Proxy {
            stage: "udp relay",
            message: "invalid UDP datagram header".to_owned(),
        });
    }
    match datagram[3] {
        0x01 => {
            if datagram.len() < 10 {
                return Err(TransportError::Socks5Proxy {
                    stage: "udp relay",
                    message: "truncated IPv4 UDP datagram header".to_owned(),
                });
            }
            Ok((
                SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::new(
                        datagram[4],
                        datagram[5],
                        datagram[6],
                        datagram[7],
                    )),
                    u16::from_be_bytes([datagram[8], datagram[9]]),
                ),
                10,
            ))
        }
        0x04 => {
            if datagram.len() < 22 {
                return Err(TransportError::Socks5Proxy {
                    stage: "udp relay",
                    message: "truncated IPv6 UDP datagram header".to_owned(),
                });
            }
            let mut addr = [0_u8; 16];
            addr.copy_from_slice(&datagram[4..20]);
            Ok((
                SocketAddr::new(
                    IpAddr::V6(std::net::Ipv6Addr::from(addr)),
                    u16::from_be_bytes([datagram[20], datagram[21]]),
                ),
                22,
            ))
        }
        0x03 => Err(TransportError::Socks5Proxy {
            stage: "udp relay",
            message: "domain response address is unsupported".to_owned(),
        }),
        other => Err(TransportError::Socks5Proxy {
            stage: "udp relay",
            message: format!("unsupported address type {other:#x}"),
        }),
    }
}

async fn relay_udp_over_stream_session(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    stream_header: OwnedProxyHeader,
    idle_timeout: Duration,
    egress: ProxyEgressPolicy,
) -> Result<UdpOverStreamRelayReport, TransportError> {
    if stream_header.network != Network::Udp {
        return Err(TransportError::UnexpectedProxyNetwork(
            stream_header.network,
        ));
    }

    let mut relay_state = UdpEgressRelayState::default();
    let mut first_target = None;
    let mut bytes_from_client = 0_u64;
    let mut bytes_from_target = 0_u64;
    let mut peer_closed_connection = false;
    loop {
        let frame = tokio::time::timeout(idle_timeout, read_udp_datagram_frame(&mut recv)).await;
        let request = match frame {
            Ok(Ok(request)) => request,
            Ok(Err(TransportError::ReadExact(quinn::ReadExactError::FinishedEarly(0)))) => break,
            Ok(Err(error)) if first_target.is_some() && udp_session_connection_lost(&error) => {
                peer_closed_connection = true;
                break;
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => break,
        };
        let (target, peer, response) = relay_udp_payload_to_target_with_egress(
            &mut relay_state,
            &request.header,
            &request.payload,
            &egress,
        )
        .await?;
        first_target.get_or_insert(target);
        bytes_from_client += request.payload.len() as u64;
        bytes_from_target += response.len() as u64;

        let response_header = proxy_header_for_ip(Network::Udp, peer.ip(), peer.port());
        let mut encoded =
            Vec::with_capacity(response_header.address.runtime_metadata_len() + 2 + response.len());
        encode_udp_datagram(&response_header, &response, &mut encoded)?;
        send.write_all(&encoded).await?;
    }
    let target = first_target.ok_or(TransportError::EmptyUdpOverStream)?;
    if !peer_closed_connection {
        send.finish()?;
    }
    Ok(UdpOverStreamRelayReport {
        target,
        bytes_from_client,
        bytes_from_target,
    })
}

async fn read_udp_datagram_frame(recv: &mut quinn::RecvStream) -> Result<UdpFrame, TransportError> {
    let mut encoded = Vec::with_capacity(1 + 16 + 2 + 2 + 512);
    read_runtime_target_metadata(recv, &mut encoded).await?;

    let mut length = [0_u8; 2];
    recv.read_exact(&mut length).await?;
    encoded.extend_from_slice(&length);
    let payload_len = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0_u8; payload_len];
    recv.read_exact(&mut payload).await?;
    encoded.extend_from_slice(&payload);

    let (header, payload, rest) = decode_udp_datagram(&encoded)?;
    debug_assert!(rest.is_empty());
    let header = OwnedProxyHeader::from_borrowed(header)?;
    Ok(UdpFrame {
        header,
        payload: payload.to_vec(),
    })
}

async fn write_proxy_header(
    send: &mut quinn::SendStream,
    header: &OwnedProxyHeader,
) -> Result<(), TransportError> {
    let header = header.as_borrowed();
    let mut encoded = Vec::with_capacity(header.encoded_len());
    header.encode_to(&mut encoded)?;
    send.write_all(&encoded).await?;
    Ok(())
}

async fn read_proxy_header_prefix(
    recv: &mut quinn::RecvStream,
) -> Result<(OwnedProxyHeader, Vec<u8>), TransportError> {
    let mut network = [0_u8; 1];
    recv.read_exact(&mut network).await?;

    let mut encoded = Vec::with_capacity(1 + 1 + 16 + 2);
    encoded.extend_from_slice(&network);
    read_runtime_target_metadata(recv, &mut encoded).await?;

    let (header, rest) = ProxyHeader::decode(&encoded)?;
    debug_assert!(rest.is_empty());
    let owned_header = OwnedProxyHeader::from_borrowed(header)?;
    Ok((owned_header, Vec::new()))
}

async fn read_tuic_connect_header_prefix(
    recv: &mut quinn::RecvStream,
) -> Result<(OwnedProxyHeader, Vec<u8>), TransportError> {
    let mut command = [0_u8; 2];
    recv.read_exact(&mut command).await?;
    if command[0] != TUIC_VERSION_5 {
        return Err(TransportError::TuicProxy {
            stage: "accept",
            message: format!("unexpected TUIC version {}", command[0]),
        });
    }
    if command[1] != TUIC_COMMAND_CONNECT {
        return Err(TransportError::TuicProxy {
            stage: "accept",
            message: format!("unsupported TUIC command {}", command[1]),
        });
    }

    let mut addr_type = [0_u8; 1];
    recv.read_exact(&mut addr_type).await?;
    let address = match addr_type[0] {
        TUIC_ADDR_IPV4 => {
            let mut rest = [0_u8; 4];
            recv.read_exact(&mut rest).await?;
            OwnedProxyAddress::Ipv4(std::net::Ipv4Addr::from(rest))
        }
        TUIC_ADDR_IPV6 => {
            let mut rest = [0_u8; 16];
            recv.read_exact(&mut rest).await?;
            OwnedProxyAddress::Ipv6(std::net::Ipv6Addr::from(rest))
        }
        TUIC_ADDR_DOMAIN => {
            let mut len = [0_u8; 1];
            recv.read_exact(&mut len).await?;
            let mut domain = vec![0_u8; len[0] as usize];
            recv.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain).map_err(|_| TransportError::TuicProxy {
                stage: "accept",
                message: "TUIC domain target is not valid UTF-8".to_owned(),
            })?;
            OwnedProxyAddress::Domain(domain)
        }
        other => {
            return Err(TransportError::TuicProxy {
                stage: "accept",
                message: format!("unknown TUIC address type {other}"),
            });
        }
    };
    let mut port = [0_u8; 2];
    recv.read_exact(&mut port).await?;
    let header = OwnedProxyHeader {
        network: Network::Tcp,
        address,
        port: u16::from_be_bytes(port),
    };
    Ok((header, Vec::new()))
}

async fn read_runtime_target_metadata(
    recv: &mut quinn::RecvStream,
    encoded: &mut Vec<u8>,
) -> Result<(), TransportError> {
    let mut addr_type = [0_u8; 1];
    recv.read_exact(&mut addr_type).await?;
    encoded.extend_from_slice(&addr_type);

    match addr_type[0] {
        RUNTIME_ADDR_TYPE_IPV4 => {
            let mut rest = [0_u8; 6];
            recv.read_exact(&mut rest).await?;
            encoded.extend_from_slice(&rest);
        }
        RUNTIME_ADDR_TYPE_IPV6 => {
            let mut rest = [0_u8; 18];
            recv.read_exact(&mut rest).await?;
            encoded.extend_from_slice(&rest);
        }
        RUNTIME_ADDR_TYPE_DOMAIN => {
            let mut len = [0_u8; 1];
            recv.read_exact(&mut len).await?;
            encoded.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            recv.read_exact(&mut rest).await?;
            encoded.extend_from_slice(&rest);
        }
        other => {
            return Err(TransportError::Protocol(
                ProtocolError::UnknownRuntimeAddrType(other),
            ));
        }
    }
    Ok(())
}

// Bounds writes so a relay wedged on a target whose receive window stays closed
// cannot block forever. Reads are allowed to idle: long-lived TCP sessions such
// as SSH can legitimately have no payload for minutes while the QUIC connection
// itself remains healthy via keepalive.
async fn relay_copy_with_stall_timeout<R, W>(
    reader: &mut R,
    writer: &mut W,
    stall_timeout: Duration,
) -> std::io::Result<u64>
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
        match tokio::time::timeout(stall_timeout, writer.write_all(&buffer[..read])).await {
            Ok(result) => result?,
            Err(_) => return Err(std::io::Error::from(std::io::ErrorKind::TimedOut)),
        }
        copied += read as u64;
    }
    writer.flush().await?;
    Ok(copied)
}

async fn relay_tcp_proxy_stream(
    quic_send: quinn::SendStream,
    quic_recv: quinn::RecvStream,
    target_stream: TcpProxyTargetStream,
    initial_payload: Vec<u8>,
    stall_timeout: Duration,
) -> Result<TcpProxyRelayReport, TransportError> {
    let target = target_stream.peer_addr();
    let (mut target_read, mut target_write) = tokio::io::split(target_stream);
    let mut target_to_quic = quic_send;
    let mut client_to_target = quic_recv;

    let client_to_target = async {
        let mut bytes = 0_u64;
        if !initial_payload.is_empty() {
            target_write.write_all(&initial_payload).await?;
            bytes += initial_payload.len() as u64;
        }
        bytes +=
            relay_copy_with_stall_timeout(&mut client_to_target, &mut target_write, stall_timeout)
                .await?;
        target_write.shutdown().await?;
        Ok::<_, TransportError>(bytes)
    };

    let target_to_client = async {
        let bytes =
            relay_copy_with_stall_timeout(&mut target_read, &mut target_to_quic, stall_timeout)
                .await?;
        target_to_quic.finish()?;
        // Await peer acknowledgement of the FIN before this task returns and the
        // connection is dropped, so a graceful close never races the client
        // draining the final bytes into a spurious `closed by peer` error.
        target_to_quic.stopped().await?;
        Ok::<_, TransportError>(bytes)
    };

    let (bytes_from_client, bytes_from_target) =
        tokio::try_join!(client_to_target, target_to_client)?;
    Ok(TcpProxyRelayReport {
        target,
        bytes_from_client,
        bytes_from_target,
    })
}

async fn send_authentication_stream(
    connection: &quinn::Connection,
    uuid: uuid::Uuid,
    password: &[u8],
) -> Result<(), TransportError> {
    let token = export_connection_authentication_token(connection, uuid, password)?;
    let request = AuthenticationRequest::new(uuid, token);
    let mut payload = Vec::with_capacity(request.encoded_len());
    request.encode_to(&mut payload);

    let mut stream = connection.open_uni().await?;
    stream.write_all(&payload).await?;
    stream.finish()?;
    Ok(())
}

async fn verify_authentication_stream_with<'a>(
    connection: &quinn::Connection,
    credentials: impl IntoIterator<Item = (uuid::Uuid, &'a [u8])>,
) -> Result<ProxyProtocol, TransportError> {
    let payload = loop {
        let mut stream = connection.accept_uni().await?;
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await?;
        let is_auth_frame = head[0] == zuicity_protocol::VERSION_0
            || (head[0] == TUIC_VERSION_5 && head[1] == TUIC_COMMAND_AUTHENTICATE);
        if !is_auth_frame {
            let _ = stream.read_to_end(TUIC_UNI_STREAM_MAX_LEN).await;
            continue;
        }
        let mut payload = [0u8; AUTHENTICATION_FRAME_LEN];
        payload[..2].copy_from_slice(&head);
        stream
            .read_exact(&mut payload[2..AUTHENTICATION_FRAME_LEN])
            .await?;
        break payload;
    };

    let parsed = match payload[0] {
        zuicity_protocol::VERSION_0 => {
            let (request, rest) = AuthenticationRequest::decode(&payload)?;
            debug_assert!(rest.is_empty());
            Some((ProxyProtocol::Juicity, request.uuid, request.token))
        }
        TUIC_VERSION_5 if payload[1] == TUIC_COMMAND_AUTHENTICATE => {
            let mut uuid_bytes = [0u8; zuicity_protocol::AUTH_UUID_LEN];
            uuid_bytes.copy_from_slice(
                &payload[zuicity_protocol::COMMAND_HEADER_LEN
                    ..zuicity_protocol::COMMAND_HEADER_LEN + zuicity_protocol::AUTH_UUID_LEN],
            );
            let mut token = [0u8; zuicity_protocol::AUTH_TOKEN_LEN];
            token.copy_from_slice(
                &payload[zuicity_protocol::COMMAND_HEADER_LEN + zuicity_protocol::AUTH_UUID_LEN
                    ..AUTHENTICATION_FRAME_LEN],
            );
            Some((
                ProxyProtocol::Tuic,
                uuid::Uuid::from_bytes(uuid_bytes),
                token,
            ))
        }
        _ => None,
    };

    if let Some((protocol, request_uuid, request_token)) = parsed {
        for (uuid, password) in credentials {
            if request_uuid != uuid {
                continue;
            }
            let expected_token =
                export_connection_authentication_token(connection, uuid, password)?;
            if request_token == expected_token {
                return Ok(protocol);
            }
            break;
        }
    }
    connection.close(quinn::VarInt::from_u32(1), b"authentication rejected");
    Err(TransportError::AuthenticationRejected)
}

fn export_connection_authentication_token(
    connection: &quinn::Connection,
    uuid: uuid::Uuid,
    password: &[u8],
) -> Result<[u8; zuicity_protocol::AUTH_TOKEN_LEN], TransportError> {
    Ok(export_authentication_token(
        uuid,
        password,
        |output, label, context| {
            connection
                .export_keying_material(output, label, context)
                .map_err(|err| ProtocolError::Exporter(format!("{err:?}")))
        },
    )?)
}

/// Introspectable Quinn server config wrapper.
#[derive(Clone, Debug)]
pub struct QuicServerConfig {
    /// Built Quinn server configuration.
    pub inner: quinn::ServerConfig,
}

impl QuicServerConfig {
    /// Returns the applied upstream transport policy wrapper.
    #[must_use]
    pub fn transport(&self) -> BuiltTransportConfig {
        build_transport_config(&QuicRuntimePolicy::upstream_server())
    }
}

/// Introspectable Quinn client config wrapper.
#[derive(Clone, Debug)]
pub struct QuicClientConfig {
    /// Built Quinn client configuration.
    pub inner: quinn::ClientConfig,
}

impl QuicClientConfig {
    /// Returns the applied upstream transport policy wrapper.
    #[must_use]
    pub fn transport(&self) -> BuiltTransportConfig {
        build_transport_config(&QuicRuntimePolicy::upstream_client())
    }
}

#[derive(Clone, Debug)]
struct PinnedCertChainVerification {
    pinned_hash: Vec<u8>,
}

impl PinnedCertChainVerification {
    fn new(pinned_hash: &[u8]) -> Self {
        Self {
            pinned_hash: pinned_hash.to_vec(),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertChainVerification {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let chain_hash = zuicity_protocol::generate_cert_chain_hash(
            std::iter::once(end_entity.as_ref())
                .chain(intermediates.iter().map(|cert| cert.as_ref())),
        )
        .ok_or_else(|| rustls::Error::General("empty certificate chain".to_owned()))?;
        if chain_hash.as_slice() == self.pinned_hash.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(PinnedCertChainMismatch.to_string()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
struct PinnedCertChainMismatch;

impl fmt::Display for PinnedCertChainMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("pinned hash of cert chain does not match")
    }
}

impl std::error::Error for PinnedCertChainMismatch {}

#[derive(Clone, Debug)]
struct PinnedLeafSha256Verification {
    pinned_hash: Vec<u8>,
}

impl PinnedLeafSha256Verification {
    fn new(pinned_hash: &[u8]) -> Self {
        Self {
            pinned_hash: pinned_hash.to_vec(),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedLeafSha256Verification {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let leaf_hash = Sha256::digest(end_entity.as_ref());
        if leaf_hash.as_slice() == self.pinned_hash.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "pinned leaf SHA256 does not match".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn upstream_client_policy_matches_upstream_runtime_values() {
        let policy = QuicRuntimePolicy::upstream_client();

        assert_eq!(policy.receive_windows.initial_stream, 2 * 1024 * 1024);
        assert_eq!(policy.receive_windows.max_stream, 32 * 1024 * 1024);
        assert_eq!(policy.receive_windows.initial_connection, 32 * 1024 * 1024);
        assert_eq!(policy.receive_windows.max_connection, 64 * 1024 * 1024);
        assert_eq!(policy.keep_alive, Duration::from_secs(5));
        assert_eq!(policy.handshake_idle_timeout, Some(Duration::from_secs(8)));
        assert!(!policy.disable_path_mtu_discovery);
        assert!(!policy.enable_datagrams);
        assert_eq!(policy.congestion_controller, CongestionController::Bbr);
        assert_eq!(policy.cwnd, 10);
        assert_eq!(policy.streams.client_stream_rotation_threshold, 30);
        assert_eq!(policy.streams.client_reserved_stream_capacity(), 5);
    }

    #[test]
    fn upstream_server_policy_matches_upstream_runtime_values() {
        let policy = QuicRuntimePolicy::upstream_server();

        assert_eq!(policy.receive_windows.initial_stream, 2 * 1024 * 1024);
        assert_eq!(policy.receive_windows.max_stream, 32 * 1024 * 1024);
        assert_eq!(policy.receive_windows.initial_connection, 32 * 1024 * 1024);
        assert_eq!(policy.receive_windows.max_connection, 64 * 1024 * 1024);
        assert_eq!(policy.keep_alive, Duration::from_secs(10));
        assert_eq!(policy.handshake_idle_timeout, None);
        assert_eq!(policy.streams.max_incoming_streams, 100);
        assert_eq!(policy.streams.max_incoming_uni_streams, 100);
        assert!(!policy.disable_path_mtu_discovery);
        assert!(policy.enable_datagrams);
        assert_eq!(policy.congestion_controller, CongestionController::Bbr);
        assert_eq!(policy.cwnd, 10);
    }

    #[test]
    fn server_builder_loads_pem_and_applies_tls13_h3_policy() -> Result<(), TransportError> {
        let cert = rcgen::generate_simple_self_signed(vec!["example.com".to_owned()])
            .expect("generate fixture cert");
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let server = build_server_crypto_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
        assert_eq!(server.alpn_protocols, vec![ALPN_H3.as_bytes().to_vec()]);
        assert_eq!(TlsPolicy::upstream().min_version, MinimumTlsVersion::Tls13);

        let quic = build_server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
        assert_eq!(
            quic.transport().max_concurrent_bidi_streams(),
            quinn::VarInt::from_u32(MAX_OPEN_INCOMING_STREAMS as u32)
        );
        assert_eq!(
            quic.transport().max_concurrent_uni_streams(),
            quinn::VarInt::from_u32(MAX_OPEN_INCOMING_STREAMS as u32)
        );
        Ok(())
    }

    #[test]
    fn client_builder_applies_tls13_h3_and_root_pin_policy() -> Result<(), TransportError> {
        let cert = rcgen::generate_simple_self_signed(vec!["example.com".to_owned()])
            .expect("generate fixture cert");
        let cert_pem = cert.cert.pem();

        let client = build_client_crypto_config_with_roots(cert_pem.as_bytes(), false)?;
        assert_eq!(client.alpn_protocols, vec![ALPN_H3.as_bytes().to_vec()]);
        assert_eq!(TlsPolicy::upstream().min_version, MinimumTlsVersion::Tls13);

        let insecure = build_client_crypto_config_with_roots(&[], true)?;
        assert_eq!(insecure.alpn_protocols, vec![ALPN_H3.as_bytes().to_vec()]);

        let system_roots = build_client_crypto_config_with_roots(&[], false)?;
        assert_eq!(
            system_roots.alpn_protocols,
            vec![ALPN_H3.as_bytes().to_vec()]
        );

        let quic = build_client_config_with_roots(cert_pem.as_bytes(), false)?;
        assert!(quic.transport().keep_alive_interval().is_some());
        Ok(())
    }

    #[test]
    fn upstream_transport_config_applies_client_and_server_policy() {
        let client = build_transport_config(&QuicRuntimePolicy::upstream_client());
        assert_eq!(
            client.max_concurrent_bidi_streams(),
            quinn::VarInt::from_u32(MAX_OPEN_INCOMING_STREAMS as u32)
        );
        assert_eq!(
            client.max_concurrent_uni_streams(),
            quinn::VarInt::from_u32(MAX_OPEN_INCOMING_STREAMS as u32)
        );
        assert_eq!(
            client.stream_receive_window(),
            quinn::VarInt::from_u32(INITIAL_STREAM_RECEIVE_WINDOW as u32)
        );
        assert_eq!(
            client.receive_window(),
            quinn::VarInt::from_u32(INITIAL_CONNECTION_RECEIVE_WINDOW as u32)
        );
        assert_eq!(client.keep_alive_interval(), Some(CLIENT_KEEP_ALIVE));
        assert!(client.datagram_receive_buffer_size().is_none());

        let server = build_transport_config(&QuicRuntimePolicy::upstream_server());
        assert_eq!(server.keep_alive_interval(), Some(SERVER_KEEP_ALIVE));
        assert_eq!(
            server.datagram_receive_buffer_size(),
            Some(usize::from(u16::MAX))
        );
    }

    #[tokio::test]
    async fn rust_client_authenticates_to_rust_server_over_quic_uni_stream()
    -> Result<(), TransportError> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate fixture cert");
        let uuid = uuid::Uuid::new_v4();
        let password = b"correct horse battery staple";

        let server = JuicityQuicServer::bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;

        let server_task = tokio::spawn(async move {
            let authenticated = server.accept_authenticated(uuid, password).await?;
            Ok::<_, TransportError>(authenticated.remote_address())
        });

        let client = JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "localhost",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password,
            )
            .await?;
        assert_eq!(connection.remote_address(), server_addr);

        let authenticated_remote = server_task.await??;
        assert_eq!(authenticated_remote, client.local_addr()?);
        Ok(())
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ShadowsocksTcpRequest {
        target: SocketAddr,
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

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ShadowsocksUdpRequest {
        target: SocketAddr,
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
                        IpAddr::V4(std::net::Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
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
        let mut tls_config = build_server_crypto_config_from_pem(
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )
        .map_err(std::io::Error::other)?;
        tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
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

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Hysteria2TcpRequest {
        target: String,
        auth: String,
        client_rx: u64,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Hysteria2UdpRequest {
        target: SocketAddr,
        auth: String,
        client_rx: u64,
        session_id: u32,
        packet_id: u16,
        frag_id: u8,
        frag_count: u8,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Hysteria2UdpPacket {
        session_id: u32,
        packet_id: u16,
        frag_id: u8,
        frag_count: u8,
        addr: String,
        data: Vec<u8>,
    }

    fn hysteria2_quic_test_server_config(
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> std::io::Result<quinn::ServerConfig> {
        let crypto = build_server_crypto_config_from_pem(cert_pem, key_pem)
            .map_err(std::io::Error::other)?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
                .map_err(std::io::Error::other)?,
        ));
        let mut policy = QuicRuntimePolicy::upstream_server();
        policy.receive_windows = ReceiveWindowPolicy {
            initial_stream: HYSTERIA2_STREAM_RECEIVE_WINDOW,
            max_stream: HYSTERIA2_STREAM_RECEIVE_WINDOW,
            initial_connection: HYSTERIA2_CONNECTION_RECEIVE_WINDOW,
            max_connection: HYSTERIA2_CONNECTION_RECEIVE_WINDOW,
        };
        policy.keep_alive = HYSTERIA2_KEEP_ALIVE;
        policy.enable_datagrams = true;
        config.transport_config(build_transport_config(&policy).into_arc());
        Ok(config)
    }

    async fn start_hysteria2_tcp_proxy(
        expected_auth: &'static str,
    ) -> std::io::Result<(
        SocketAddr,
        tokio::sync::mpsc::Receiver<Hysteria2TcpRequest>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .map_err(std::io::Error::other)?;
        let server = JuicityQuicServer::bind_with_pem(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )
        .map_err(std::io::Error::other)?;
        let local_addr = server.local_addr().map_err(std::io::Error::other)?;
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async move {
            let incoming = server.endpoint.accept().await.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "closed Hysteria2 endpoint",
                )
            })?;
            let connection = incoming
                .accept()
                .map_err(std::io::Error::other)?
                .await
                .map_err(std::io::Error::other)?;
            let raw_connection = connection.clone();
            let mut h3_connection: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
                h3::server::Connection::new(h3_quinn::Connection::new(connection))
                    .await
                    .map_err(std::io::Error::other)?;
            let resolver = h3_connection
                .accept()
                .await
                .map_err(std::io::Error::other)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "missing Hysteria2 auth request",
                    )
                })?;
            let (request, mut stream) = resolver
                .resolve_request()
                .await
                .map_err(std::io::Error::other)?;
            if request.method() != http::Method::POST || request.uri().path() != "/auth" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "unexpected Hysteria2 auth request {} {}",
                        request.method(),
                        request.uri()
                    ),
                ));
            }
            let auth = request
                .headers()
                .get("Hysteria-Auth")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            if auth != expected_auth {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("unexpected Hysteria2 auth {auth:?}"),
                ));
            }
            let client_rx = request
                .headers()
                .get("Hysteria-CC-RX")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or_default();
            let response = http::Response::builder()
                .status(233)
                .header("Hysteria-UDP", "false")
                .header("Hysteria-CC-RX", "0")
                .header("Hysteria-Padding", "")
                .body(())
                .map_err(std::io::Error::other)?;
            stream
                .send_response(response)
                .await
                .map_err(std::io::Error::other)?;
            stream.finish().await.map_err(std::io::Error::other)?;
            let _h3_connection = h3_connection;

            let (mut send, mut recv) = raw_connection
                .accept_bi()
                .await
                .map_err(std::io::Error::other)?;
            let target = read_hysteria2_tcp_request(&mut recv).await?;
            request_tx
                .send(Hysteria2TcpRequest {
                    target: target.clone(),
                    auth,
                    client_rx,
                })
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
                })?;
            write_hysteria2_tcp_response(&mut send, true, "").await?;
            let mut outbound = tokio::net::TcpStream::connect(target.as_str()).await?;
            let mut stream = Hysteria2TestTcpStream { send, recv };
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut outbound).await?;
            Ok(())
        });
        Ok((local_addr, request_rx, task))
    }

    async fn start_hysteria2_udp_proxy(
        expected_auth: &'static str,
    ) -> std::io::Result<(
        SocketAddr,
        tokio::sync::mpsc::Receiver<Hysteria2UdpRequest>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .map_err(std::io::Error::other)?;
        let endpoint = quinn::Endpoint::server(
            hysteria2_quic_test_server_config(
                cert.cert.pem().as_bytes(),
                cert.key_pair.serialize_pem().as_bytes(),
            )?,
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )?;
        let local_addr = endpoint.local_addr()?;
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async move {
            let incoming = endpoint.accept().await.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "closed Hysteria2 UDP endpoint",
                )
            })?;
            let connection = incoming
                .accept()
                .map_err(std::io::Error::other)?
                .await
                .map_err(std::io::Error::other)?;
            let raw_connection = connection.clone();
            let mut h3_connection: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
                h3::server::Connection::new(h3_quinn::Connection::new(connection))
                    .await
                    .map_err(std::io::Error::other)?;
            let resolver = h3_connection
                .accept()
                .await
                .map_err(std::io::Error::other)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "missing Hysteria2 auth request",
                    )
                })?;
            let (request, mut stream) = resolver
                .resolve_request()
                .await
                .map_err(std::io::Error::other)?;
            if request.method() != http::Method::POST || request.uri().path() != "/auth" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "unexpected Hysteria2 auth request {} {}",
                        request.method(),
                        request.uri()
                    ),
                ));
            }
            let auth = request
                .headers()
                .get("Hysteria-Auth")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            if auth != expected_auth {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("unexpected Hysteria2 auth {auth:?}"),
                ));
            }
            let client_rx = request
                .headers()
                .get("Hysteria-CC-RX")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or_default();
            let response = http::Response::builder()
                .status(233)
                .header("Hysteria-UDP", "true")
                .header("Hysteria-CC-RX", "0")
                .header("Hysteria-Padding", "")
                .body(())
                .map_err(std::io::Error::other)?;
            stream
                .send_response(response)
                .await
                .map_err(std::io::Error::other)?;
            stream.finish().await.map_err(std::io::Error::other)?;
            let _h3_connection = h3_connection;

            let datagram = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                raw_connection.read_datagram(),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Hysteria2 UDP proxy did not receive a datagram",
                )
            })?
            .map_err(std::io::Error::other)?;
            let packet = read_hysteria2_udp_packet(&datagram)?;
            let target = packet
                .addr
                .parse::<SocketAddr>()
                .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidData, source))?;
            request_tx
                .send(Hysteria2UdpRequest {
                    target,
                    auth,
                    client_rx,
                    session_id: packet.session_id,
                    packet_id: packet.packet_id,
                    frag_id: packet.frag_id,
                    frag_count: packet.frag_count,
                })
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
                })?;

            let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
            socket.send_to(&packet.data, target).await?;
            let mut response = vec![0_u8; 65_535];
            let (received, peer) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                socket.recv_from(&mut response),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Hysteria2 UDP proxy target did not respond",
                )
            })??;
            let encoded = write_hysteria2_udp_packet(
                packet.session_id,
                packet.packet_id,
                0,
                1,
                peer.to_string().as_str(),
                &response[..received],
            );
            raw_connection
                .send_datagram(bytes::Bytes::from(encoded))
                .map_err(std::io::Error::other)?;
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(1), raw_connection.closed())
                    .await;
            Ok(())
        });
        Ok((local_addr, request_rx, task))
    }

    struct Hysteria2TestTcpStream {
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    }

    impl AsyncRead for Hysteria2TestTcpStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Hysteria2TestTcpStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            map_quinn_stream_poll(Pin::new(&mut self.get_mut().send).poll_write(cx, buf))
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            map_quinn_stream_poll(Pin::new(&mut self.get_mut().send).poll_flush(cx))
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            map_quinn_stream_poll(Pin::new(&mut self.get_mut().send).poll_shutdown(cx))
        }
    }

    async fn read_hysteria2_tcp_request(recv: &mut quinn::RecvStream) -> std::io::Result<String> {
        let frame_type = read_hysteria2_varint(recv).await?;
        if frame_type != 0x401 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexpected Hysteria2 TCP frame type {frame_type:#x}"),
            ));
        }
        let address_len =
            usize::try_from(read_hysteria2_varint(recv).await?).map_err(std::io::Error::other)?;
        if address_len == 0 || address_len > 2048 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Hysteria2 target length",
            ));
        }
        let mut address = vec![0_u8; address_len];
        recv.read_exact(&mut address)
            .await
            .map_err(std::io::Error::other)?;
        let padding_len =
            usize::try_from(read_hysteria2_varint(recv).await?).map_err(std::io::Error::other)?;
        if padding_len > 4096 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Hysteria2 padding length",
            ));
        }
        if padding_len > 0 {
            let mut padding = vec![0_u8; padding_len];
            recv.read_exact(&mut padding)
                .await
                .map_err(std::io::Error::other)?;
        }
        String::from_utf8(address)
            .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidData, source))
    }

    async fn write_hysteria2_tcp_response(
        send: &mut quinn::SendStream,
        ok: bool,
        message: &str,
    ) -> std::io::Result<()> {
        let mut response = Vec::with_capacity(1 + 8 + message.len() + 1);
        response.push(u8::from(!ok));
        write_hysteria2_varint(message.len() as u64, &mut response);
        response.extend_from_slice(message.as_bytes());
        write_hysteria2_varint(0, &mut response);
        send.write_all(&response)
            .await
            .map_err(std::io::Error::other)
    }

    async fn read_hysteria2_varint(recv: &mut quinn::RecvStream) -> std::io::Result<u64> {
        let mut first = [0_u8; 1];
        recv.read_exact(&mut first)
            .await
            .map_err(std::io::Error::other)?;
        let tag = first[0] >> 6;
        let len = 1usize << tag;
        let mut value = u64::from(first[0] & 0x3f);
        for _ in 1..len {
            let mut byte = [0_u8; 1];
            recv.read_exact(&mut byte)
                .await
                .map_err(std::io::Error::other)?;
            value = (value << 8) | u64::from(byte[0]);
        }
        Ok(value)
    }

    fn write_hysteria2_varint(value: u64, output: &mut Vec<u8>) {
        if value <= 63 {
            output.push(value as u8);
        } else if value <= 16_383 {
            output.push(((value >> 8) as u8) | 0x40);
            output.push(value as u8);
        } else if value <= 1_073_741_823 {
            output.push(((value >> 24) as u8) | 0x80);
            output.extend_from_slice(&[(value >> 16) as u8, (value >> 8) as u8, value as u8]);
        } else {
            output.push(((value >> 56) as u8) | 0xc0);
            output.extend_from_slice(&[
                (value >> 48) as u8,
                (value >> 40) as u8,
                (value >> 32) as u8,
                (value >> 24) as u8,
                (value >> 16) as u8,
                (value >> 8) as u8,
                value as u8,
            ]);
        }
    }

    fn write_hysteria2_udp_packet(
        session_id: u32,
        packet_id: u16,
        frag_id: u8,
        frag_count: u8,
        addr: &str,
        data: &[u8],
    ) -> Vec<u8> {
        let mut output = Vec::with_capacity(8 + 8 + addr.len() + data.len());
        output.extend_from_slice(&session_id.to_be_bytes());
        output.extend_from_slice(&packet_id.to_be_bytes());
        output.push(frag_id);
        output.push(frag_count);
        write_hysteria2_varint(addr.len() as u64, &mut output);
        output.extend_from_slice(addr.as_bytes());
        output.extend_from_slice(data);
        output
    }

    fn read_hysteria2_udp_packet(datagram: &[u8]) -> std::io::Result<Hysteria2UdpPacket> {
        if datagram.len() < 8 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated Hysteria2 UDP datagram header",
            ));
        }
        let session_id = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
        let packet_id = u16::from_be_bytes([datagram[4], datagram[5]]);
        let frag_id = datagram[6];
        let frag_count = datagram[7];
        let mut offset = 8;
        let address_len = usize::try_from(read_hysteria2_datagram_varint(datagram, &mut offset)?)
            .map_err(std::io::Error::other)?;
        if address_len == 0 || address_len > 2048 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Hysteria2 UDP address length",
            ));
        }
        let address_end = offset.checked_add(address_len).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Hysteria2 UDP address length overflow",
            )
        })?;
        if datagram.len() <= address_end {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Hysteria2 UDP payload length",
            ));
        }
        let addr = std::str::from_utf8(&datagram[offset..address_end])
            .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidData, source))?
            .to_owned();
        Ok(Hysteria2UdpPacket {
            session_id,
            packet_id,
            frag_id,
            frag_count,
            addr,
            data: datagram[address_end..].to_vec(),
        })
    }

    fn read_hysteria2_datagram_varint(datagram: &[u8], offset: &mut usize) -> std::io::Result<u64> {
        let first = *datagram.get(*offset).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "missing Hysteria2 UDP varint",
            )
        })?;
        *offset += 1;
        let tag = first >> 6;
        let len = 1usize << tag;
        if datagram.len() < *offset + len - 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated Hysteria2 UDP varint",
            ));
        }
        let mut value = u64::from(first & 0x3f);
        for _ in 1..len {
            value = (value << 8) | u64::from(datagram[*offset]);
            *offset += 1;
        }
        Ok(value)
    }

    async fn handle_http_connect_proxy_stream<S>(
        mut inbound: S,
        request_tx: tokio::sync::mpsc::Sender<HttpConnectRequest>,
    ) -> std::io::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
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
        network: Network,
        auth_hash: String,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TrojanUdpRequest {
        target: SocketAddr,
        network: Network,
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
        let tls_config = build_server_crypto_config_from_pem(
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

    async fn start_trojan_udp_proxy(
        password: &str,
    ) -> std::io::Result<(
        SocketAddr,
        tokio::sync::mpsc::Receiver<TrojanUdpRequest>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let local_addr = listener.local_addr()?;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .map_err(std::io::Error::other)?;
        let tls_config = build_server_crypto_config_from_pem(
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
            handle_trojan_udp_proxy_stream(&mut inbound, expected_auth_hash, request_tx).await
        });
        Ok((local_addr, request_rx, task))
    }

    fn trojan_test_sha224_hex(password: &str) -> std::io::Result<&'static str> {
        match password {
            "trojan dialer link password" => {
                Ok("aa902bd458fed8988c34be5a5c3905d9b9aee68ef92d65ad01008c38")
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
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
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
            1 => Network::Tcp,
            3 => Network::Udp,
            value => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid Trojan network byte {value}"),
                ));
            }
        };
        if network != Network::Tcp {
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

    async fn handle_trojan_udp_proxy_stream<S>(
        mut inbound: S,
        expected_auth_hash: String,
        request_tx: tokio::sync::mpsc::Sender<TrojanUdpRequest>,
    ) -> std::io::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
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
            1 => Network::Tcp,
            3 => Network::Udp,
            value => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid Trojan network byte {value}"),
                ));
            }
        };
        if network != Network::Udp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Trojan UDP fixture only supports UDP",
            ));
        }
        let initial_target = read_trojan_target_metadata(&mut inbound).await?;
        inbound.read_exact(&mut crlf).await?;
        if crlf != *b"\r\n" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing Trojan target CRLF",
            ));
        }

        let mut request_payload = vec![0_u8; 65_535];
        let (packet_target, received) =
            read_trojan_udp_packet_frame(&mut inbound, &mut request_payload)
                .await
                .map_err(std::io::Error::other)?;
        request_payload.truncate(received);
        if packet_target != initial_target {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Trojan UDP packet target differed from initial target",
            ));
        }
        request_tx
            .send(TrojanUdpRequest {
                target: packet_target,
                network,
                auth_hash,
            })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
            })?;

        let outbound = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        outbound.connect(packet_target).await?;
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
                "Trojan UDP proxy target did not respond",
            )
        })??;
        let response_header =
            OwnedProxyHeader::from_ip(Network::Udp, packet_target.ip(), packet_target.port());
        write_trojan_udp_packet_frame(&mut inbound, &response_header, &response[..received])
            .await
            .map_err(std::io::Error::other)?;
        Ok(())
    }

    async fn read_trojan_target_metadata<S>(inbound: &mut S) -> std::io::Result<SocketAddr>
    where
        S: tokio::io::AsyncRead + Unpin,
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
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut port = [0_u8; 2];
        inbound.read_exact(&mut port).await?;
        Ok(u16::from_be_bytes(port))
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct VmessProxyRequest {
        target: SocketAddr,
        network: Network,
        key: [u8; 16],
    }

    async fn start_vmess_tcp_proxy(
        expected_key: [u8; 16],
    ) -> std::io::Result<(
        SocketAddr,
        tokio::sync::mpsc::Receiver<VmessProxyRequest>,
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
        request_tx: tokio::sync::mpsc::Sender<VmessProxyRequest>,
    ) -> std::io::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
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
        let len_cipher = aes_gcm_from_key(&len_key[..16]).map_err(test_io_error)?;
        let len = len_cipher
            .decrypt(
                Nonce::from_slice(&len_iv[..12]),
                Payload {
                    msg: &prefix[16..34],
                    aad: &eauth_id,
                },
            )
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "decrypt VMess request length",
                )
            })?;
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
        let payload_cipher = aes_gcm_from_key(&payload_key[..16]).map_err(test_io_error)?;
        let instruction = payload_cipher
            .decrypt(
                Nonce::from_slice(&payload_iv[..12]),
                Payload {
                    msg: sealed.as_slice(),
                    aad: &eauth_id,
                },
            )
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "decrypt VMess request payload",
                )
            })?;
        let (context, target, network) = parse_vmess_request_instruction(&instruction)?;
        request_tx
            .send(VmessProxyRequest {
                target,
                network,
                key: expected_key,
            })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
            })?;
        write_vmess_response_header(&mut inbound, &context).await?;
        match network {
            Network::Tcp => {
                let outbound = tokio::net::TcpStream::connect(target).await?;
                let request = VmessBodyContext::request(&context).map_err(test_io_error)?;
                let response = VmessBodyContext::response(&context).map_err(test_io_error)?;
                let (mut inbound_read, mut inbound_write) = tokio::io::split(inbound);
                let (mut outbound_read, mut outbound_write) = tokio::io::split(outbound);
                let upload = async {
                    copy_vmess_to_plain(&mut inbound_read, &mut outbound_write, request)
                        .await
                        .map_err(test_io_error)
                };
                let download = async {
                    copy_plain_to_vmess(&mut outbound_read, &mut inbound_write, response)
                        .await
                        .map_err(test_io_error)
                };
                let _ = tokio::try_join!(upload, download)?;
                Ok(())
            }
            Network::Udp => {
                let mut request = VmessBodyContext::request(&context).map_err(test_io_error)?;
                let mut response = VmessBodyContext::response(&context).map_err(test_io_error)?;
                let request_payload =
                    read_vmess_udp_packet_chunk(&mut inbound, &mut request).await?;
                let outbound =
                    tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
                outbound.connect(target).await?;
                outbound.send(&request_payload).await?;
                let mut response_payload = vec![0_u8; 65_535];
                let received = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    outbound.recv(&mut response_payload),
                )
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "VMess UDP proxy target did not respond",
                    )
                })??;
                write_vmess_udp_packet_chunk(
                    &mut inbound,
                    &mut response,
                    &response_payload[..received],
                )
                .await
            }
        }
    }

    fn parse_vmess_request_instruction(
        instruction: &[u8],
    ) -> std::io::Result<(VmessStreamContext, SocketAddr, Network)> {
        if instruction.len() < 45 || instruction[0] != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid VMess instruction",
            ));
        }
        let network = match instruction[37] {
            1 => Network::Tcp,
            2 => Network::Udp,
            value => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unsupported VMess network byte {value}"),
                ));
            }
        };
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
                std::net::ToSocketAddrs::to_socket_addrs(&(domain, port))?
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
            VmessStreamContext {
                request_body_iv,
                request_body_key,
                response_body_iv,
                response_body_key,
                response_auth,
                request_options,
            },
            target,
            network,
        ))
    }

    async fn write_vmess_response_header<S>(
        stream: &mut S,
        context: &VmessStreamContext,
    ) -> std::io::Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
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
        let len_cipher = aes_gcm_from_key(&len_key[..16]).map_err(test_io_error)?;
        let sealed_len = len_cipher
            .encrypt(
                Nonce::from_slice(&len_iv[..12]),
                (header.len() as u16).to_be_bytes().as_slice(),
            )
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "encrypt VMess response length",
                )
            })?;
        let header_key = vmess_kdf(
            &context.response_body_key,
            &[b"AEAD Resp Header Key".as_slice()],
        );
        let header_iv = vmess_kdf(
            &context.response_body_iv,
            &[b"AEAD Resp Header IV".as_slice()],
        );
        let header_cipher = aes_gcm_from_key(&header_key[..16]).map_err(test_io_error)?;
        let sealed_header = header_cipher
            .encrypt(Nonce::from_slice(&header_iv[..12]), header.as_slice())
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "encrypt VMess response header",
                )
            })?;
        stream.write_all(&sealed_len).await?;
        stream.write_all(&sealed_header).await?;
        Ok(())
    }

    async fn read_vmess_udp_packet_chunk<S>(
        stream: &mut S,
        context: &mut VmessBodyContext,
    ) -> std::io::Result<Vec<u8>>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut size = [0_u8; 2];
        stream.read_exact(&mut size).await?;
        let padding_len = context.size_mask.padding_len();
        let size = usize::from(context.size_mask.decode_size(size));
        let mut encrypted = vec![0_u8; size];
        stream.read_exact(&mut encrypted).await?;
        let payload = context
            .decode_chunk(encrypted, padding_len)
            .map_err(test_io_error)?;
        if payload.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "VMess UDP packet frame was empty terminal chunk",
            ));
        }
        Ok(payload)
    }

    async fn write_vmess_udp_packet_chunk<S>(
        stream: &mut S,
        context: &mut VmessBodyContext,
        payload: &[u8],
    ) -> std::io::Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        let chunk = context.encode_chunk(payload).map_err(test_io_error)?;
        stream.write_all(&chunk).await
    }

    fn test_io_error(error: impl std::fmt::Display) -> std::io::Error {
        std::io::Error::other(error.to_string())
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct VlessProxyRequest {
        target: SocketAddr,
        network: Network,
        uuid: uuid::Uuid,
    }

    async fn start_vless_tcp_proxy(
        expected_uuid: uuid::Uuid,
    ) -> std::io::Result<(
        SocketAddr,
        tokio::sync::mpsc::Receiver<VlessProxyRequest>,
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
        request_tx: tokio::sync::mpsc::Sender<VlessProxyRequest>,
    ) -> std::io::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
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
            1 => Network::Tcp,
            2 => Network::Udp,
            value => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid VLESS network byte {value}"),
                ));
            }
        };
        let target = read_vless_target_metadata(&mut inbound).await?;
        request_tx
            .send(VlessProxyRequest {
                target,
                network,
                uuid: expected_uuid,
            })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
            })?;
        match network {
            Network::Tcp => {
                let mut outbound = tokio::net::TcpStream::connect(target).await?;
                inbound.write_all(&[0_u8, 0_u8]).await?;
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
                Ok(())
            }
            Network::Udp => {
                inbound.write_all(&[0_u8, 0_u8]).await?;
                let mut request_payload = vec![0_u8; 65_535];
                let received =
                    read_vless_udp_packet_frame(&mut inbound, &mut request_payload).await?;
                request_payload.truncate(received);
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
                        "VLESS UDP proxy target did not respond",
                    )
                })??;
                write_vless_udp_packet_frame(&mut inbound, &response[..received]).await
            }
        }
    }

    async fn read_vless_target_metadata<S>(inbound: &mut S) -> std::io::Result<SocketAddr>
    where
        S: tokio::io::AsyncRead + Unpin,
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

    async fn read_vless_udp_packet_frame<S>(
        inbound: &mut S,
        payload: &mut [u8],
    ) -> std::io::Result<usize>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut length = [0_u8; 2];
        inbound.read_exact(&mut length).await?;
        let length = usize::from(u16::from_be_bytes(length));
        if length > payload.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VLESS UDP payload exceeded receive buffer",
            ));
        }
        inbound.read_exact(&mut payload[..length]).await?;
        Ok(length)
    }

    async fn write_vless_udp_packet_frame<S>(
        outbound: &mut S,
        payload: &[u8],
    ) -> std::io::Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        let length = u16::try_from(payload.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "VLESS UDP payload exceeded 65535 bytes",
            )
        })?;
        outbound.write_all(&length.to_be_bytes()).await?;
        outbound.write_all(payload).await
    }

    const TUIC_TEST_VERSION_5: u8 = 0x05;
    const TUIC_TEST_COMMAND_AUTHENTICATE: u8 = 0x00;
    const TUIC_TEST_COMMAND_CONNECT: u8 = 0x01;
    const TUIC_TEST_ADDR_DOMAIN: u8 = 0x00;
    const TUIC_TEST_ADDR_IPV4: u8 = 0x01;
    const TUIC_TEST_ADDR_IPV6: u8 = 0x02;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TuicTcpRequest {
        target: SocketAddr,
        version: u8,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TuicUdpRequest {
        target: SocketAddr,
        association_id: u16,
        packet_id: u16,
    }

    fn tuic_fixture_error(message: impl Into<String>) -> TransportError {
        TransportError::InvalidProxyDialerLink {
            link: "tuic fixture".to_owned(),
            message: message.into(),
        }
    }

    fn tuic_quic_test_server_config(
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<quinn::ServerConfig, TransportError> {
        let crypto = build_server_crypto_config_from_pem(cert_pem, key_pem)?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
        ));
        let mut policy = QuicRuntimePolicy::upstream_server();
        policy.enable_datagrams = true;
        config.transport_config(build_transport_config(&policy).into_arc());
        Ok(config)
    }

    fn start_tuic_tcp_proxy(
        cert_pem: &[u8],
        key_pem: &[u8],
        uuid: uuid::Uuid,
        password: &[u8],
    ) -> Result<
        (
            SocketAddr,
            tokio::sync::mpsc::Receiver<TuicTcpRequest>,
            tokio::task::JoinHandle<Result<TcpProxyRelayReport, TransportError>>,
        ),
        TransportError,
    > {
        let endpoint = quinn::Endpoint::server(
            tuic_quic_test_server_config(cert_pem, key_pem)?,
            ([127, 0, 0, 1], 0).into(),
        )?;
        let local_addr = endpoint.local_addr()?;
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
        let password = password.to_vec();
        let task = tokio::spawn(async move {
            let incoming = endpoint
                .accept()
                .await
                .ok_or(TransportError::EndpointClosed)?;
            let connection = incoming.accept()?.await?;
            verify_tuic_authentication_stream(&connection, uuid, &password).await?;
            let (send, mut recv) = connection.accept_bi().await?;
            let request = read_tuic_tcp_request(&mut recv).await?;
            request_tx.send(request.clone()).await.map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
            })?;
            let target_stream =
                TcpProxyTargetStream::plain(tokio::net::TcpStream::connect(request.target).await?)?;
            relay_tcp_proxy_stream(send, recv, target_stream, Vec::new(), DEFAULT_NAT_TIMEOUT).await
        });
        Ok((local_addr, request_rx, task))
    }

    fn start_tuic_udp_proxy(
        cert_pem: &[u8],
        key_pem: &[u8],
        uuid: uuid::Uuid,
        password: &[u8],
    ) -> Result<
        (
            SocketAddr,
            tokio::sync::mpsc::Receiver<TuicUdpRequest>,
            tokio::task::JoinHandle<Result<(), TransportError>>,
        ),
        TransportError,
    > {
        let endpoint = quinn::Endpoint::server(
            tuic_quic_test_server_config(cert_pem, key_pem)?,
            ([127, 0, 0, 1], 0).into(),
        )?;
        let local_addr = endpoint.local_addr()?;
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
        let password = password.to_vec();
        let task = tokio::spawn(async move {
            let incoming = endpoint
                .accept()
                .await
                .ok_or(TransportError::EndpointClosed)?;
            let connection = incoming.accept()?.await?;
            verify_tuic_authentication_stream(&connection, uuid, &password).await?;
            let datagram = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                connection.read_datagram(),
            )
            .await
            .map_err(|_| TransportError::NoUsableUdpTarget)??;
            let packet =
                decode_tuic_udp_packet(&datagram, u16::from_be_bytes([datagram[2], datagram[3]]))?;
            let target = packet.target;
            request_tx
                .send(TuicUdpRequest {
                    target,
                    association_id: packet.association_id,
                    packet_id: packet.packet_id,
                })
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
                })?;
            let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
            socket.send_to(&packet.payload, target).await?;
            let mut response = vec![0_u8; 65_535];
            let (received, peer) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                socket.recv_from(&mut response),
            )
            .await
            .map_err(|_| TransportError::NoUsableUdpTarget)??;
            response.truncate(received);
            let response_header = OwnedProxyHeader::from_ip(Network::Udp, peer.ip(), peer.port());
            let encoded = encode_tuic_udp_packet(
                &response_header,
                &response,
                packet.association_id,
                packet.packet_id,
            )?;
            connection
                .send_datagram(bytes::Bytes::from(encoded))
                .map_err(tuic_send_datagram_error)?;
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(1), connection.closed()).await;
            Ok(())
        });
        Ok((local_addr, request_rx, task))
    }

    async fn verify_tuic_authentication_stream(
        connection: &quinn::Connection,
        expected_uuid: uuid::Uuid,
        expected_password: &[u8],
    ) -> Result<(), TransportError> {
        let mut stream = connection.accept_uni().await?;
        let mut payload = [0_u8; 50];
        stream.read_exact(&mut payload).await?;
        if payload[0] != TUIC_TEST_VERSION_5 || payload[1] != TUIC_TEST_COMMAND_AUTHENTICATE {
            return Err(tuic_fixture_error(format!(
                "unexpected TUIC auth head {:02x?}",
                &payload[..2]
            )));
        }
        let mut raw_uuid = [0_u8; 16];
        raw_uuid.copy_from_slice(&payload[2..18]);
        let observed_uuid = uuid::Uuid::from_bytes(raw_uuid);
        if observed_uuid != expected_uuid {
            return Err(TransportError::AuthenticationRejected);
        }
        let expected_token =
            export_connection_authentication_token(connection, expected_uuid, expected_password)?;
        if payload[18..] != expected_token {
            return Err(TransportError::AuthenticationRejected);
        }
        Ok(())
    }

    async fn read_tuic_tcp_request<S>(stream: &mut S) -> Result<TuicTcpRequest, TransportError>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut head = [0_u8; 2];
        stream.read_exact(&mut head).await?;
        if head[0] != TUIC_TEST_VERSION_5 || head[1] != TUIC_TEST_COMMAND_CONNECT {
            return Err(tuic_fixture_error(format!(
                "unexpected TUIC connect head {:02x?}",
                head
            )));
        }
        let target = read_tuic_target(stream).await?;
        Ok(TuicTcpRequest {
            target,
            version: head[0],
        })
    }

    async fn read_tuic_target<S>(stream: &mut S) -> Result<SocketAddr, TransportError>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut address_type = [0_u8; 1];
        stream.read_exact(&mut address_type).await?;
        let target = match address_type[0] {
            TUIC_TEST_ADDR_IPV4 => {
                let mut address = [0_u8; 4];
                stream.read_exact(&mut address).await?;
                SocketAddr::new(IpAddr::from(address), read_tuic_port(stream).await?)
            }
            TUIC_TEST_ADDR_IPV6 => {
                let mut address = [0_u8; 16];
                stream.read_exact(&mut address).await?;
                SocketAddr::new(IpAddr::from(address), read_tuic_port(stream).await?)
            }
            TUIC_TEST_ADDR_DOMAIN => {
                let mut len = [0_u8; 1];
                stream.read_exact(&mut len).await?;
                let mut domain = vec![0_u8; len[0] as usize];
                stream.read_exact(&mut domain).await?;
                let port = read_tuic_port(stream).await?;
                let domain = std::str::from_utf8(&domain)?;
                tokio::net::lookup_host((domain, port))
                    .await?
                    .next()
                    .ok_or(TransportError::NoUsableTcpTarget)?
            }
            other => {
                return Err(tuic_fixture_error(format!(
                    "unsupported TUIC address type {other}"
                )));
            }
        };
        Ok(target)
    }

    async fn read_tuic_port<S>(stream: &mut S) -> Result<u16, TransportError>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).await?;
        Ok(u16::from_be_bytes(port))
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
                IpAddr::V4(std::net::Ipv4Addr::new(
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
    async fn rust_server_rejects_wrong_password_authentication() -> Result<(), TransportError> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate fixture cert");
        let uuid = uuid::Uuid::new_v4();

        let server = JuicityQuicServer::bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;

        let server_task = tokio::spawn(async move {
            server
                .accept_authenticated(uuid, b"expected-password")
                .await
        });

        let client = JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_roots(
                server_addr,
                "localhost",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                b"wrong-password",
            )
            .await?;
        assert_eq!(connection.remote_address(), server_addr);

        let error = server_task
            .await
            .expect("server task joins")
            .expect_err("wrong password is rejected");
        assert!(matches!(error, TransportError::AuthenticationRejected));
        Ok(())
    }

    #[tokio::test]
    async fn rust_server_rejects_unknown_uuid_authentication() -> Result<(), TransportError> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate fixture cert");
        let server_uuid = uuid::Uuid::new_v4();
        let client_uuid = uuid::Uuid::new_v4();

        let server = JuicityQuicServer::bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;

        let server_task = tokio::spawn(async move {
            server
                .accept_authenticated(server_uuid, b"shared-password")
                .await
        });

        let client = JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let _connection = client
            .connect_with_roots(
                server_addr,
                "localhost",
                cert.cert.pem().as_bytes(),
                false,
                client_uuid,
                b"shared-password",
            )
            .await?;

        let error = server_task
            .await
            .expect("server task joins")
            .expect_err("unknown uuid is rejected");
        assert!(matches!(error, TransportError::AuthenticationRejected));
        Ok(())
    }

    #[tokio::test]
    async fn rust_rust_tcp_proxy_stream_reaches_domain_echo_target() -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate fixture cert");
        let uuid = uuid::Uuid::new_v4();
        let password = b"tcp proxy domain password";

        let server = JuicityQuicServer::bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let echo_addr = echo.local_addr();

        let server_task = tokio::spawn(async move {
            let authenticated = server.accept_authenticated(uuid, password).await?;
            authenticated.accept_tcp_proxy_once().await
        });

        let client = JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let authenticated = client
            .connect_with_roots(
                server_addr,
                "localhost",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password,
            )
            .await?;
        let mut stream = authenticated
            .open_tcp_proxy_domain_stream("localhost", echo_addr.port())
            .await?;

        stream.write_all(b"domain ping through juicity").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"domain ping through juicity");

        let relayed = server_task.await??;
        assert_eq!(relayed.target, echo_addr);
        assert!(relayed.bytes_from_client >= b"domain ping through juicity".len() as u64);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn rust_rust_tcp_proxy_stream_reaches_echo_target() -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate fixture cert");
        let uuid = uuid::Uuid::new_v4();
        let password = b"tcp proxy password";

        let server = JuicityQuicServer::bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let echo_addr = echo.local_addr();

        let server_task = tokio::spawn(async move {
            let authenticated = server.accept_authenticated(uuid, password).await?;
            authenticated.accept_tcp_proxy_once().await
        });

        let client = JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let authenticated = client
            .connect_with_roots(
                server_addr,
                "localhost",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password,
            )
            .await?;
        let mut stream = authenticated
            .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
            .await?;

        stream.write_all(b"ping through juicity").await?;
        stream.finish()?;
        let echoed = stream.read_to_end(1024).await?;
        assert_eq!(echoed, b"ping through juicity");

        let relayed = server_task.await??;
        assert_eq!(relayed.target, echo_addr);
        assert!(relayed.bytes_from_client >= b"ping through juicity".len() as u64);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn rust_rust_tcp_proxy_stream_keeps_idle_target_response_open()
    -> Result<(), TransportError> {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let target_addr = listener.local_addr()?;
        let target_task = tokio::spawn(async move {
            let (mut target_stream, _) = listener.accept().await?;
            let mut request = [0_u8; 4];
            target_stream.read_exact(&mut request).await?;
            tokio::time::sleep(Duration::from_millis(300)).await;
            target_stream.write_all(b"idle response").await?;
            Ok::<_, std::io::Error>(request)
        });
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate fixture cert");
        let uuid = uuid::Uuid::new_v4();
        let password = b"tcp idle response password";

        let server = JuicityQuicServer::bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move {
            let authenticated = server.accept_authenticated(uuid, password).await?;
            authenticated
                .accept_proxy_once_with_idle_timeout(Duration::from_millis(100))
                .await
        });

        let client = JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let authenticated = client
            .connect_with_roots(
                server_addr,
                "localhost",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password,
            )
            .await?;
        let mut stream = authenticated
            .open_tcp_proxy_stream(target_addr.ip(), target_addr.port())
            .await?;

        stream.write_all(b"ping").await?;
        stream.finish()?;
        let response = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(1024))
            .await
            .expect("idle TCP proxy response timed out")?;
        assert_eq!(response, b"idle response");

        let request = target_task.await??;
        assert_eq!(&request, b"ping");
        let relayed = server_task.await??;
        assert_eq!(relayed.bytes_from_client(), b"ping".len() as u64);
        assert_eq!(relayed.bytes_from_target(), b"idle response".len() as u64);
        Ok(())
    }

    #[test]
    fn socks_dialer_link_requires_explicit_port_like_upstream() {
        for raw in ["socks://127.0.0.1", "socks5://127.0.0.1"] {
            let error = ProxyDialerLink::parse(raw).expect_err("missing SOCKS port is rejected");
            assert!(matches!(
                error,
                TransportError::InvalidProxyDialerLink { .. }
            ));
            assert!(
                error.to_string().contains("missing SOCKS5 port"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn trojan_dialer_link_parses_registered_tcp_schemes_and_rejects_unsupported_transports()
    -> Result<(), TransportError> {
        for raw in [
            "trojan://trojan%20parser%20password@127.0.0.1:443?peer=example.com&allowInsecure=true",
            "trojan-go://trojan%20parser%20password@127.0.0.1:443?sni=example.com",
        ] {
            assert!(
                ProxyDialerLink::parse(raw).is_ok(),
                "upstream-registered Trojan TCP link should parse: {raw}"
            );
        }

        let missing_port = ProxyDialerLink::parse("trojan://password@127.0.0.1")
            .expect_err("upstream rejects Trojan links without an explicit port");
        assert!(matches!(
            missing_port,
            TransportError::InvalidProxyDialerLink { .. }
        ));
        assert!(
            missing_port.to_string().contains("missing Trojan port"),
            "unexpected error: {missing_port}"
        );

        let websocket = ProxyDialerLink::parse(
            "trojan://password@127.0.0.1:443?type=ws&host=example.com&path=/trojan",
        )
        .expect_err("Trojan WebSocket links need a separate transport slice");
        assert!(matches!(
            websocket,
            TransportError::InvalidProxyDialerLink { .. }
        ));
        assert!(
            websocket.to_string().contains("Trojan transport type ws"),
            "unexpected error: {websocket}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_trojan_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let password = "trojan dialer link password";
        let (proxy_addr, mut requests, proxy_task) = start_trojan_tcp_proxy(password).await?;
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!(
            "trojan://{password}@localhost:{port}?sni=localhost&allowInsecure=true",
            port = proxy_addr.port()
        ))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        stream.write_all(b"trojan dialer link tcp").await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("Trojan proxy did not receive a TCP request")
            .expect("Trojan proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        assert_eq!(request.network, Network::Tcp);
        assert_eq!(
            request.auth_hash,
            "aa902bd458fed8988c34be5a5c3905d9b9aee68ef92d65ad01008c38"
        );
        let mut echoed = vec![0_u8; b"trojan dialer link tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"trojan dialer link tcp");
        stream.shutdown().await?;
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_relays_udp_target_through_trojan_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let echo_addr = echo.local_addr();
        let password = "trojan dialer link password";
        let (proxy_addr, mut requests, proxy_task) = start_trojan_udp_proxy(password).await?;
        let header = OwnedProxyHeader::from_ip(Network::Udp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!(
            "trojan://{password}@localhost:{port}?sni=localhost&allowInsecure=true",
            port = proxy_addr.port()
        ))?;
        let mut relay_state = UdpEgressRelayState::default();

        let (target, peer, response) = relay_udp_payload_to_target_with_egress(
            &mut relay_state,
            &header,
            b"trojan dialer link udp",
            &ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("Trojan proxy did not receive a UDP payload")
            .expect("Trojan UDP proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        assert_eq!(request.network, Network::Udp);
        assert_eq!(request.auth_hash, trojan_test_sha224_hex(password)?);
        assert_eq!(target, echo_addr);
        assert_eq!(peer, echo_addr);
        assert_eq!(response, b"trojan dialer link udp");
        drop(relay_state);
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[test]
    fn hysteria2_dialer_link_parses_upstream_url_fields_and_aliases() -> Result<(), TransportError>
    {
        let parsed = ProxyDialerLink::parse(
            "hysteria2://user:pass@example.com:443?sni=sni.example&insecure=true&pinSHA256=abcd&maxTx=100&maxRx=200#name",
        )?;
        assert_eq!(parsed.scheme_for_error(), "hysteria2");
        let ProxyDialerLink::Hysteria2(link) = parsed else {
            panic!("expected Hysteria2 dialer link");
        };
        assert_eq!(link.host, "example.com");
        assert_eq!(link.port, 443);
        assert_eq!(link.user, "user");
        assert_eq!(link.password, "pass");
        assert_eq!(link.sni.as_deref(), Some("sni.example"));
        assert!(link.insecure);
        assert_eq!(link.pin_sha256.as_deref(), Some("abcd"));
        assert_eq!(link.max_tx, Some(100));
        assert_eq!(link.max_rx, Some(200));

        let hy2 = ProxyDialerLink::parse("hy2://user@example.com:443")?;
        assert_eq!(hy2.scheme_for_error(), "hysteria2");
        let ProxyDialerLink::Hysteria2(hy2) = hy2 else {
            panic!("expected Hysteria2 dialer link");
        };
        assert_eq!(hy2.host, "example.com");
        assert_eq!(hy2.port, 443);
        assert_eq!(hy2.user, "user");
        assert_eq!(hy2.password, "");
        assert_eq!(hy2.sni, None);
        assert!(!hy2.insecure);
        assert_eq!(hy2.pin_sha256, None);
        assert_eq!(hy2.max_tx, None);
        assert_eq!(hy2.max_rx, None);

        let missing_port = ProxyDialerLink::parse("hysteria2://user:pass@example.com")
            .expect_err("Hysteria2 links need an explicit port like upstream");
        assert!(
            missing_port.to_string().contains("missing Hysteria2 port"),
            "unexpected error: {missing_port}"
        );

        let invalid_insecure =
            ProxyDialerLink::parse("hysteria2://user:pass@example.com:443?insecure=not-bool")
                .expect_err("invalid insecure values fail like upstream");
        assert!(
            invalid_insecure
                .to_string()
                .contains("invalid Hysteria2 insecure"),
            "unexpected error: {invalid_insecure}"
        );

        let invalid_bandwidth =
            ProxyDialerLink::parse("hysteria2://user:pass@example.com:443?maxTx=bad&maxRx=200")
                .expect_err("invalid bandwidth values fail like upstream");
        assert!(
            invalid_bandwidth
                .to_string()
                .contains("invalid Hysteria2 maxTx"),
            "unexpected error: {invalid_bandwidth}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_hysteria2_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let expected_auth = "hysteria-user:hysteria-pass";
        let (proxy_addr, mut requests, proxy_task) =
            start_hysteria2_tcp_proxy(expected_auth).await?;
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!(
            "hysteria2://hysteria-user:hysteria-pass@localhost:{port}?sni=localhost&insecure=true&maxTx=0&maxRx=0",
            port = proxy_addr.port()
        ))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        stream.write_all(b"hysteria2 dialer link tcp").await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("Hysteria2 proxy did not receive a TCP request")
            .expect("Hysteria2 proxy request channel closed");
        assert_eq!(request.target, echo_addr.to_string());
        assert_eq!(request.auth, expected_auth);
        assert_eq!(request.client_rx, 0);
        let mut echoed = vec![0_u8; b"hysteria2 dialer link tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"hysteria2 dialer link tcp");
        stream.shutdown().await?;
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_relays_udp_target_through_hysteria2_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let echo_addr = echo.local_addr();
        let expected_auth = "hysteria-user:hysteria-pass";
        let (proxy_addr, mut requests, proxy_task) =
            start_hysteria2_udp_proxy(expected_auth).await?;
        let header = OwnedProxyHeader::from_ip(Network::Udp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!(
            "hysteria2://hysteria-user:hysteria-pass@localhost:{port}?sni=localhost&insecure=true&maxTx=0&maxRx=0",
            port = proxy_addr.port()
        ))?;
        let mut relay_state = UdpEgressRelayState::default();

        let (target, peer, response) = relay_udp_payload_to_target_with_egress(
            &mut relay_state,
            &header,
            b"hysteria2 dialer link udp",
            &ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("Hysteria2 proxy did not receive a UDP datagram")
            .expect("Hysteria2 UDP proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        assert_eq!(request.auth, expected_auth);
        assert_eq!(request.client_rx, 0);
        assert_eq!(request.session_id, 1);
        assert_eq!(request.packet_id, 0);
        assert_eq!(request.frag_id, 0);
        assert_eq!(request.frag_count, 1);
        assert_eq!(target, echo_addr);
        assert_eq!(peer, echo_addr);
        assert_eq!(response, b"hysteria2 dialer link udp");
        drop(relay_state);
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[test]
    fn tuic_dialer_link_parses_upstream_url_fields_and_aliases() -> Result<(), TransportError> {
        let parsed = ProxyDialerLink::parse(
            "tuic://00000000-0000-0000-0000-000000000001:password@example.com:443?peer=peer.example&allowInsecure=true&congestion_control=bbr&alpn=h3&udp_relay_mode=native#name",
        )?;
        assert_eq!(parsed.scheme_for_error(), "tuic");
        let ProxyDialerLink::Tuic(link) = parsed else {
            panic!("expected TUIC dialer link");
        };
        assert_eq!(link.host, "example.com");
        assert_eq!(link.port, 443);
        assert_eq!(link.user, "00000000-0000-0000-0000-000000000001");
        assert_eq!(link.password, "password");
        assert_eq!(link.sni.as_deref(), Some("peer.example"));
        assert!(link.allow_insecure);
        assert!(!link.disable_sni);
        assert_eq!(link.congestion_control.as_deref(), Some("bbr"));
        assert_eq!(link.alpn, ["h3"]);
        assert_eq!(link.udp_relay_mode.as_deref(), Some("native"));

        let sni = ProxyDialerLink::parse(
            "tuic://00000000-0000-0000-0000-000000000001:password@example.com:443?sni=sni.example&allow_insecure=true",
        )?;
        let ProxyDialerLink::Tuic(sni) = sni else {
            panic!("expected TUIC dialer link");
        };
        assert_eq!(sni.sni.as_deref(), Some("sni.example"));
        assert!(sni.allow_insecure);

        let disable_sni = ProxyDialerLink::parse(
            "tuic://00000000-0000-0000-0000-000000000001:password@example.com:443?disable_sni=true",
        )?;
        let ProxyDialerLink::Tuic(disable_sni) = disable_sni else {
            panic!("expected TUIC dialer link");
        };
        assert_eq!(disable_sni.sni, None);
        assert!(disable_sni.allow_insecure);
        assert!(disable_sni.disable_sni);

        let non_uuid_user = ProxyDialerLink::parse("tuic://not-a-uuid:password@example.com:443")?;
        let ProxyDialerLink::Tuic(non_uuid_user) = non_uuid_user else {
            panic!("expected TUIC dialer link");
        };
        assert_eq!(non_uuid_user.user, "not-a-uuid");
        assert_eq!(non_uuid_user.sni.as_deref(), Some("example.com"));

        let missing_port = ProxyDialerLink::parse(
            "tuic://00000000-0000-0000-0000-000000000001:password@example.com",
        )
        .expect_err("TUIC links need an explicit port like upstream");
        assert!(
            missing_port.to_string().contains("missing TUIC port"),
            "unexpected error: {missing_port}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_tuic_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate TUIC proxy fixture cert");
        let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
            .expect("valid fixture UUID");
        let password = "tuic dialer link password";
        let (proxy_addr, mut requests, proxy_task) = start_tuic_tcp_proxy(
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
            uuid,
            password.as_bytes(),
        )?;
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!(
            "tuic://{uuid}:{password}@localhost:{port}?sni=localhost&allowInsecure=true&alpn=h3",
            port = proxy_addr.port()
        ))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("TUIC proxy did not receive a TCP CONNECT request")
            .expect("TUIC proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        assert_eq!(request.version, TUIC_TEST_VERSION_5);
        stream.write_all(b"tuic dialer link tcp").await?;
        let mut echoed = vec![0_u8; b"tuic dialer link tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"tuic dialer link tcp");
        stream.shutdown().await?;
        let relayed = proxy_task.await??;
        assert_eq!(relayed.target, echo_addr);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_relays_udp_target_through_tuic_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let echo_addr = echo.local_addr();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate TUIC UDP proxy fixture cert");
        let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
            .expect("valid fixture UUID");
        let password = "tuic udp dialer link password";
        let (proxy_addr, mut requests, proxy_task) = start_tuic_udp_proxy(
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
            uuid,
            password.as_bytes(),
        )?;
        let header = OwnedProxyHeader::from_ip(Network::Udp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!(
            "tuic://{uuid}:{password}@localhost:{port}?sni=localhost&allowInsecure=true&alpn=h3&udp_relay_mode=native",
            port = proxy_addr.port()
        ))?;
        let mut relay_state = UdpEgressRelayState::default();

        let (target, peer, response) = relay_udp_payload_to_target_with_egress(
            &mut relay_state,
            &header,
            b"tuic dialer link udp",
            &ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("TUIC proxy did not receive a UDP packet")
            .expect("TUIC UDP proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        assert_eq!(target, echo_addr);
        assert_eq!(peer, echo_addr);
        assert_eq!(response, b"tuic dialer link udp");
        drop(relay_state);
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[test]
    fn vmess_dialer_link_parses_json_and_raw_tcp_urls_and_rejects_unsupported_features()
    -> Result<(), TransportError> {
        let uuid = "00000000-0000-0000-0000-000000000001";
        let json = format!(
            r#"{{"v":"2","ps":"name","add":"example.com","port":"443","id":"{uuid}","aid":"0","net":"tcp","type":"none","host":"","path":"","tls":""}}"#
        );
        let encoded_json = general_purpose::STANDARD.encode(json);
        let parsed = ProxyDialerLink::parse(&format!("vmess://{encoded_json}"))?;
        assert_eq!(parsed.endpoint(), Some(("example.com", 443)));
        assert_eq!(parsed.scheme_for_error(), "vmess");
        let ProxyDialerLink::Vmess(link) = parsed else {
            panic!("expected VMess dialer link");
        };
        assert_eq!(link.host, "example.com");
        assert_eq!(link.port, 443);
        assert_eq!(link.id, uuid);

        let raw_payload =
            general_purpose::URL_SAFE_NO_PAD.encode(format!("auto:{uuid}@raw.example:8443"));
        let raw =
            ProxyDialerLink::parse(&format!("vmess://{raw_payload}?remarks=raw&obfs=tcp&tls=0"))?;
        assert_eq!(raw.endpoint(), Some(("raw.example", 8443)));

        let alter_id_json = general_purpose::STANDARD.encode(format!(
            r#"{{"add":"example.com","port":"443","id":"{uuid}","aid":"1","net":"tcp","type":"none"}}"#
        ));
        let alter_id = ProxyDialerLink::parse(&format!("vmess://{alter_id_json}"))
            .expect_err("VMess alterId requires a separate non-AEAD slice");
        assert!(
            alter_id.to_string().contains("alterId 1"),
            "unexpected error: {alter_id}"
        );

        let websocket_json = general_purpose::STANDARD.encode(format!(
            r#"{{"add":"example.com","port":"443","id":"{uuid}","aid":"0","net":"ws","type":"none"}}"#
        ));
        let websocket = ProxyDialerLink::parse(&format!("vmess://{websocket_json}"))
            .expect_err("VMess WebSocket requires a separate transport slice");
        assert!(
            websocket.to_string().contains("transport network ws"),
            "unexpected error: {websocket}"
        );

        let tls_json = general_purpose::STANDARD.encode(format!(
            r#"{{"add":"example.com","port":"443","id":"{uuid}","aid":"0","net":"tcp","type":"none","tls":"tls"}}"#
        ));
        let tls = ProxyDialerLink::parse(&format!("vmess://{tls_json}"))
            .expect_err("VMess TLS requires a separate transport slice");
        assert!(
            tls.to_string().contains("TLS mode tls"),
            "unexpected error: {tls}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_vmess_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let uuid = "00000000-0000-0000-0000-000000000001";
        let key = vless_user_to_key("vmess fixture", uuid)?;
        let (proxy_addr, mut requests, proxy_task) = start_vmess_tcp_proxy(key).await?;
        let json = general_purpose::STANDARD.encode(format!(
            r#"{{"add":"127.0.0.1","port":"{}","id":"{uuid}","aid":"0","net":"tcp","type":"none","tls":""}}"#,
            proxy_addr.port()
        ));
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!("vmess://{json}"))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        stream.write_all(b"vmess dialer link tcp").await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("VMess proxy did not receive a TCP request")
            .expect("VMess proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        assert_eq!(request.network, Network::Tcp);
        assert_eq!(request.key, key);
        let mut echoed = vec![0_u8; b"vmess dialer link tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"vmess dialer link tcp");
        stream.shutdown().await?;
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_relays_udp_target_through_vmess_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let echo_addr = echo.local_addr();
        let uuid = "00000000-0000-0000-0000-000000000001";
        let key = vless_user_to_key("vmess fixture", uuid)?;
        let (proxy_addr, mut requests, proxy_task) = start_vmess_tcp_proxy(key).await?;
        let json = general_purpose::STANDARD.encode(format!(
            r#"{{"add":"127.0.0.1","port":"{}","id":"{uuid}","aid":"0","net":"tcp","type":"none","tls":""}}"#,
            proxy_addr.port()
        ));
        let header = OwnedProxyHeader::from_ip(Network::Udp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!("vmess://{json}"))?;
        let mut relay_state = UdpEgressRelayState::default();

        let (target, peer, response) = relay_udp_payload_to_target_with_egress(
            &mut relay_state,
            &header,
            b"vmess dialer link udp",
            &ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("VMess proxy did not receive a UDP payload")
            .expect("VMess proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        assert_eq!(request.network, Network::Udp);
        assert_eq!(request.key, key);
        assert_eq!(target, echo_addr);
        assert_eq!(peer, echo_addr);
        assert_eq!(response, b"vmess dialer link udp");
        drop(relay_state);
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[test]
    fn vless_dialer_link_parses_minimal_tcp_url_and_rejects_unsupported_transports()
    -> Result<(), TransportError> {
        let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
            .expect("valid fixture UUID");
        let parsed = ProxyDialerLink::parse(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?type=tcp&security=none&headerType=none#name",
        )?;
        assert_eq!(parsed.endpoint(), Some(("example.com", 443)));
        assert_eq!(parsed.scheme_for_error(), "vless");

        let missing_port = ProxyDialerLink::parse(&format!("vless://{uuid}@example.com"))
            .expect_err("VLESS links need an explicit port for a dialable proxy address");
        assert!(matches!(
            missing_port,
            TransportError::InvalidProxyDialerLink { .. }
        ));
        assert!(
            missing_port.to_string().contains("missing VLESS port"),
            "unexpected error: {missing_port}"
        );

        let websocket = ProxyDialerLink::parse(&format!(
            "vless://{uuid}@example.com:443?type=ws&path=/ws&security=tls"
        ))
        .expect_err("WebSocket VLESS requires a separate transport slice");
        assert!(matches!(
            websocket,
            TransportError::InvalidProxyDialerLink { .. }
        ));
        assert!(
            websocket.to_string().contains("VLESS transport type ws"),
            "unexpected error: {websocket}"
        );

        let tls = ProxyDialerLink::parse(&format!(
            "vless://{uuid}@example.com:443?type=tcp&security=tls&sni=example.com"
        ))
        .expect_err("TLS VLESS requires a separate transport slice");
        assert!(matches!(tls, TransportError::InvalidProxyDialerLink { .. }));
        assert!(
            tls.to_string().contains("VLESS security tls"),
            "unexpected error: {tls}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_vless_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
            .expect("valid fixture UUID");
        let (proxy_addr, mut requests, proxy_task) = start_vless_tcp_proxy(uuid).await?;
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!(
            "vless://{uuid}@127.0.0.1:{port}?type=tcp&security=none&headerType=none",
            port = proxy_addr.port()
        ))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        stream.write_all(b"vless dialer link tcp").await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("VLESS proxy did not receive a TCP request")
            .expect("VLESS proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        assert_eq!(request.network, Network::Tcp);
        assert_eq!(request.uuid, uuid);
        let mut echoed = vec![0_u8; b"vless dialer link tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"vless dialer link tcp");
        stream.shutdown().await?;
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_relays_udp_target_through_vless_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let echo_addr = echo.local_addr();
        let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
            .expect("valid fixture UUID");
        let (proxy_addr, mut requests, proxy_task) = start_vless_tcp_proxy(uuid).await?;
        let header = OwnedProxyHeader::from_ip(Network::Udp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!(
            "vless://{uuid}@127.0.0.1:{port}?type=tcp&security=none",
            port = proxy_addr.port()
        ))?;
        let mut relay_state = UdpEgressRelayState::default();

        let (target, peer, response) = relay_udp_payload_to_target_with_egress(
            &mut relay_state,
            &header,
            b"vless dialer link udp",
            &ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("VLESS proxy did not receive a UDP payload")
            .expect("VLESS proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        assert_eq!(request.network, Network::Udp);
        assert_eq!(request.uuid, uuid);
        assert_eq!(target, echo_addr);
        assert_eq!(peer, echo_addr);
        assert_eq!(response, b"vless dialer link udp");
        drop(relay_state);
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[test]
    fn juicity_dialer_link_parses_upstream_url_fields_and_aliases() -> Result<(), TransportError> {
        let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
            .expect("valid fixture UUID");
        let parsed = ProxyDialerLink::parse(
            "juicity://00000000-0000-0000-0000-000000000001:pass%20word@example.com:443?peer=peer.example&allowInsecure=true&congestion_control=bbr&pinned_certchain_sha256=YWJj#name",
        )?;
        let ProxyDialerLink::Juicity(link) = parsed else {
            panic!("expected Juicity dialer link");
        };
        assert_eq!(link.host, "example.com");
        assert_eq!(link.port, 443);
        assert_eq!(link.uuid, uuid);
        assert_eq!(link.password, "pass word");
        assert_eq!(link.sni, "peer.example");
        assert!(link.allow_insecure);
        assert_eq!(link.congestion_control, "bbr");
        assert_eq!(
            link.pinned_cert_chain_sha256.as_deref(),
            Some(b"abc".as_slice())
        );

        for raw in [
            "juicity://00000000-0000-0000-0000-000000000001:pass@example.com:443?sni=sni.example&allow_insecure=true",
            "juicity://00000000-0000-0000-0000-000000000001:pass@example.com:443?allowinsecure=true",
            "juicity://00000000-0000-0000-0000-000000000001:pass@example.com:443?skipVerify=true",
        ] {
            let ProxyDialerLink::Juicity(link) = ProxyDialerLink::parse(raw)? else {
                panic!("expected Juicity dialer link for {raw}");
            };
            assert!(
                link.allow_insecure,
                "allow-insecure alias did not parse for {raw}"
            );
        }

        let ProxyDialerLink::Juicity(link) = ProxyDialerLink::parse(
            "juicity://00000000-0000-0000-0000-000000000001@example.com:443",
        )?
        else {
            panic!("expected Juicity dialer link with empty password");
        };
        assert_eq!(link.password, "");
        assert_eq!(link.sni, "example.com");

        let missing_port = ProxyDialerLink::parse(
            "juicity://00000000-0000-0000-0000-000000000001:pass@example.com",
        )
        .expect_err("upstream rejects Juicity links without an explicit port");
        assert!(matches!(
            missing_port,
            TransportError::InvalidProxyDialerLink { .. }
        ));
        assert!(
            missing_port.to_string().contains("missing Juicity port"),
            "unexpected error: {missing_port}"
        );

        let invalid_uuid = ProxyDialerLink::parse("juicity://not-a-uuid:pass@example.com:443")
            .expect_err("upstream Juicity dialer rejects non-UUID users");
        assert!(matches!(
            invalid_uuid,
            TransportError::InvalidProxyDialerLink { .. }
        ));
        assert!(
            invalid_uuid.to_string().contains("parse Juicity UUID"),
            "unexpected error: {invalid_uuid}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_juicity_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate Juicity proxy fixture cert");
        let uuid = uuid::Uuid::new_v4();
        let password = "juicity dialer link password";
        let server = JuicityQuicServer::bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move {
            let authenticated = server
                .accept_authenticated(uuid, password.as_bytes())
                .await?;
            authenticated.accept_tcp_proxy_once().await
        });
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!(
            "juicity://{uuid}:{password}@localhost:{port}?sni=localhost&allowInsecure=true&congestion_control=bbr",
            port = server_addr.port()
        ))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        stream.write_all(b"juicity dialer link tcp").await?;
        let mut echoed = vec![0_u8; b"juicity dialer link tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"juicity dialer link tcp");
        stream.shutdown().await?;
        let relayed = server_task.await??;
        assert_eq!(relayed.target, echo_addr);
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_relays_udp_target_through_juicity_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let echo_addr = echo.local_addr();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate Juicity UDP proxy fixture cert");
        let uuid = uuid::Uuid::new_v4();
        let password = "juicity udp dialer link password";
        let server = JuicityQuicServer::bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move {
            let authenticated = server
                .accept_authenticated(uuid, password.as_bytes())
                .await?;
            authenticated.accept_udp_over_stream_once().await
        });
        let header = OwnedProxyHeader::from_ip(Network::Udp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!(
            "juicity://{uuid}:{password}@localhost:{port}?sni=localhost&allowInsecure=true&congestion_control=bbr",
            port = server_addr.port()
        ))?;
        let mut relay_state = UdpEgressRelayState::default();

        let (target, peer, response) = relay_udp_payload_to_target_with_egress(
            &mut relay_state,
            &header,
            b"juicity dialer link udp",
            &ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        assert_eq!(target, echo_addr);
        assert_eq!(peer, echo_addr);
        assert_eq!(response, b"juicity dialer link udp");
        drop(relay_state);
        let relayed = server_task.await??;
        assert_eq!(relayed.target, echo_addr);
        assert_eq!(
            relayed.bytes_from_client,
            b"juicity dialer link udp".len() as u64
        );
        assert_eq!(
            relayed.bytes_from_target,
            b"juicity dialer link udp".len() as u64
        );
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_shadowsocks_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let password = "shadowsocks dialer link password";
        let (proxy_addr, mut requests, proxy_task) =
            start_shadowsocks_tcp_proxy(password, shadowsocks::crypto::CipherKind::AES_128_GCM)
                .await?;
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let userinfo = general_purpose::URL_SAFE_NO_PAD.encode(format!("aes-128-gcm:{password}"));
        let dialer_link = ProxyDialerLink::parse(&format!("ss://{userinfo}@{proxy_addr}"))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        stream.write_all(b"shadowsocks dialer link tcp").await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("Shadowsocks proxy did not receive a TCP request")
            .expect("Shadowsocks proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        let mut echoed = vec![0_u8; b"shadowsocks dialer link tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"shadowsocks dialer link tcp");
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[test]
    fn shadowsocks_dialer_link_parses_registered_schemes_and_rejects_plugins()
    -> Result<(), TransportError> {
        let password = "shadowsocks parser password";
        let userinfo = general_purpose::URL_SAFE_NO_PAD.encode(format!("aes-128-gcm:{password}"));
        for scheme in ["ss", "shadowsocks"] {
            let dialer_link =
                ProxyDialerLink::parse(&format!("{scheme}://{userinfo}@127.0.0.1:8388"))?;
            assert!(matches!(dialer_link, ProxyDialerLink::Shadowsocks(_)));
        }

        let error = ProxyDialerLink::parse(&format!(
            "ss://{userinfo}@127.0.0.1:8388?plugin=simple-obfs"
        ))
        .expect_err("plugin Shadowsocks links remain unsupported");
        assert!(matches!(
            error,
            TransportError::InvalidProxyDialerLink { .. }
        ));
        assert!(
            error.to_string().contains("plugin"),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[test]
    fn shadowsocks_dialer_link_parses_legacy_encoded_body_forms() -> Result<(), TransportError> {
        let password = "legacy shadowsocks parser password";
        let body = format!("aes-128-gcm:{password}@127.0.0.1:8388");
        for encoded_body in [
            general_purpose::STANDARD.encode(&body),
            general_purpose::URL_SAFE_NO_PAD.encode(&body),
        ] {
            let dialer_link = ProxyDialerLink::parse(&format!("ss://{encoded_body}"))?;
            assert!(matches!(dialer_link, ProxyDialerLink::Shadowsocks(_)));
        }
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_legacy_shadowsocks_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let password = "legacy shadowsocks dialer link password";
        let (proxy_addr, mut requests, proxy_task) =
            start_shadowsocks_tcp_proxy(password, shadowsocks::crypto::CipherKind::AES_128_GCM)
                .await?;
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let legacy_body =
            general_purpose::STANDARD.encode(format!("aes-128-gcm:{password}@{proxy_addr}"));
        let dialer_link = ProxyDialerLink::parse(&format!("ss://{legacy_body}"))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        stream
            .write_all(b"legacy shadowsocks dialer link tcp")
            .await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("legacy Shadowsocks proxy did not receive a TCP request")
            .expect("legacy Shadowsocks proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        let mut echoed = vec![0_u8; b"legacy shadowsocks dialer link tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"legacy shadowsocks dialer link tcp");
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    fn shadowsocksr_origin_plain_link(
        host: &str,
        port: u16,
        password: &str,
        proto: &str,
        obfs: &str,
    ) -> String {
        let host = general_purpose::URL_SAFE_NO_PAD.encode(host);
        let password = general_purpose::URL_SAFE_NO_PAD.encode(password);
        format!(
            "ssr://{host}:{port}:{proto}:aes-128-gcm:{obfs}:{password}/?remarks=&protoparam=&obfsparam="
        )
    }

    fn encoded_shadowsocksr_origin_plain_link(host: &str, port: u16, password: &str) -> String {
        let host = general_purpose::URL_SAFE_NO_PAD.encode(host);
        let password = general_purpose::URL_SAFE_NO_PAD.encode(password);
        let body = format!(
            "{host}:{port}:origin:aes-128-gcm:plain:{password}/?remarks=&protoparam=&obfsparam="
        );
        format!("ssr://{}", general_purpose::URL_SAFE_NO_PAD.encode(body))
    }

    #[test]
    fn shadowsocksr_dialer_link_parses_origin_plain_forms_and_rejects_unsupported_variants()
    -> Result<(), TransportError> {
        let password = "shadowsocksr parser password";
        for dialer_link in [
            shadowsocksr_origin_plain_link("127.0.0.1", 8388, password, "origin", "plain"),
            encoded_shadowsocksr_origin_plain_link("127.0.0.1", 8388, password),
        ] {
            assert!(matches!(
                ProxyDialerLink::parse(&dialer_link)?,
                ProxyDialerLink::ShadowsocksR(_)
            ));
        }

        let protocol_error = ProxyDialerLink::parse(&shadowsocksr_origin_plain_link(
            "127.0.0.1",
            8388,
            password,
            "auth_sha1_v4",
            "plain",
        ))
        .expect_err("non-origin SSR protocols need a real SSR protocol stack");
        assert!(matches!(
            protocol_error,
            TransportError::InvalidProxyDialerLink { .. }
        ));
        assert!(
            protocol_error.to_string().contains("protocol auth_sha1_v4"),
            "unexpected error: {protocol_error}"
        );

        let obfs_error = ProxyDialerLink::parse(&shadowsocksr_origin_plain_link(
            "127.0.0.1",
            8388,
            password,
            "origin",
            "http_simple",
        ))
        .expect_err("non-plain SSR obfs needs a real SSR obfs stack");
        assert!(matches!(
            obfs_error,
            TransportError::InvalidProxyDialerLink { .. }
        ));
        assert!(
            obfs_error.to_string().contains("obfs http_simple"),
            "unexpected error: {obfs_error}"
        );

        let scheme_error = ProxyDialerLink::parse(&format!(
            "shadowsocksr://{}",
            &shadowsocksr_origin_plain_link("127.0.0.1", 8388, password, "origin", "plain")
                ["ssr://".len()..]
        ))
        .expect_err("upstream's shadowsocksr:// parser registration is not a usable URL form");
        assert!(matches!(
            scheme_error,
            TransportError::InvalidProxyDialerLink { .. }
        ));
        assert!(
            scheme_error.to_string().contains("ssr:// parser prefix"),
            "unexpected error: {scheme_error}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_shadowsocksr_origin_plain_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let password = "shadowsocksr origin plain password";
        let (proxy_addr, mut requests, proxy_task) =
            start_shadowsocks_tcp_proxy(password, shadowsocks::crypto::CipherKind::AES_128_GCM)
                .await?;
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&shadowsocksr_origin_plain_link(
            &proxy_addr.ip().to_string(),
            proxy_addr.port(),
            password,
            "origin",
            "plain",
        ))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        stream.write_all(b"shadowsocksr origin plain tcp").await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("ShadowsocksR origin/plain proxy did not receive a TCP request")
            .expect("ShadowsocksR origin/plain proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        let mut echoed = vec![0_u8; b"shadowsocksr origin plain tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"shadowsocksr origin plain tcp");
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_relays_udp_target_through_shadowsocksr_origin_plain_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let echo_addr = echo.local_addr();
        let password = "shadowsocksr origin plain udp password";
        let (proxy_addr, mut requests, proxy_task) =
            start_shadowsocks_udp_proxy(password, shadowsocks::crypto::CipherKind::AES_128_GCM)
                .await?;
        let header = OwnedProxyHeader::from_ip(Network::Udp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&shadowsocksr_origin_plain_link(
            &proxy_addr.ip().to_string(),
            proxy_addr.port(),
            password,
            "origin",
            "plain",
        ))?;
        let mut relay_state = UdpEgressRelayState::default();

        let (target, peer, response) = relay_udp_payload_to_target_with_egress(
            &mut relay_state,
            &header,
            b"shadowsocksr origin plain udp",
            &ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("ShadowsocksR origin/plain UDP proxy did not receive a request")
            .expect("ShadowsocksR origin/plain UDP proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        assert_eq!(target, echo_addr);
        assert_eq!(peer, echo_addr);
        assert_eq!(response, b"shadowsocksr origin plain udp");
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_relays_udp_target_through_shadowsocks_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let echo_addr = echo.local_addr();
        let password = "shadowsocks udp dialer link password";
        let (proxy_addr, mut requests, proxy_task) =
            start_shadowsocks_udp_proxy(password, shadowsocks::crypto::CipherKind::AES_128_GCM)
                .await?;
        let userinfo = general_purpose::URL_SAFE_NO_PAD.encode(format!("aes-128-gcm:{password}"));
        let header = OwnedProxyHeader::from_ip(Network::Udp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!("ss://{userinfo}@{proxy_addr}"))?;
        let mut relay_state = UdpEgressRelayState::default();

        let (target, peer, response) = relay_udp_payload_to_target_with_egress(
            &mut relay_state,
            &header,
            b"shadowsocks dialer link udp",
            &ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("Shadowsocks proxy did not receive a UDP payload")
            .expect("Shadowsocks UDP proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        assert_eq!(target, echo_addr);
        assert_eq!(peer, echo_addr);
        assert_eq!(response, b"shadowsocks dialer link udp");
        drop(relay_state);
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_socks_alias_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let (proxy_addr, mut requests, proxy_task) = start_socks5_tcp_connect_proxy().await?;
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!("socks://{proxy_addr}"))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(200), requests.recv())
            .await
            .expect("SOCKS alias proxy did not receive a CONNECT request")
            .expect("SOCKS alias proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        stream.write_all(b"socks alias dialer link tcp").await?;
        let mut echoed = vec![0_u8; b"socks alias dialer link tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"socks alias dialer link tcp");
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_socks5_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let (proxy_addr, mut requests, proxy_task) = start_socks5_tcp_connect_proxy().await?;
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!("socks5://{proxy_addr}"))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(200), requests.recv())
            .await
            .expect("SOCKS5 proxy did not receive a CONNECT request")
            .expect("SOCKS5 proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        stream.write_all(b"socks5 dialer link tcp").await?;
        let mut echoed = vec![0_u8; b"socks5 dialer link tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"socks5 dialer link tcp");
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_http_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let (proxy_addr, mut requests, proxy_task) = start_http_connect_proxy().await?;
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!("http://{proxy_addr}"))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(200), requests.recv())
            .await
            .expect("HTTP proxy did not receive a CONNECT request")
            .expect("HTTP proxy request channel closed");
        assert_eq!(request.authority, echo_addr.to_string());
        stream.write_all(b"http dialer link tcp").await?;
        let mut echoed = vec![0_u8; b"http dialer link tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"http dialer link tcp");
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_http_dialer_link_with_basic_auth()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let (proxy_addr, mut requests, proxy_task) = start_http_connect_proxy().await?;
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link =
            ProxyDialerLink::parse(&format!("http://proxy-user:proxy-pass@{proxy_addr}"))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(200), requests.recv())
            .await
            .expect("HTTP proxy did not receive an authenticated CONNECT request")
            .expect("HTTP proxy request channel closed");
        assert_eq!(request.authority, echo_addr.to_string());
        assert_eq!(
            request.proxy_authorization,
            Some("Basic cHJveHktdXNlcjpwcm94eS1wYXNz".to_owned())
        );
        stream.write_all(b"http dialer link tcp basic auth").await?;
        let mut echoed = vec![0_u8; b"http dialer link tcp basic auth".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"http dialer link tcp basic auth");
        drop(stream);
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_https_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let (proxy_addr, mut requests, proxy_task) = start_https_connect_proxy().await?;
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!(
            "https://localhost:{port}?allowInsecure=true",
            port = proxy_addr.port()
        ))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("HTTPS proxy did not receive a CONNECT request")
            .expect("HTTPS proxy request channel closed");
        assert_eq!(request.authority, echo_addr.to_string());
        stream.write_all(b"https dialer link tcp").await?;
        let mut echoed = vec![0_u8; b"https dialer link tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"https dialer link tcp");
        stream.shutdown().await?;
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_https_dialer_link_with_basic_auth()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let (proxy_addr, mut requests, proxy_task) = start_https_connect_proxy().await?;
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!(
            "https://proxy-user:proxy-pass@localhost:{port}?allowInsecure=true",
            port = proxy_addr.port()
        ))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(500), requests.recv())
            .await
            .expect("HTTPS proxy did not receive an authenticated CONNECT request")
            .expect("HTTPS proxy request channel closed");
        assert_eq!(request.authority, echo_addr.to_string());
        assert_eq!(
            request.proxy_authorization,
            Some("Basic cHJveHktdXNlcjpwcm94eS1wYXNz".to_owned())
        );
        stream
            .write_all(b"https dialer link tcp basic auth")
            .await?;
        let mut echoed = vec![0_u8; b"https dialer link tcp basic auth".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"https dialer link tcp basic auth");
        stream.shutdown().await?;
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_socks5_https_dialer_chain()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let (https_proxy_addr, mut https_requests, https_proxy_task) =
            start_https_connect_proxy().await?;
        let (socks_proxy_addr, mut socks_requests, socks_proxy_task) =
            start_socks5_tcp_connect_proxy().await?;
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!(
            "socks5://{socks_proxy_addr} -> https://localhost:{port}?allowInsecure=true",
            port = https_proxy_addr.port()
        ))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let https_request =
            tokio::time::timeout(std::time::Duration::from_millis(500), https_requests.recv())
                .await
                .expect("HTTPS proxy did not receive an outer CONNECT request")
                .expect("HTTPS proxy request channel closed");
        assert_eq!(https_request.authority, socks_proxy_addr.to_string());
        let socks_request =
            tokio::time::timeout(std::time::Duration::from_millis(500), socks_requests.recv())
                .await
                .expect("SOCKS5 proxy did not receive an inner CONNECT request")
                .expect("SOCKS5 proxy request channel closed");
        assert_eq!(socks_request.target, echo_addr);
        stream.write_all(b"socks5 https dialer chain tcp").await?;
        let mut echoed = vec![0_u8; b"socks5 https dialer chain tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"socks5 https dialer chain tcp");
        stream.shutdown().await?;
        socks_proxy_task.await??;
        https_proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_socks5_http_dialer_chain()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let (http_proxy_addr, mut http_requests, http_proxy_task) =
            start_http_connect_proxy().await?;
        let (socks_proxy_addr, mut socks_requests, socks_proxy_task) =
            start_socks5_tcp_connect_proxy().await?;
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!(
            "socks5://{socks_proxy_addr} -> http://{http_proxy_addr}"
        ))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let http_request =
            tokio::time::timeout(std::time::Duration::from_millis(200), http_requests.recv())
                .await
                .expect("HTTP proxy did not receive an outer CONNECT request")
                .expect("HTTP proxy request channel closed");
        assert_eq!(http_request.authority, socks_proxy_addr.to_string());
        let socks_request =
            tokio::time::timeout(std::time::Duration::from_millis(200), socks_requests.recv())
                .await
                .expect("SOCKS5 proxy did not receive an inner CONNECT request")
                .expect("SOCKS5 proxy request channel closed");
        assert_eq!(socks_request.target, echo_addr);
        stream.write_all(b"socks5 http dialer chain tcp").await?;
        let mut echoed = vec![0_u8; b"socks5 http dialer chain tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"socks5 http dialer chain tcp");
        drop(stream);
        socks_proxy_task.await??;
        http_proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_vless_http_dialer_chain()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let (http_proxy_addr, mut http_requests, http_proxy_task) =
            start_http_connect_proxy().await?;
        let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
            .expect("valid fixture UUID");
        let (vless_proxy_addr, mut vless_requests, vless_proxy_task) =
            start_vless_tcp_proxy(uuid).await?;
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!(
            "vless://{uuid}@127.0.0.1:{vless_port}?type=tcp&security=none&headerType=none -> http://{http_proxy_addr}",
            vless_port = vless_proxy_addr.port()
        ))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let http_request =
            tokio::time::timeout(std::time::Duration::from_millis(500), http_requests.recv())
                .await
                .expect("HTTP proxy did not receive an outer CONNECT request")
                .expect("HTTP proxy request channel closed");
        assert_eq!(http_request.authority, vless_proxy_addr.to_string());
        let vless_request =
            tokio::time::timeout(std::time::Duration::from_millis(500), vless_requests.recv())
                .await
                .expect("VLESS proxy did not receive an inner TCP request")
                .expect("VLESS proxy request channel closed");
        assert_eq!(vless_request.target, echo_addr);
        assert_eq!(vless_request.network, Network::Tcp);
        assert_eq!(vless_request.uuid, uuid);
        stream.write_all(b"vless http dialer chain tcp").await?;
        let mut echoed = vec![0_u8; b"vless http dialer chain tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"vless http dialer chain tcp");
        stream.shutdown().await?;
        vless_proxy_task.await??;
        http_proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_connects_tcp_target_through_vmess_http_dialer_chain()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::TcpEchoServer::start()
            .await
            .expect("start TCP echo fixture");
        let echo_addr = echo.local_addr();
        let (http_proxy_addr, mut http_requests, http_proxy_task) =
            start_http_connect_proxy().await?;
        let uuid = "00000000-0000-0000-0000-000000000001";
        let key = vless_user_to_key("vmess fixture", uuid)?;
        let (vmess_proxy_addr, mut vmess_requests, vmess_proxy_task) =
            start_vmess_tcp_proxy(key).await?;
        let json = general_purpose::STANDARD.encode(format!(
            r#"{{"add":"127.0.0.1","port":"{}","id":"{uuid}","aid":"0","net":"tcp","type":"none","tls":""}}"#,
            vmess_proxy_addr.port()
        ));
        let header = OwnedProxyHeader::from_ip(Network::Tcp, echo_addr.ip(), echo_addr.port());
        let dialer_link =
            ProxyDialerLink::parse(&format!("vmess://{json} -> http://{http_proxy_addr}"))?;

        let mut stream = connect_tcp_proxy_target_with_egress(
            &header,
            ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let http_request =
            tokio::time::timeout(std::time::Duration::from_millis(500), http_requests.recv())
                .await
                .expect("HTTP proxy did not receive an outer CONNECT request")
                .expect("HTTP proxy request channel closed");
        assert_eq!(http_request.authority, vmess_proxy_addr.to_string());
        let vmess_request =
            tokio::time::timeout(std::time::Duration::from_millis(500), vmess_requests.recv())
                .await
                .expect("VMess proxy did not receive an inner TCP request")
                .expect("VMess proxy request channel closed");
        assert_eq!(vmess_request.target, echo_addr);
        assert_eq!(vmess_request.network, Network::Tcp);
        assert_eq!(vmess_request.key, key);
        stream.write_all(b"vmess http dialer chain tcp").await?;
        let mut echoed = vec![0_u8; b"vmess http dialer chain tcp".len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"vmess http dialer chain tcp");
        stream.shutdown().await?;
        vmess_proxy_task.await??;
        http_proxy_task.await??;
        echo.shutdown().await.expect("shutdown TCP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_relays_udp_target_through_socks5_shadowsocks_dialer_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        zuicity_testkit::retry_on_addr_in_use(|| async {
            let echo = zuicity_testkit::UdpEchoServer::start()
                .await
                .expect("start UDP echo fixture");
            let echo_addr = echo.local_addr();
            let (socks_proxy_addr, mut socks_requests, socks_proxy_task) =
                start_socks5_udp_associate_proxy().await?;
            let password = "socks5 shadowsocks udp chain password";
            let (
                shadowsocks_proxy_addr,
                mut shadowsocks_tcp_requests,
                mut shadowsocks_udp_requests,
                shadowsocks_proxy_task,
            ) = start_shadowsocks_tcp_udp_proxy(
                password,
                shadowsocks::crypto::CipherKind::AES_128_GCM,
            )
            .await?;
            let userinfo =
                general_purpose::URL_SAFE_NO_PAD.encode(format!("aes-128-gcm:{password}"));
            let header = OwnedProxyHeader::from_ip(Network::Udp, echo_addr.ip(), echo_addr.port());
            let dialer_link = ProxyDialerLink::parse(&format!(
                "socks5://{socks_proxy_addr} -> ss://{userinfo}@{shadowsocks_proxy_addr}"
            ))?;
            let mut relay_state = UdpEgressRelayState::default();

            let (target, peer, response) = relay_udp_payload_to_target_with_egress(
                &mut relay_state,
                &header,
                b"socks5 shadowsocks dialer chain udp",
                &ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                    None,
                    None,
                    Some(dialer_link),
                ),
            )
            .await?;
            let shadowsocks_tcp_request = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                shadowsocks_tcp_requests.recv(),
            )
            .await
            .expect("Shadowsocks proxy did not receive the SOCKS5 TCP control request")
            .expect("Shadowsocks TCP request channel closed");
            assert_eq!(shadowsocks_tcp_request.target, socks_proxy_addr);
            let shadowsocks_udp_request = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                shadowsocks_udp_requests.recv(),
            )
            .await
            .expect("Shadowsocks proxy did not receive the SOCKS5 UDP relay datagram")
            .expect("Shadowsocks UDP request channel closed");
            assert_eq!(shadowsocks_udp_request.target.ip(), socks_proxy_addr.ip());
            let socks_request =
                tokio::time::timeout(std::time::Duration::from_millis(500), socks_requests.recv())
                    .await
                    .expect(
                        "SOCKS5 proxy did not receive a UDP ASSOCIATE payload through Shadowsocks",
                    )
                    .expect("SOCKS5 proxy request channel closed");
            assert_eq!(socks_request.target, echo_addr);
            assert_eq!(target, echo_addr);
            assert_eq!(peer, echo_addr);
            assert_eq!(response, b"socks5 shadowsocks dialer chain udp");
            drop(relay_state);
            socks_proxy_task.await??;
            shadowsocks_proxy_task.await??;
            echo.shutdown().await.expect("shutdown UDP echo fixture");
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn proxy_egress_policy_relays_udp_target_through_shadowsocks_socks5_dialer_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        zuicity_testkit::retry_on_addr_in_use(|| async {
            let echo = zuicity_testkit::UdpEchoServer::start()
                .await
                .expect("start UDP echo fixture");
            let echo_addr = echo.local_addr();
            let (socks_proxy_addr, mut socks_requests, socks_proxy_task) =
                start_socks5_udp_associate_proxy().await?;
            let password = "shadowsocks socks5 udp chain password";
            let (shadowsocks_proxy_addr, mut shadowsocks_requests, shadowsocks_proxy_task) =
                start_shadowsocks_udp_proxy(password, shadowsocks::crypto::CipherKind::AES_128_GCM)
                    .await?;
            let userinfo =
                general_purpose::URL_SAFE_NO_PAD.encode(format!("aes-128-gcm:{password}"));
            let header = OwnedProxyHeader::from_ip(Network::Udp, echo_addr.ip(), echo_addr.port());
            let dialer_link = ProxyDialerLink::parse(&format!(
                "ss://{userinfo}@{shadowsocks_proxy_addr} -> socks5://{socks_proxy_addr}"
            ))?;
            let mut relay_state = UdpEgressRelayState::default();

            let (target, peer, response) = relay_udp_payload_to_target_with_egress(
                &mut relay_state,
                &header,
                b"shadowsocks socks5 dialer chain udp",
                &ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                    None,
                    None,
                    Some(dialer_link),
                ),
            )
            .await?;
            let socks_request =
                tokio::time::timeout(std::time::Duration::from_millis(500), socks_requests.recv())
                    .await
                    .expect("SOCKS5 proxy did not receive the Shadowsocks UDP relay datagram")
                    .expect("SOCKS5 proxy request channel closed");
            assert_eq!(socks_request.target, shadowsocks_proxy_addr);
            let shadowsocks_request = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                shadowsocks_requests.recv(),
            )
            .await
            .expect("Shadowsocks proxy did not receive the final UDP payload through SOCKS5")
            .expect("Shadowsocks UDP request channel closed");
            assert_eq!(shadowsocks_request.target, echo_addr);
            assert_eq!(target, echo_addr);
            assert_eq!(peer, echo_addr);
            assert_eq!(response, b"shadowsocks socks5 dialer chain udp");
            drop(relay_state);
            shadowsocks_proxy_task.await??;
            socks_proxy_task.await??;
            echo.shutdown().await.expect("shutdown UDP echo fixture");
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn proxy_egress_policy_rejects_udp_target_through_http_connect_dialer_link()
    -> Result<(), TransportError> {
        let header =
            OwnedProxyHeader::from_ip(Network::Udp, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 53);
        let dialer_link = ProxyDialerLink::parse("http://127.0.0.1:18080")?;
        let mut relay_state = UdpEgressRelayState::default();

        let error = relay_udp_payload_to_target_with_egress(
            &mut relay_state,
            &header,
            b"http udp boundary",
            &ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await
        .expect_err("upstream HTTP CONNECT dialer rejects UDP tunnels");
        assert!(
            matches!(
                error,
                TransportError::UnsupportedProxyDialerLinkNetwork {
                    scheme: "http",
                    network: Network::Udp,
                }
            ),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_rejects_udp_target_through_https_connect_dialer_link()
    -> Result<(), TransportError> {
        let header =
            OwnedProxyHeader::from_ip(Network::Udp, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 53);
        let dialer_link = ProxyDialerLink::parse("https://localhost:18443?allowInsecure=true")?;
        let mut relay_state = UdpEgressRelayState::default();

        let error = relay_udp_payload_to_target_with_egress(
            &mut relay_state,
            &header,
            b"https udp boundary",
            &ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await
        .expect_err("upstream HTTPS CONNECT dialer rejects UDP tunnels");
        assert!(
            matches!(
                error,
                TransportError::UnsupportedProxyDialerLinkNetwork {
                    scheme: "https",
                    network: Network::Udp,
                }
            ),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_rejects_udp_target_through_http_dialer_chain_boundary()
    -> Result<(), TransportError> {
        let header =
            OwnedProxyHeader::from_ip(Network::Udp, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 53);
        let dialer_link =
            ProxyDialerLink::parse("socks5://127.0.0.1:1080 -> http://127.0.0.1:18080")?;
        let mut relay_state = UdpEgressRelayState::default();

        let error = relay_udp_payload_to_target_with_egress(
            &mut relay_state,
            &header,
            b"http chain udp boundary",
            &ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await
        .expect_err("HTTP-containing UDP proxy chains remain an explicit boundary");
        assert!(
            matches!(
                error,
                TransportError::UnsupportedProxyDialerLinkNetwork {
                    scheme: "chain",
                    network: Network::Udp,
                }
            ),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn proxy_egress_policy_relays_udp_target_through_socks5_dialer_link()
    -> Result<(), TransportError> {
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let echo_addr = echo.local_addr();
        let (proxy_addr, mut requests, proxy_task) = start_socks5_udp_associate_proxy().await?;
        let header = OwnedProxyHeader::from_ip(Network::Udp, echo_addr.ip(), echo_addr.port());
        let dialer_link = ProxyDialerLink::parse(&format!("socks5://{proxy_addr}"))?;
        let mut relay_state = UdpEgressRelayState::default();

        let (target, peer, response) = relay_udp_payload_to_target_with_egress(
            &mut relay_state,
            &header,
            b"socks5 dialer link udp",
            &ProxyEgressPolicy::with_send_through_fwmark_and_dialer_link(
                None,
                None,
                Some(dialer_link),
            ),
        )
        .await?;
        let request = tokio::time::timeout(std::time::Duration::from_millis(200), requests.recv())
            .await
            .expect("SOCKS5 proxy did not receive a UDP ASSOCIATE payload")
            .expect("SOCKS5 proxy request channel closed");
        assert_eq!(request.target, echo_addr);
        assert_eq!(target, echo_addr);
        assert_eq!(peer, echo_addr);
        assert_eq!(response, b"socks5 dialer link udp");
        drop(relay_state);
        proxy_task.await??;
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn fwmark_permission_denied(error: &std::io::Error) -> bool {
        error.kind() == std::io::ErrorKind::PermissionDenied
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn transport_fwmark_permission_denied(error: &TransportError) -> bool {
        matches!(error, TransportError::Io(source) if fwmark_permission_denied(source))
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[tokio::test]
    async fn proxy_egress_policy_sets_tcp_target_socket_fwmark() -> Result<(), TransportError> {
        let fwmark = 0x1234;
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let target = listener.local_addr()?;
        let accept_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            Ok::<_, std::io::Error>(stream)
        });

        let stream = match connect_tcp_socket_to_target(
            target,
            &ProxyEgressPolicy::with_send_through_and_fwmark(None, Some(fwmark)),
        )
        .await
        {
            Ok(stream) => stream,
            Err(error) if fwmark_permission_denied(&error) => {
                accept_task.abort();
                eprintln!("skipping SO_MARK TCP assertion because the host denied mark setting");
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let observed = socket2::SockRef::from(&stream).mark()?;
        assert_eq!(observed, fwmark);
        drop(stream);
        drop(accept_task.await??);
        Ok(())
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[tokio::test]
    async fn proxy_egress_policy_sets_udp_target_socket_fwmark() -> Result<(), TransportError> {
        let fwmark = 0x1234;
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let echo_addr = echo.local_addr();
        let header = OwnedProxyHeader::from_ip(Network::Udp, echo_addr.ip(), echo_addr.port());
        let mut relay_socket = None;

        let (_target, _peer, response) = match relay_udp_payload_to_target_with_socket(
            &mut relay_socket,
            &header,
            b"fwmark udp payload",
            &ProxyEgressPolicy::with_send_through_and_fwmark(None, Some(fwmark)),
        )
        .await
        {
            Ok(result) => result,
            Err(error) if transport_fwmark_permission_denied(&error) => {
                echo.shutdown().await.expect("shutdown UDP echo fixture");
                eprintln!("skipping SO_MARK UDP assertion because the host denied mark setting");
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        assert_eq!(response, b"fwmark udp payload");
        let socket = &relay_socket
            .as_ref()
            .expect("relay socket remains available")
            .1;
        let observed = socket2::SockRef::from(socket).mark()?;
        assert_eq!(observed, fwmark);
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[test]
    fn udp_response_target_normalizes_ipv4_mapped_ipv6_peer() -> Result<(), TransportError> {
        let header = OwnedProxyHeader {
            network: Network::Udp,
            address: OwnedProxyAddress::Ipv6("::ffff:127.0.0.1".parse().expect("mapped IPv6")),
            port: 53,
        };
        assert_eq!(
            udp_ip_header_target(&header)?,
            SocketAddr::from(([127, 0, 0, 1], 53))
        );
        Ok(())
    }

    #[tokio::test]
    async fn rust_rust_udp_over_stream_reaches_domain_echo_target() -> Result<(), TransportError> {
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate fixture cert");
        let uuid = uuid::Uuid::new_v4();
        let password = b"udp domain password";

        let server = JuicityQuicServer::bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let echo_addr = echo.local_addr();

        let server_task = tokio::spawn(async move {
            let authenticated = server.accept_authenticated(uuid, password).await?;
            authenticated.accept_udp_over_stream_once().await
        });

        let client = JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let authenticated = client
            .connect_with_roots(
                server_addr,
                "localhost",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password,
            )
            .await?;
        let mut stream = authenticated
            .open_udp_over_domain_stream("localhost", echo_addr.port())
            .await?;
        stream.send_datagram(b"udp domain ping").await?;
        let response = stream.recv_datagram(1024).await?;
        assert_eq!(response.payload, b"udp domain ping");
        stream.finish()?;

        let relayed = server_task.await??;
        assert_eq!(relayed.target, echo_addr);
        assert_eq!(relayed.bytes_from_client, b"udp domain ping".len() as u64);
        assert_eq!(relayed.bytes_from_target, b"udp domain ping".len() as u64);
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn rust_rust_udp_over_stream_reaches_echo_target() -> Result<(), TransportError> {
        let echo = zuicity_testkit::UdpEchoServer::start()
            .await
            .expect("start UDP echo fixture");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate fixture cert");
        let uuid = uuid::Uuid::new_v4();
        let password = b"udp over stream password";

        let server = JuicityQuicServer::bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let echo_addr = echo.local_addr();

        let server_task = tokio::spawn(async move {
            let authenticated = server.accept_authenticated(uuid, password).await?;
            authenticated.accept_udp_over_stream_once().await
        });

        let client = JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let authenticated = client
            .connect_with_roots(
                server_addr,
                "localhost",
                cert.cert.pem().as_bytes(),
                false,
                uuid,
                password,
            )
            .await?;
        let mut stream = authenticated
            .open_udp_over_stream(echo_addr.ip(), echo_addr.port())
            .await?;

        stream.send_datagram(b"dns-ish payload").await?;
        let echoed = stream.recv_datagram(1024).await?;
        assert_eq!(echoed.payload, b"dns-ish payload");
        assert_eq!(echoed.target, echo_addr);
        stream.finish()?;

        let relayed = server_task.await??;
        assert_eq!(relayed.target, echo_addr);
        assert_eq!(relayed.bytes_from_client, b"dns-ish payload".len() as u64);
        assert_eq!(relayed.bytes_from_target, b"dns-ish payload".len() as u64);
        echo.shutdown().await.expect("shutdown UDP echo fixture");
        Ok(())
    }

    #[tokio::test]
    async fn pinned_cert_chain_allows_self_signed_match_without_root_trust()
    -> Result<(), TransportError> {
        let cert = rcgen::generate_simple_self_signed(vec!["pin.local".to_owned()])
            .expect("generate fixture cert");
        let uuid = uuid::Uuid::new_v4();
        let password = b"pin password";
        let pinned = zuicity_protocol::generate_cert_chain_hash([cert.cert.der().as_ref()])
            .expect("hash fixture cert");

        let server = JuicityQuicServer::bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;
        let server_task = tokio::spawn(async move {
            let authenticated = server.accept_authenticated(uuid, password).await?;
            Ok::<_, TransportError>(authenticated.remote_address())
        });

        let client = JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let connection = client
            .connect_with_cert_chain_pin(server_addr, "pin.local", &pinned, uuid, password)
            .await?;
        assert_eq!(connection.remote_address(), server_addr);
        server_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn pinned_cert_chain_rejects_self_signed_mismatch() -> Result<(), TransportError> {
        let cert = rcgen::generate_simple_self_signed(vec!["pin.local".to_owned()])
            .expect("generate fixture cert");
        let uuid = uuid::Uuid::new_v4();
        let mut pinned = zuicity_protocol::generate_cert_chain_hash([cert.cert.der().as_ref()])
            .expect("hash fixture cert");
        pinned[0] ^= 0xff;

        let server = JuicityQuicServer::bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let server_addr = server.local_addr()?;

        let client = JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())?;
        let error = client
            .connect_with_cert_chain_pin(server_addr, "pin.local", &pinned, uuid, b"unused")
            .await
            .expect_err("mismatched pin rejects connection");
        assert!(matches!(error, TransportError::Connection(_)));
        Ok(())
    }

    #[test]
    fn upstream_tls_policy_requires_tls13_and_h3() {
        let policy = TlsPolicy::upstream();

        assert_eq!(policy.alpn, ALPN_H3);
        assert_eq!(policy.min_version, MinimumTlsVersion::Tls13);
        assert!(policy.tls13_or_newer);
    }

    fn short_header_transmit(dest: SocketAddr, segment: usize, segments: usize) -> Vec<u8> {
        // Short-header QUIC packets clear the high bit (0x80) of the first byte.
        // Build `segments` chunks of `segment` bytes each; first byte 0x40.
        let mut contents = vec![0x55_u8; segment * segments];
        for index in 0..segments {
            contents[index * segment] = 0x40;
        }
        let _ = dest;
        contents
    }

    #[tokio::test]
    async fn gso_fallback_resends_both_datagrams_and_marks_dest_disabled() -> std::io::Result<()> {
        // Test A: force the first GSO sendmsg to EINVAL and assert the same-call
        // fallback delivers BOTH datagrams while the destination is disabled.
        let receiver = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        receiver.set_nonblocking(true)?;
        let dest = receiver.local_addr()?;

        let sender_std = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let socket = PlainUdpSocket::with_mode_and_hook(
            sender_std,
            GsoMode::Auto,
            GsoTestHook::FirstEinval,
        )?;
        let counters = socket.counters();

        let segment = 1200;
        let contents = short_header_transmit(dest, segment, 2);
        let transmit = quinn::udp::Transmit {
            destination: dest,
            ecn: None,
            contents: &contents,
            segment_size: Some(segment),
            src_ip: None,
        };

        quinn::AsyncUdpSocket::try_send(&socket, &transmit)?;

        let mut received = 0;
        let mut buf = [0_u8; 2048];
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while received < 2 && std::time::Instant::now() < deadline {
            match receiver.recv_from(&mut buf) {
                Ok((len, _)) => {
                    assert_eq!(len, segment, "each fallback datagram is one segment");
                    received += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(error),
            }
        }

        assert_eq!(received, 2, "both datagrams delivered after fallback");
        assert_eq!(counters.attempt.load(Ordering::Relaxed), 1);
        assert_eq!(counters.fallback.load(Ordering::Relaxed), 1);
        assert_eq!(counters.plain_after_fallback.load(Ordering::Relaxed), 1);
        assert_eq!(counters.long_header_gso_attempt.load(Ordering::Relaxed), 0);
        assert_eq!(socket.gso_dest_state(dest), GsoDestState::Disabled);
        Ok(())
    }

    #[tokio::test]
    async fn long_header_transmit_is_never_segmented_even_when_gso_working() -> std::io::Result<()>
    {
        // Test C: a batched transmit whose first byte has 0x80 set is sent as
        // plain datagrams even when GSO is otherwise eligible/working.
        let receiver = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        receiver.set_nonblocking(true)?;
        let dest = receiver.local_addr()?;

        let sender_std = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let socket =
            PlainUdpSocket::with_mode_and_hook(sender_std, GsoMode::Auto, GsoTestHook::None)?;
        // Pre-mark the destination Working so only the long-header guard can
        // route this transmit to the plain path.
        socket.set_dest_state(dest, GsoDestState::Working);
        let counters = socket.counters();

        let segment = 1200;
        let mut contents = vec![0x55_u8; segment * 2];
        contents[0] = 0x80; // long-header (Initial) high bit set on first segment.
        contents[segment] = 0x40;
        let transmit = quinn::udp::Transmit {
            destination: dest,
            ecn: None,
            contents: &contents,
            segment_size: Some(segment),
            src_ip: None,
        };

        quinn::AsyncUdpSocket::try_send(&socket, &transmit)?;

        let mut received = 0;
        let mut buf = [0_u8; 2048];
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while received < 2 && std::time::Instant::now() < deadline {
            match receiver.recv_from(&mut buf) {
                Ok((len, _)) => {
                    assert_eq!(
                        len, segment,
                        "long-header transmit split into plain datagrams"
                    );
                    received += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(error),
            }
        }

        assert_eq!(
            received, 2,
            "long-header transmit delivered as two plain datagrams"
        );
        assert_eq!(
            counters.attempt.load(Ordering::Relaxed),
            0,
            "no GSO attempt for a long-header transmit"
        );
        assert_eq!(counters.long_header_gso_attempt.load(Ordering::Relaxed), 0);
        Ok(())
    }

    fn build_hooked_endpoint(
        addr: SocketAddr,
        server_config: Option<quinn::ServerConfig>,
        hook: GsoTestHook,
    ) -> Result<(quinn::Endpoint, Arc<PlainUdpSocket>), TransportError> {
        let std_socket = std::net::UdpSocket::bind(addr)?;
        let socket = Arc::new(PlainUdpSocket::with_mode_and_hook(
            std_socket,
            GsoMode::Auto,
            hook,
        )?);
        let runtime = quinn::default_runtime()
            .ok_or_else(|| std::io::Error::other("no async runtime found"))?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            server_config,
            Arc::clone(&socket) as Arc<dyn quinn::AsyncUdpSocket>,
            runtime,
        )?;
        Ok((endpoint, socket))
    }

    #[tokio::test]
    async fn handshake_survives_gso_hostile_path_and_never_segments_long_header()
    -> Result<(), TransportError> {
        // Test B: every GSO attempt fails (AlwaysEinval) yet a real cross-socket
        // QUIC handshake + small echo succeeds, and no long-header packet ever
        // reaches the GSO path.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate fixture cert");
        let server_crypto = build_server_crypto_config_from_pem(
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
        ));
        server_config.transport_config(
            build_transport_config(&QuicRuntimePolicy::upstream_server()).into_arc(),
        );

        let (server_endpoint, server_socket) = build_hooked_endpoint(
            ([127, 0, 0, 1], 0).into(),
            Some(server_config),
            GsoTestHook::AlwaysEinval,
        )?;
        let server_addr = server_endpoint.local_addr()?;

        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint
                .accept()
                .await
                .ok_or(TransportError::EndpointClosed)?;
            let connection = incoming.accept()?.await?;
            let (mut send, mut recv) = connection.accept_bi().await?;
            let payload = recv.read_to_end(4096).await?;
            send.write_all(&payload).await?;
            send.finish()?;
            // Await peer acknowledgement of the FIN before this task returns and
            // the connection is dropped, so the graceful close never races the
            // client draining the echoed bytes into a spurious closed-by-peer
            // error (the same shutdown ordering the production relay relies on).
            send.stopped().await?;
            Ok::<_, TransportError>(payload.len())
        });

        let client_crypto =
            build_client_crypto_config_with_roots(cert.cert.pem().as_bytes(), false)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
        ));
        client_config.transport_config(
            build_transport_config(&QuicRuntimePolicy::upstream_client()).into_arc(),
        );

        let (client_endpoint, client_socket) =
            build_hooked_endpoint(([127, 0, 0, 1], 0).into(), None, GsoTestHook::AlwaysEinval)?;
        let connection = client_endpoint
            .connect_with(client_config, server_addr, "localhost")?
            .await?;

        let (mut send, mut recv) = connection.open_bi().await?;
        let probe = b"gso-hostile-path-echo";
        send.write_all(probe).await?;
        send.finish()?;
        let echoed = recv.read_to_end(probe.len()).await?;
        assert_eq!(echoed, probe, "echo round-trips over a GSO-hostile path");

        let server_read = server_task.await??;
        assert_eq!(server_read, probe.len());

        assert_eq!(
            client_socket
                .counters()
                .long_header_gso_attempt
                .load(Ordering::Relaxed),
            0,
            "client never attempted GSO on a long-header packet"
        );
        assert_eq!(
            server_socket
                .counters()
                .long_header_gso_attempt
                .load(Ordering::Relaxed),
            0,
            "server never attempted GSO on a long-header packet"
        );
        assert_eq!(
            client_socket.counters().success.load(Ordering::Relaxed),
            0,
            "all GSO attempts failed yet the handshake still completed"
        );
        Ok(())
    }

    fn build_gro_endpoint(
        addr: SocketAddr,
        server_config: Option<quinn::ServerConfig>,
        gro_mode: GroMode,
    ) -> Result<(quinn::Endpoint, Arc<PlainUdpSocket>), TransportError> {
        let std_socket = std::net::UdpSocket::bind(addr)?;
        let socket = Arc::new(PlainUdpSocket::with_modes_and_hook(
            std_socket,
            GsoMode::Auto,
            gro_mode,
            GsoTestHook::None,
        )?);
        let runtime = quinn::default_runtime()
            .ok_or_else(|| std::io::Error::other("no async runtime found"))?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            server_config,
            Arc::clone(&socket) as Arc<dyn quinn::AsyncUdpSocket>,
            runtime,
        )?;
        Ok((endpoint, socket))
    }

    async fn run_gro_bulk_transfer(
        gro_mode: GroMode,
    ) -> Result<(Arc<PlainUdpSocket>, usize), TransportError> {
        // Server echoes a multi-MiB upload; the bulk ingress drives the kernel
        // to coalesce same-sized datagrams when GRO is enabled. Returns the
        // server socket (for GRO-counter assertions) and the verified byte
        // count, so a caller can prove both throughput and integrity.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate fixture cert");
        let server_crypto = build_server_crypto_config_from_pem(
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
        ));
        server_config.transport_config(
            build_transport_config(&QuicRuntimePolicy::upstream_server()).into_arc(),
        );

        let (server_endpoint, server_socket) =
            build_gro_endpoint(([127, 0, 0, 1], 0).into(), Some(server_config), gro_mode)?;
        let server_addr = server_endpoint.local_addr()?;

        let payload_len = 4 * 1024 * 1024;
        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint
                .accept()
                .await
                .ok_or(TransportError::EndpointClosed)?;
            let connection = incoming.accept()?.await?;
            let (mut send, mut recv) = connection.accept_bi().await?;
            let payload = recv.read_to_end(payload_len).await?;
            send.write_all(&payload).await?;
            send.finish()?;
            send.stopped().await?;
            Ok::<_, TransportError>(payload.len())
        });

        let client_crypto =
            build_client_crypto_config_with_roots(cert.cert.pem().as_bytes(), false)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
        ));
        client_config.transport_config(
            build_transport_config(&QuicRuntimePolicy::upstream_client()).into_arc(),
        );

        let (client_endpoint, _client_socket) =
            build_gro_endpoint(([127, 0, 0, 1], 0).into(), None, gro_mode)?;
        let connection = client_endpoint
            .connect_with(client_config, server_addr, "localhost")?
            .await?;

        let (mut send, mut recv) = connection.open_bi().await?;
        let upload: Vec<u8> = (0..payload_len).map(|index| (index % 251) as u8).collect();
        send.write_all(&upload).await?;
        send.finish()?;
        let echoed = recv.read_to_end(payload_len).await?;
        assert_eq!(echoed.len(), payload_len, "echo returns the full payload");
        assert_eq!(echoed, upload, "echoed bytes match the upload exactly");

        let server_read = server_task.await??;
        assert_eq!(server_read, payload_len);
        Ok((server_socket, server_read))
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gro_coalesces_bulk_recv_and_preserves_integrity() -> Result<(), TransportError> {
        // Drive a 4 MiB QUIC upload over a GRO-enabled loopback path. The kernel
        // coalesces same-sized datagrams into super-buffers; the GRO recv path
        // must split them by the cmsg-reported stride (so the echo stays byte
        // exact) and tally the coalescing counters.
        let (server_socket, _len) = run_gro_bulk_transfer(GroMode::Auto).await?;

        // GRO availability is environmental (kernel/path). If the receive socket
        // never got GRO it falls back to plain and cannot coalesce, so only
        // assert coalescing when GRO actually engaged on this host.
        if server_socket.gro_recv.is_some() {
            let counters = server_socket.gro_counters();
            let coalesced = counters.gro_coalesced_recv.load(Ordering::Relaxed);
            let segments = counters.gro_segments_total.load(Ordering::Relaxed);
            assert!(
                coalesced > 0,
                "bulk ingress over a GRO socket must coalesce at least once"
            );
            assert!(
                segments > coalesced,
                "coalesced reads must carry more segments than reads ({segments} > {coalesced})"
            );
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gro_disabled_path_transfers_without_coalescing() -> Result<(), TransportError> {
        // With GRO Off the same bulk transfer must still round-trip byte-exact,
        // and the GRO counters must stay at zero (no coalescing path taken).
        let (server_socket, _len) = run_gro_bulk_transfer(GroMode::Off).await?;
        assert!(
            server_socket.gro_recv.is_none(),
            "GroMode::Off must not build a GRO receiver"
        );
        let counters = server_socket.gro_counters();
        assert_eq!(
            counters.gro_coalesced_recv.load(Ordering::Relaxed),
            0,
            "no coalescing when GRO is disabled"
        );
        assert_eq!(
            counters.gro_segments_total.load(Ordering::Relaxed),
            0,
            "no GRO segments counted when GRO is disabled"
        );
        Ok(())
    }

    #[test]
    fn tuic_auth_frame_matches_juicity_frame_length() {
        let uuid = uuid::Uuid::from_bytes([0x11; 16]);
        let token = [0x22_u8; zuicity_protocol::AUTH_TOKEN_LEN];
        let mut payload = Vec::new();
        payload.push(TUIC_VERSION_5);
        payload.push(TUIC_COMMAND_AUTHENTICATE);
        payload.extend_from_slice(uuid.as_bytes());
        payload.extend_from_slice(&token);
        assert_eq!(payload.len(), AUTHENTICATION_FRAME_LEN);
    }

    #[test]
    fn tuic_connect_header_encode_matches_addr_constants() {
        let header = OwnedProxyHeader {
            network: Network::Tcp,
            address: OwnedProxyAddress::Ipv4(std::net::Ipv4Addr::new(10, 0, 0, 9)),
            port: 443,
        };
        let mut encoded = Vec::new();
        encode_tuic_target(&header, &mut encoded).unwrap();
        assert_eq!(encoded[0], TUIC_ADDR_IPV4);
        assert_eq!(&encoded[1..5], &[10, 0, 0, 9]);
        assert_eq!(u16::from_be_bytes([encoded[5], encoded[6]]), 443);

        let domain_header = OwnedProxyHeader {
            network: Network::Tcp,
            address: OwnedProxyAddress::Domain("example.com".to_owned()),
            port: 8080,
        };
        let mut domain_encoded = Vec::new();
        encode_tuic_target(&domain_header, &mut domain_encoded).unwrap();
        assert_eq!(domain_encoded[0], TUIC_ADDR_DOMAIN);
        assert_eq!(domain_encoded[1] as usize, "example.com".len());
        assert_eq!(&domain_encoded[2..2 + 11], b"example.com");
    }

    #[test]
    fn tuic_udp_packet_roundtrips_ipv4_target() {
        let header = OwnedProxyHeader {
            network: Network::Udp,
            address: OwnedProxyAddress::Ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            port: 53,
        };
        let payload = b"hello udp world";
        let association_id = 0x1234;
        let packet_id = 0xabcd;

        let encoded = encode_tuic_udp_packet(&header, payload, association_id, packet_id).unwrap();
        let decoded = decode_tuic_udp_packet(&encoded, association_id).unwrap();

        assert_eq!(decoded.association_id, association_id);
        assert_eq!(decoded.packet_id, packet_id);
        assert_eq!(decoded.target, SocketAddr::from(([8, 8, 8, 8], 53)));
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn tuic_udp_decode_rejects_heartbeat_and_garbage() {
        let heartbeat = [TUIC_VERSION_5, 0x04, 0x00, 0x00];
        assert!(decode_tuic_udp_packet(&heartbeat, 0).is_err());

        let garbage = [0xff_u8; 32];
        let expected = u16::from_be_bytes([garbage[2], garbage[3]]);
        assert!(decode_tuic_udp_packet(&garbage, expected).is_err());

        let truncated = [TUIC_VERSION_5, TUIC_COMMAND_PACKET];
        assert!(decode_tuic_udp_packet(&truncated, 0).is_err());
    }

    fn udp_header(addr: OwnedProxyAddress, port: u16) -> OwnedProxyHeader {
        OwnedProxyHeader {
            network: Network::Udp,
            address: addr,
            port,
        }
    }

    #[test]
    fn tuic_udp_single_fragment_fast_path() {
        let header = udp_header(
            OwnedProxyAddress::Ipv4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            53,
        );
        let payload = b"small dns query";
        let fragments = encode_tuic_udp_fragments(&header, payload, 7, 9, 1500).unwrap();
        assert_eq!(fragments.len(), 1);
        let mut reassembler = TuicUdpReassembler::default();
        let fragment = decode_tuic_udp_fragment(&fragments[0]).unwrap();
        let (data, target) = reassembler.accept(fragment).unwrap().unwrap();
        assert_eq!(data, payload);
        assert_eq!(target, SocketAddr::from(([1, 1, 1, 1], 53)));
    }

    #[test]
    fn tuic_udp_fragments_split_and_reassemble_in_order() {
        let header = udp_header(
            OwnedProxyAddress::Ipv4(std::net::Ipv4Addr::new(9, 9, 9, 9)),
            443,
        );
        let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let fragments = encode_tuic_udp_fragments(&header, &payload, 0x1111, 0x2222, 128).unwrap();
        assert!(fragments.len() > 1, "payload should split");

        let first = decode_tuic_udp_fragment(&fragments[0]).unwrap();
        assert_eq!(first.fragment_id, 0);
        assert!(first.target.is_some(), "frag 0 carries the address");
        for frag in &fragments[1..] {
            let decoded = decode_tuic_udp_fragment(frag).unwrap();
            assert!(decoded.target.is_none(), "later frags use the none address");
        }

        let mut reassembler = TuicUdpReassembler::default();
        let mut result = None;
        for frag in &fragments {
            let decoded = decode_tuic_udp_fragment(frag).unwrap();
            if let Some(done) = reassembler.accept(decoded).unwrap() {
                result = Some(done);
            }
        }
        let (data, target) = result.expect("reassembly completes");
        assert_eq!(data, payload);
        assert_eq!(target, SocketAddr::from(([9, 9, 9, 9], 443)));
    }

    #[test]
    fn tuic_udp_fragments_reassemble_out_of_order() {
        let header = udp_header(
            OwnedProxyAddress::Ipv4(std::net::Ipv4Addr::new(8, 8, 4, 4)),
            53,
        );
        let payload: Vec<u8> = (0..2500u32).map(|i| (i * 7) as u8).collect();
        let fragments = encode_tuic_udp_fragments(&header, &payload, 5, 6, 200).unwrap();
        assert!(fragments.len() >= 3);

        let mut reassembler = TuicUdpReassembler::default();
        let mut order: Vec<usize> = (0..fragments.len()).collect();
        order.reverse();
        let mut result = None;
        for idx in order {
            let decoded = decode_tuic_udp_fragment(&fragments[idx]).unwrap();
            if let Some(done) = reassembler.accept(decoded).unwrap() {
                result = Some(done);
            }
        }
        let (data, _) = result.expect("out-of-order reassembly completes");
        assert_eq!(data, payload);
    }

    #[test]
    fn tuic_udp_reassembler_rejects_duplicate_fragment() {
        let header = udp_header(
            OwnedProxyAddress::Ipv4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            80,
        );
        let payload: Vec<u8> = vec![0xAB; 1000];
        let fragments = encode_tuic_udp_fragments(&header, &payload, 1, 1, 100).unwrap();
        let mut reassembler = TuicUdpReassembler::default();
        let first = decode_tuic_udp_fragment(&fragments[0]).unwrap();
        assert!(reassembler.accept(first).unwrap().is_none());
        let dup = decode_tuic_udp_fragment(&fragments[0]).unwrap();
        assert!(
            reassembler.accept(dup).is_err(),
            "duplicate must be rejected"
        );
    }

    #[test]
    fn tuic_udp_fragment_decode_enforces_address_discipline() {
        let mut frag0 = encode_tuic_udp_fragment(
            &udp_header(
                OwnedProxyAddress::Ipv4(std::net::Ipv4Addr::new(5, 5, 5, 5)),
                1,
            ),
            b"x",
            1,
            1,
            2,
            0,
            false,
        )
        .unwrap();
        frag0[6] = 2;
        frag0[7] = 0;
        assert!(
            decode_tuic_udp_fragment(&frag0).is_err(),
            "frag 0 without real address must fail"
        );

        let frag1 = encode_tuic_udp_fragment(
            &udp_header(
                OwnedProxyAddress::Ipv4(std::net::Ipv4Addr::new(5, 5, 5, 5)),
                1,
            ),
            b"x",
            1,
            1,
            2,
            1,
            true,
        )
        .unwrap();
        assert!(
            decode_tuic_udp_fragment(&frag1).is_err(),
            "non-first frag with real address must fail"
        );
    }

    #[test]
    fn tuic_udp_fragment_decode_rejects_bad_index() {
        let frag = encode_tuic_udp_fragment(
            &udp_header(
                OwnedProxyAddress::Ipv4(std::net::Ipv4Addr::new(7, 7, 7, 7)),
                9,
            ),
            b"y",
            1,
            1,
            2,
            0,
            true,
        );
        let mut bytes = frag.unwrap();
        bytes[6] = 2;
        bytes[7] = 2;
        assert!(decode_tuic_udp_fragment(&bytes).is_err());
    }

    #[test]
    fn tuic_dissociate_frame_parses() {
        let bytes = [TUIC_VERSION_5, TUIC_COMMAND_DISSOCIATE, 0x12, 0x34];
        assert_eq!(bytes[0], TUIC_VERSION_5);
        assert_eq!(bytes[1], TUIC_COMMAND_DISSOCIATE);
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0x1234);
    }

    #[tokio::test]
    async fn relay_copy_with_stall_timeout_copies_all_bytes_when_data_flows() {
        let (mut writer_end, mut reader) = tokio::io::duplex(64 * 1024);
        let mut sink: Vec<u8> = Vec::new();

        let payload = vec![0x5a_u8; 200 * 1024];
        let expected = payload.clone();
        let feeder = tokio::spawn(async move {
            tokio::io::AsyncWriteExt::write_all(&mut writer_end, &payload)
                .await
                .expect("feed payload");
            drop(writer_end);
        });

        let copied = relay_copy_with_stall_timeout(&mut reader, &mut sink, Duration::from_secs(30))
            .await
            .expect("steady-flow copy must not time out");

        feeder.await.expect("feeder task");
        assert_eq!(copied, expected.len() as u64);
        assert_eq!(sink, expected);
    }

    struct StalledWriter;

    impl AsyncWrite for StalledWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn relay_copy_with_stall_timeout_fires_on_stalled_writer() {
        let mut reader = b"payload".as_slice();
        let mut writer = StalledWriter;

        let started = tokio::time::Instant::now();
        let error =
            relay_copy_with_stall_timeout(&mut reader, &mut writer, Duration::from_millis(150))
                .await
                .expect_err("stalled writer must time out");

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "stall timeout must fire promptly, not hang"
        );
    }

    #[tokio::test]
    async fn relay_copy_with_stall_timeout_keeps_idle_reader_alive() {
        let (mut writer_end, mut reader) = tokio::io::duplex(64 * 1024);
        let mut sink: Vec<u8> = Vec::new();

        let feeder = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            tokio::io::AsyncWriteExt::write_all(&mut writer_end, b"after idle")
                .await
                .expect("write after idle");
            drop(writer_end);
        });

        let copied =
            relay_copy_with_stall_timeout(&mut reader, &mut sink, Duration::from_millis(100))
                .await
                .expect("idle read must not trip the TCP relay stall guard");

        feeder.await.expect("feeder task");
        assert_eq!(copied, b"after idle".len() as u64);
        assert_eq!(sink, b"after idle");
    }

    #[tokio::test]
    async fn relay_copy_with_stall_timeout_resets_on_progress() {
        // Several writes spaced just under the stall window: each resets the
        // timer, so a long but steadily-progressing transfer never times out.
        let (mut writer_end, mut reader) = tokio::io::duplex(64 * 1024);
        let mut sink: Vec<u8> = Vec::new();

        let feeder = tokio::spawn(async move {
            for _ in 0..5 {
                tokio::time::sleep(Duration::from_millis(80)).await;
                tokio::io::AsyncWriteExt::write_all(&mut writer_end, &[0x11_u8; 1024])
                    .await
                    .expect("write chunk");
            }
            drop(writer_end);
        });

        let copied =
            relay_copy_with_stall_timeout(&mut reader, &mut sink, Duration::from_millis(200))
                .await
                .expect("steady progress must not trip the stall timer");

        feeder.await.expect("feeder task");
        assert_eq!(copied, 5 * 1024);
    }
}
