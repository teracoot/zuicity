use crate::{
    HttpConnectDialerLink, Hysteria2DialerLink, JuicityDialerLink, ShadowsocksDialerLink,
    ShadowsocksRDialerLink, Socks5DialerLink, TransportError, TrojanDialerLink, TuicDialerLink,
    VlessDialerLink, VmessDialerLink,
};

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

    pub(crate) fn endpoint(&self) -> Option<(&str, u16)> {
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

    pub(crate) fn scheme_for_error(&self) -> &'static str {
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
