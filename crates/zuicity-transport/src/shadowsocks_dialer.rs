use base64::{Engine, engine::general_purpose};

use crate::{
    TransportError, decode_padded_base64_bytes, decode_padded_base64_string,
    dialer_link_host_authority,
};

/// Parsed Shadowsocks outbound proxy endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowsocksDialerLink {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) normalized_link: String,
}

impl ShadowsocksDialerLink {
    pub(crate) fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
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

    pub(crate) fn server_config(
        &self,
    ) -> Result<shadowsocks::config::ServerConfig, TransportError> {
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
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) shadowsocks: ShadowsocksDialerLink,
}

impl ShadowsocksRDialerLink {
    pub(crate) fn from_url(raw: &str) -> Result<Self, TransportError> {
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedShadowsocksRLink {
    host: String,
    port: u16,
    proto: String,
    cipher: String,
    obfs: String,
    password: String,
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
