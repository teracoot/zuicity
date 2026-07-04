use base64::engine::general_purpose;

use crate::{TransportError, decode_padded_base64_bytes, vless_user_to_key, vmess_cmd_key};

/// Parsed VMess outbound proxy endpoint for AEAD plain TCP target dials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmessDialerLink {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) id: String,
    pub(crate) key: [u8; 16],
    pub(crate) cmd_key: [u8; 16],
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
    pub(crate) fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
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
