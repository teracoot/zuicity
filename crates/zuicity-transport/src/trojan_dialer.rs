use crate::{TransportError, http_connect_allow_insecure, percent_decode_utf8};

/// Parsed Trojan outbound proxy endpoint for TCP-over-TLS target dials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanDialerLink {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) password: String,
    pub(crate) sni: String,
    pub(crate) allow_insecure: bool,
}

impl TrojanDialerLink {
    pub(crate) fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
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
