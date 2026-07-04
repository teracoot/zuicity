use crate::{TransportError, dialer_link_query_value, percent_decode_utf8, vless_user_to_key};

/// Parsed VLESS outbound proxy endpoint for plain TCP target dials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessDialerLink {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) user: String,
    pub(crate) key: [u8; 16],
}

impl VlessDialerLink {
    pub(crate) fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
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
