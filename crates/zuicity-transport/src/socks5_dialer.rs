use crate::{TransportError, percent_decode_utf8};

/// Parsed SOCKS5 outbound proxy endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5DialerLink {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
}

impl Socks5DialerLink {
    pub(crate) fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
        let host = match parsed.host() {
            Some(url::Host::Domain(host)) => host.to_owned(),
            Some(url::Host::Ipv4(host)) => host.to_string(),
            Some(url::Host::Ipv6(host)) => host.to_string(),
            None => {
                return Err(TransportError::InvalidProxyDialerLink {
                    link: raw.to_owned(),
                    message: "missing SOCKS5 host".to_owned(),
                });
            }
        };
        let port = parsed
            .port()
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing SOCKS5 port".to_owned(),
            })?;
        let username = if parsed.username().is_empty() {
            None
        } else {
            Some(percent_decode_utf8(
                raw,
                parsed.username(),
                "SOCKS5 username",
            )?)
        };
        let password = parsed
            .password()
            .map(|password| percent_decode_utf8(raw, password, "SOCKS5 password"))
            .transpose()?;
        if username.is_some() != password.is_some()
            || username.as_ref().is_some_and(String::is_empty)
            || password.as_ref().is_some_and(String::is_empty)
        {
            return Err(TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "SOCKS5 username and password must either both be set or both be absent"
                    .to_owned(),
            });
        }
        Ok(Self {
            host,
            port,
            username,
            password,
        })
    }
}
