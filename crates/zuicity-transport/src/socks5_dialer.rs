use crate::TransportError;

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
