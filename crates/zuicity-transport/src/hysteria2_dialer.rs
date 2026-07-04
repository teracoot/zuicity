use crate::{
    TransportError, dialer_link_query_bool_strict, dialer_link_query_u64, dialer_link_query_value,
    percent_decode_utf8,
};

/// Parsed Hysteria2 outbound proxy endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hysteria2DialerLink {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) user: String,
    pub(crate) password: String,
    pub(crate) insecure: bool,
    pub(crate) sni: Option<String>,
    pub(crate) pin_sha256: Option<String>,
    pub(crate) max_tx: Option<u64>,
    pub(crate) max_rx: Option<u64>,
}

impl Hysteria2DialerLink {
    pub(crate) fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
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
