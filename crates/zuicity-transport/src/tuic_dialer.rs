use crate::{
    TransportError, dialer_link_query_bool, dialer_link_query_value, http_connect_allow_insecure,
    percent_decode_utf8,
};

/// Parsed TUIC outbound proxy endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuicDialerLink {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) user: String,
    pub(crate) password: String,
    pub(crate) sni: Option<String>,
    pub(crate) allow_insecure: bool,
    pub(crate) disable_sni: bool,
    pub(crate) congestion_control: Option<String>,
    pub(crate) alpn: Vec<String>,
    pub(crate) udp_relay_mode: Option<String>,
}

impl TuicDialerLink {
    pub(crate) fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
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
