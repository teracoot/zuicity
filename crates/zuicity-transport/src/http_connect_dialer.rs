use crate::{TransportError, dialer_link_query_bool};

/// Parsed HTTP CONNECT outbound proxy endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpConnectDialerLink {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) tls: bool,
    pub(crate) sni: Option<String>,
    pub(crate) allow_insecure: bool,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
}

impl HttpConnectDialerLink {
    pub(crate) fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
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

    pub(crate) const fn scheme(&self) -> &'static str {
        if self.tls { "https" } else { "http" }
    }
}

pub(super) fn http_connect_allow_insecure(parsed: &url::Url) -> bool {
    parsed.query_pairs().any(|(key, value)| {
        matches!(
            key.as_ref(),
            "allowInsecure" | "allow_insecure" | "allowinsecure" | "skipVerify"
        ) && dialer_link_query_bool(&value)
    })
}
