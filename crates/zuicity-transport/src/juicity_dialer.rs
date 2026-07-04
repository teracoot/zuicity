use crate::{
    TransportError, decode_juicity_pinned_cert_chain_sha256, dialer_link_query_value,
    http_connect_allow_insecure, percent_decode_utf8,
};

/// Parsed Juicity outbound proxy endpoint for TCP-over-QUIC target dials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityDialerLink {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) uuid: uuid::Uuid,
    pub(crate) password: String,
    pub(crate) sni: String,
    pub(crate) allow_insecure: bool,
    pub(crate) congestion_control: String,
    pub(crate) pinned_cert_chain_sha256: Option<Vec<u8>>,
}

impl JuicityDialerLink {
    pub(crate) fn from_url(raw: &str, parsed: &url::Url) -> Result<Self, TransportError> {
        let host = parsed
            .host_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing Juicity host".to_owned(),
            })?
            .to_owned();
        let port = parsed
            .port()
            .ok_or_else(|| TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: "missing Juicity port".to_owned(),
            })?;
        let raw_uuid = percent_decode_utf8(raw, parsed.username(), "Juicity UUID")?;
        let uuid = uuid::Uuid::parse_str(&raw_uuid).map_err(|source| {
            TransportError::InvalidProxyDialerLink {
                link: raw.to_owned(),
                message: format!("parse Juicity UUID: {source}"),
            }
        })?;
        let password = match parsed.password() {
            Some(password) => percent_decode_utf8(raw, password, "Juicity password")?,
            None => String::new(),
        };
        let sni = dialer_link_query_value(parsed, "peer")
            .or_else(|| dialer_link_query_value(parsed, "sni"))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| host.clone());
        let pinned_cert_chain_sha256 = dialer_link_query_value(parsed, "pinned_certchain_sha256")
            .filter(|value| !value.is_empty())
            .map(|value| decode_juicity_pinned_cert_chain_sha256(raw, &value))
            .transpose()?;
        Ok(Self {
            host,
            port,
            uuid,
            password,
            sni,
            allow_insecure: http_connect_allow_insecure(parsed),
            congestion_control: dialer_link_query_value(parsed, "congestion_control")
                .unwrap_or_default(),
            pinned_cert_chain_sha256,
        })
    }
}
