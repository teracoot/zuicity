//! JSON configuration model for Zuicity client and server runtimes.

use std::{
    borrow::Cow,
    collections::BTreeMap,
    fs,
    net::{AddrParseError, IpAddr},
    path::Path,
};

use base64::{Engine, engine::general_purpose};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Congestion-control values documented by upstream Juicity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CongestionControl {
    /// BBR congestion control.
    Bbr,
    /// CUBIC congestion control.
    Cubic,
    /// NewReno congestion control.
    NewReno,
}

impl CongestionControl {
    /// Parses an upstream congestion-control string.
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        match value {
            "bbr" => Ok(Self::Bbr),
            "cubic" => Ok(Self::Cubic),
            "new_reno" => Ok(Self::NewReno),
            other => Err(ConfigError::InvalidCongestionControl(other.to_owned())),
        }
    }

    /// Returns the upstream config spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bbr => "bbr",
            Self::Cubic => "cubic",
            Self::NewReno => "new_reno",
        }
    }
}

/// Optional structured server outbound (egress) configuration.
///
/// This is a zuicity extension for operator-friendly SOCKS5 upstream VPN
/// selection. When present, it is normalized into the existing high-performance
/// `dialer_link` path so the relay hot path is unchanged.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RawOutboundConfig {
    /// Outbound type. Currently only `socks5` is accepted.
    #[serde(default, rename = "type")]
    pub outbound_type: String,
    /// Upstream SOCKS5 host or IP.
    #[serde(default)]
    pub server: String,
    /// Upstream SOCKS5 port.
    #[serde(default)]
    pub server_port: Option<u16>,
    /// Optional SOCKS5 username.
    #[serde(default)]
    pub username: String,
    /// Optional SOCKS5 password.
    #[serde(default)]
    pub password: String,
    /// SOCKS version string. Empty or `5` are accepted.
    #[serde(default)]
    pub version: String,
}

/// Raw upstream JSON config shape. Upstream uses one struct for client and server fields.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RawConfig {
    /// Client mixed proxy listen address or server listen address depending on mode.
    #[serde(default)]
    pub listen: String,
    /// Remote Juicity server address for client mode.
    #[serde(default)]
    pub server: String,
    /// Client user UUID.
    #[serde(default, rename = "uuid")]
    pub uuid: String,
    /// Client password.
    #[serde(default)]
    pub password: String,
    /// Client TLS SNI.
    #[serde(default)]
    pub sni: String,
    /// Whether the client skips default certificate verification.
    #[serde(default)]
    pub allow_insecure: bool,
    /// Optional certificate-chain pin hash.
    #[serde(default)]
    pub pinned_certchain_sha256: String,
    /// Local forward map.
    #[serde(default)]
    pub forward: BTreeMap<String, String>,
    /// Server UUID/password map.
    #[serde(default)]
    pub users: BTreeMap<String, String>,
    /// Server certificate chain file.
    #[serde(default)]
    pub certificate: String,
    /// Server private key file.
    #[serde(default)]
    pub private_key: String,
    /// Server outbound mark string parsed base-0 by upstream.
    #[serde(default)]
    pub fwmark: String,
    /// Server egress source address.
    #[serde(default)]
    pub send_through: String,
    /// Server egress dialer link.
    #[serde(default)]
    pub dialer_link: String,
    /// Optional structured server outbound config (zuicity extension).
    #[serde(default)]
    pub outbound: Option<RawOutboundConfig>,
    /// Client protect path.
    #[serde(default)]
    pub protect_path: String,
    /// Whether server blocks outbound UDP/443.
    #[serde(default)]
    pub disable_outbound_udp443: bool,
    /// Congestion control name.
    #[serde(default)]
    pub congestion_control: String,
    /// Upstream log level string.
    #[serde(default)]
    pub log_level: String,
}

/// Validated client configuration subset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    /// Raw config with upstream-compatible fields.
    pub raw: RawConfig,
    /// Parsed client UUID.
    pub uuid: Uuid,
    /// Parsed congestion control, if configured.
    pub congestion_control: Option<CongestionControl>,
    /// Decoded pinned certificate hash, if configured.
    pub pinned_certchain_sha256: Option<Vec<u8>>,
}

/// Parsed client forward rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForwardRule<'a> {
    /// Local listen address after removing upstream protocol suffixes.
    pub local_addr: &'a str,
    /// Remote destination address.
    pub remote_addr: &'a str,
    /// Whether this rule forwards TCP.
    pub relay_tcp: bool,
    /// Whether this rule forwards UDP.
    pub relay_udp: bool,
}

/// Validated server configuration subset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    /// Raw config with upstream-compatible fields.
    pub raw: RawConfig,
    /// Parsed users.
    pub users: BTreeMap<Uuid, String>,
    /// Parsed congestion control, if configured.
    pub congestion_control: Option<CongestionControl>,
    /// Parsed fwmark, if configured.
    pub fwmark: Option<u32>,
    /// Parsed egress source IP, if configured.
    pub send_through: Option<IpAddr>,
    /// Effective server egress dialer link after outbound normalization.
    pub dialer_link: Option<String>,
}

impl ClientConfig {
    /// Returns parsed forward rules in deterministic map order.
    pub fn forward_rules(&self) -> impl Iterator<Item = ForwardRule<'_>> {
        self.raw
            .forward
            .iter()
            .map(|(local, remote)| parse_forward_rule(local, remote))
    }

    /// Returns the TLS server name used by upstream client mode.
    ///
    /// Upstream mutates `sni` with `net.SplitHostPort(server)` when `sni` is
    /// empty before building the TLS config. This helper preserves explicit
    /// SNI without allocation and otherwise borrows the host part of `server`
    /// when it has a valid host:port shape.
    #[must_use]
    pub fn tls_server_name(&self) -> Cow<'_, str> {
        if !self.raw.sni.is_empty() {
            return Cow::Borrowed(&self.raw.sni);
        }
        split_host_port_host(&self.raw.server)
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Borrowed(""))
    }
}
/// Distinguishes Go `strconv.ParseUint` syntax vs range failures for fwmark.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FwmarkParseErrorKind {
    /// Input contained an invalid digit for the detected base.
    Syntax,
    /// Input was a valid number but exceeded the u32 range.
    Range,
}

impl std::fmt::Display for FwmarkParseErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Syntax => f.write_str("invalid syntax"),
            Self::Range => f.write_str("value out of range"),
        }
    }
}

/// Config parsing and validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// File read failed.
    #[error("read config: {0}")]
    Read(#[from] std::io::Error),
    /// JSON decode failed.
    #[error("decode config json: {0}")]
    Json(#[from] serde_json::Error),
    /// Client UUID failed to parse.
    #[error("parse uuid: {0}")]
    Uuid(#[from] uuid::Error),
    /// Client must configure at least listen or forward.
    #[error("either listen or forward is required")]
    MissingClientEntryPoint,
    /// Server listen address is required.
    #[error("listen is required")]
    MissingServerListen,
    /// Invalid server user UUID.
    #[error("parse user uuid {uuid}: {source}")]
    InvalidUserUuid {
        /// UUID string that failed to parse.
        uuid: String,
        /// Underlying UUID parse error.
        source: uuid::Error,
    },
    /// Invalid pinned certificate-chain hash.
    #[error("failed to decode pinned_certchain_sha256")]
    InvalidPinnedCertChainSha256,
    /// Invalid congestion control value.
    #[error("invalid congestion_control {0}")]
    InvalidCongestionControl(String),
    /// Invalid fwmark value.
    #[error("parse fwmark: strconv.ParseUint: parsing \"{value}\": {kind}")]
    InvalidFwmark {
        /// Original fwmark string.
        value: String,
        /// Whether the failure was a syntax or range error.
        kind: FwmarkParseErrorKind,
    },
    /// Invalid server egress source address.
    #[error("parse send_through: {source}")]
    InvalidSendThrough {
        /// Address string that failed to parse.
        value: String,
        /// Underlying IP parse error.
        source: AddrParseError,
    },
    /// Structured outbound config is invalid.
    #[error("invalid outbound: {0}")]
    InvalidOutbound(String),
    /// Both `outbound` and `dialer_link` were set to different values.
    #[error("outbound and dialer_link conflict: choose one egress setting")]
    ConflictingOutboundAndDialerLink,
}

/// Loads raw JSON config from a file.
pub fn load_json_file(path: impl AsRef<Path>) -> Result<RawConfig, ConfigError> {
    let data = fs::read_to_string(path)?;
    load_json_str(&data)
}

/// Loads raw JSON config from a string.
///
/// Upstream decodes config with Go's `encoding/json` into a struct, which only
/// accepts a top-level JSON object (or `null`); arrays, strings, numbers, and
/// booleans are rejected. Rust's `serde` would otherwise accept a struct encoded
/// as a sequence (e.g. `[]`), so this enforces the same object-or-null contract
/// to avoid being more lenient than upstream.
pub fn load_json_str(input: &str) -> Result<RawConfig, ConfigError> {
    let value: serde_json::Value = serde_json::from_str(input)?;
    match value {
        serde_json::Value::Object(_) => Ok(serde_json::from_value(value)?),
        serde_json::Value::Null => Ok(RawConfig::default()),
        other => Err(ConfigError::Json(non_object_config_error(&other))),
    }
}

fn non_object_config_error(value: &serde_json::Value) -> serde_json::Error {
    let kind = match value {
        serde_json::Value::Array(_) => "array",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Object(_) | serde_json::Value::Null => "object",
    };
    serde::de::Error::custom(format!("config must be a JSON object, found {kind}"))
}

/// Validates raw config for client mode.
pub fn validate_client(raw: RawConfig) -> Result<ClientConfig, ConfigError> {
    let uuid = Uuid::parse_str(&raw.uuid)?;
    let congestion_control = optional_known_congestion_control(&raw.congestion_control);
    let pinned_certchain_sha256 = optional_pin_hash(&raw.pinned_certchain_sha256)?;
    Ok(ClientConfig {
        raw,
        uuid,
        congestion_control,
        pinned_certchain_sha256,
    })
}

/// Applies optional environment overrides for server SOCKS5 outbound.
///
/// Supported variables:
/// - `ZUICITY_OUTBOUND_TYPE`
/// - `ZUICITY_OUTBOUND_SERVER`
/// - `ZUICITY_OUTBOUND_PORT`
/// - `ZUICITY_OUTBOUND_USERNAME`
/// - `ZUICITY_OUTBOUND_PASSWORD`
///
/// Existing explicit JSON `outbound` fields win over env values. Non-empty env
/// values only fill missing structured outbound fields; empty values are treated
/// as unset and do not enable outbound mode.
pub fn apply_server_outbound_env_overrides(raw: &mut RawConfig) -> Result<(), ConfigError> {
    apply_server_outbound_env_values(
        raw,
        ServerOutboundEnvValues {
            outbound_type: std::env::var("ZUICITY_OUTBOUND_TYPE").ok(),
            server: std::env::var("ZUICITY_OUTBOUND_SERVER").ok(),
            port: std::env::var("ZUICITY_OUTBOUND_PORT").ok(),
            username: std::env::var("ZUICITY_OUTBOUND_USERNAME").ok(),
            password: std::env::var("ZUICITY_OUTBOUND_PASSWORD").ok(),
        },
    )
}

#[derive(Default)]
struct ServerOutboundEnvValues {
    outbound_type: Option<String>,
    server: Option<String>,
    port: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

fn apply_server_outbound_env_values(
    raw: &mut RawConfig,
    values: ServerOutboundEnvValues,
) -> Result<(), ConfigError> {
    let ServerOutboundEnvValues {
        outbound_type: env_type,
        server: env_server,
        port: env_port,
        username: env_username,
        password: env_password,
    } = values;
    let env_type = non_empty_env_value(env_type);
    let env_server = non_empty_env_value(env_server);
    let env_port = non_empty_env_value(env_port);
    let env_username = non_empty_env_value(env_username);
    let env_password = non_empty_env_value(env_password);
    if env_type.is_none()
        && env_server.is_none()
        && env_port.is_none()
        && env_username.is_none()
        && env_password.is_none()
    {
        return Ok(());
    }

    let outbound = raw.outbound.get_or_insert_with(RawOutboundConfig::default);
    if outbound.outbound_type.is_empty()
        && let Some(value) = env_type
    {
        outbound.outbound_type = value;
    }
    if outbound.server.is_empty()
        && let Some(value) = env_server
    {
        outbound.server = value;
    }
    if outbound.server_port.is_none()
        && let Some(value) = env_port
    {
        let port = value.parse::<u16>().map_err(|_| {
            ConfigError::InvalidOutbound(
                "ZUICITY_OUTBOUND_PORT must be an integer from 1 through 65535".to_owned(),
            )
        })?;
        if port == 0 {
            return Err(ConfigError::InvalidOutbound(
                "ZUICITY_OUTBOUND_PORT must be an integer from 1 through 65535".to_owned(),
            ));
        }
        outbound.server_port = Some(port);
    }
    if outbound.username.is_empty()
        && let Some(value) = env_username
    {
        outbound.username = value;
    }
    if outbound.password.is_empty()
        && let Some(value) = env_password
    {
        outbound.password = value;
    }
    Ok(())
}

fn non_empty_env_value(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

/// Builds a SOCKS5 `dialer_link` from structured outbound config.
pub fn socks5_dialer_link_from_outbound(
    outbound: &RawOutboundConfig,
) -> Result<String, ConfigError> {
    let outbound_type = if outbound.outbound_type.is_empty() {
        "socks5"
    } else {
        outbound.outbound_type.as_str()
    };
    if !outbound_type.eq_ignore_ascii_case("socks5") && outbound_type != "5" {
        return Err(ConfigError::InvalidOutbound(format!(
            "unsupported type `{outbound_type}`; only socks5 is supported"
        )));
    }
    if !outbound.version.is_empty() && outbound.version != "5" {
        return Err(ConfigError::InvalidOutbound(format!(
            "unsupported version `{}`; only 5 is supported",
            outbound.version
        )));
    }
    if outbound.server.trim().is_empty() {
        return Err(ConfigError::InvalidOutbound(
            "server is required".to_owned(),
        ));
    }
    let port = outbound
        .server_port
        .ok_or_else(|| ConfigError::InvalidOutbound("server_port is required".to_owned()))?;
    if port == 0 {
        return Err(ConfigError::InvalidOutbound(
            "server_port must be non-zero".to_owned(),
        ));
    }

    let host = outbound.server.trim();
    let authority = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let endpoint = url::Url::parse(&format!("socks5://{authority}:{port}")).map_err(|_| {
        ConfigError::InvalidOutbound("server must be a valid hostname or IP address".to_owned())
    })?;
    if endpoint.host_str().is_none()
        || endpoint.port() != Some(port)
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(ConfigError::InvalidOutbound(
            "server must be a valid hostname or IP address".to_owned(),
        ));
    }

    if outbound.username.len() > u8::MAX as usize || outbound.password.len() > u8::MAX as usize {
        return Err(ConfigError::InvalidOutbound(
            "SOCKS5 username and password must each be at most 255 bytes".to_owned(),
        ));
    }

    let userinfo = match (outbound.username.is_empty(), outbound.password.is_empty()) {
        (true, true) => String::new(),
        (false, false) => format!(
            "{}:{}@",
            percent_encode_userinfo(&outbound.username),
            percent_encode_userinfo(&outbound.password)
        ),
        _ => {
            return Err(ConfigError::InvalidOutbound(
                "SOCKS5 username and password must either both be set or both be empty".to_owned(),
            ));
        }
    };

    Ok(format!("socks5://{userinfo}{authority}:{port}"))
}

fn percent_encode_userinfo(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn resolve_server_dialer_link(raw: &RawConfig) -> Result<Option<String>, ConfigError> {
    let from_outbound = raw
        .outbound
        .as_ref()
        .map(socks5_dialer_link_from_outbound)
        .transpose()?;
    let from_dialer_link = (!raw.dialer_link.is_empty()).then(|| raw.dialer_link.clone());
    match (from_outbound, from_dialer_link) {
        (None, None) => Ok(None),
        (Some(link), None) | (None, Some(link)) => Ok(Some(link)),
        (Some(outbound_link), Some(dialer_link)) => {
            if outbound_link == dialer_link {
                Ok(Some(outbound_link))
            } else {
                Err(ConfigError::ConflictingOutboundAndDialerLink)
            }
        }
    }
}

/// Validates raw config for server mode.
pub fn validate_server(raw: RawConfig) -> Result<ServerConfig, ConfigError> {
    let mut users = BTreeMap::new();
    for (uuid, password) in &raw.users {
        let parsed = Uuid::parse_str(uuid).map_err(|source| ConfigError::InvalidUserUuid {
            uuid: uuid.clone(),
            source,
        })?;
        users.insert(parsed, password.clone());
    }
    let congestion_control = optional_known_congestion_control(&raw.congestion_control);
    let fwmark = if raw.fwmark.is_empty() {
        None
    } else {
        Some(
            parse_u32_base0(&raw.fwmark).map_err(|kind| ConfigError::InvalidFwmark {
                value: raw.fwmark.clone(),
                kind,
            })?,
        )
    };
    let send_through = if raw.send_through.is_empty() {
        None
    } else {
        Some(raw.send_through.parse::<IpAddr>().map_err(|source| {
            ConfigError::InvalidSendThrough {
                value: raw.send_through.clone(),
                source,
            }
        })?)
    };
    let dialer_link = resolve_server_dialer_link(&raw)?;
    let mut raw = raw;
    if let Some(link) = dialer_link.as_ref() {
        // Keep raw.dialer_link filled so existing consumers and logs see the
        // effective high-performance dial path after outbound normalization.
        raw.dialer_link = link.clone();
    }
    Ok(ServerConfig {
        raw,
        users,
        congestion_control,
        fwmark,
        send_through,
        dialer_link,
    })
}

/// Parses a client forward local-address key using upstream `/tcp` and `/udp` suffix rules.
#[must_use]
pub fn parse_forward_rule<'a>(local_addr: &'a str, remote_addr: &'a str) -> ForwardRule<'a> {
    let mut parts = local_addr.split('/');
    let parsed_local_addr = parts.next().unwrap_or("");
    let suffixes: Vec<_> = parts.collect();
    let (relay_tcp, relay_udp) = if suffixes.is_empty() {
        (true, true)
    } else {
        let mut relay_tcp = false;
        let mut relay_udp = false;
        for suffix in suffixes {
            match suffix {
                "tcp" => relay_tcp = true,
                "udp" => relay_udp = true,
                _ => {}
            }
        }
        (relay_tcp, relay_udp)
    };

    ForwardRule {
        local_addr: parsed_local_addr,
        remote_addr,
        relay_tcp,
        relay_udp,
    }
}

fn split_host_port_host(value: &str) -> Option<&str> {
    let (host, port) = value.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() {
        return None;
    }
    if host.starts_with('[') && host.ends_with(']') {
        return Some(&host[1..host.len() - 1]);
    }
    if host.contains(':') {
        return None;
    }
    Some(host)
}

fn optional_known_congestion_control(value: &str) -> Option<CongestionControl> {
    if value.is_empty() {
        None
    } else {
        CongestionControl::parse(value).ok()
    }
}

fn optional_pin_hash(value: &str) -> Result<Option<Vec<u8>>, ConfigError> {
    if value.is_empty() {
        return Ok(None);
    }
    let decoded = general_purpose::URL_SAFE
        .decode(value)
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(value))
        .or_else(|_| general_purpose::STANDARD.decode(value))
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(value))
        .or_else(|_| hex::decode(value))
        .map_err(|_| ConfigError::InvalidPinnedCertChainSha256)?;
    Ok(Some(decoded))
}

fn parse_u32_base0(value: &str) -> Result<u32, FwmarkParseErrorKind> {
    let (digits, radix) = go_parse_uint_base0_digits(value).ok_or(FwmarkParseErrorKind::Syntax)?;
    parse_u32_digits_with_go_underscores(digits, radix)
}

fn go_parse_uint_base0_digits(value: &str) -> Option<(&str, u32)> {
    if value.is_empty() {
        return None;
    }
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some((hex, 16))
    } else if let Some(binary) = value
        .strip_prefix("0b")
        .or_else(|| value.strip_prefix("0B"))
    {
        Some((binary, 2))
    } else if let Some(octal) = value
        .strip_prefix("0o")
        .or_else(|| value.strip_prefix("0O"))
    {
        Some((octal, 8))
    } else if value.len() > 1 && value.starts_with('0') {
        Some((&value[1..], 8))
    } else {
        Some((value, 10))
    }
}

fn parse_u32_digits_with_go_underscores(
    digits: &str,
    radix: u32,
) -> Result<u32, FwmarkParseErrorKind> {
    let mut value = 0_u64;
    let mut seen_digit = false;
    let mut previous_was_digit = false;
    let mut overflowed = false;
    for byte in digits.bytes() {
        if byte == b'_' {
            if !previous_was_digit {
                return Err(FwmarkParseErrorKind::Syntax);
            }
            previous_was_digit = false;
            continue;
        }
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'z' => u32::from(byte - b'a') + 10,
            b'A'..=b'Z' => u32::from(byte - b'A') + 10,
            _ => return Err(FwmarkParseErrorKind::Syntax),
        };
        if digit >= radix {
            return Err(FwmarkParseErrorKind::Syntax);
        }
        // Go's strconv keeps scanning valid digits to confirm syntax before
        // reporting a range error, so track overflow without aborting early.
        if !overflowed {
            match value
                .checked_mul(u64::from(radix))
                .and_then(|v| v.checked_add(u64::from(digit)))
            {
                Some(next) if next <= u64::from(u32::MAX) => value = next,
                _ => overflowed = true,
            }
        }
        seen_digit = true;
        previous_was_digit = true;
    }
    if !seen_digit || !previous_was_digit {
        return Err(FwmarkParseErrorKind::Syntax);
    }
    if overflowed {
        return Err(FwmarkParseErrorKind::Range);
    }
    Ok(value as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn congestion_control_names_round_trip() {
        for (name, expected) in [
            ("bbr", CongestionControl::Bbr),
            ("cubic", CongestionControl::Cubic),
            ("new_reno", CongestionControl::NewReno),
        ] {
            assert_eq!(CongestionControl::parse(name).unwrap(), expected);
            assert_eq!(expected.as_str(), name);
        }
        assert!(CongestionControl::parse("unknown").is_err());
    }

    #[test]
    fn parses_upstream_client_example_shape() -> Result<(), ConfigError> {
        let raw = load_json_str(
            r#"{
              "listen": ":1080",
              "server": "127.0.0.1:23182",
              "uuid": "00000000-0000-0000-0000-000000000000",
              "password": "my_password",
              "sni": "www.example.com",
              "allow_insecure": false,
              "congestion_control": "bbr",
              "log_level": "info"
            }"#,
        )?;
        let config = validate_client(raw)?;
        assert_eq!(config.uuid, Uuid::nil());
        assert_eq!(config.congestion_control, Some(CongestionControl::Bbr));
        Ok(())
    }

    #[test]
    fn config_rejects_non_object_top_level_json_like_upstream() {
        assert!(load_json_str("[]").is_err());
        assert!(load_json_str("[1,2,3]").is_err());
        assert!(load_json_str("\"a string\"").is_err());
        assert!(load_json_str("123").is_err());
        assert!(load_json_str("true").is_err());
        assert!(load_json_str("{ not valid json").is_err());
        assert!(load_json_str("{}").is_ok());
        assert!(load_json_str("null").is_ok());
    }

    #[test]
    fn config_duplicate_key_uses_last_value_a_known_library_level_divergence() {
        let raw = load_json_str(r#"{"sni":"first","sni":"second"}"#).expect("decode");
        assert_eq!(raw.sni, "second");
    }

    #[test]
    fn client_unknown_congestion_control_is_preserved_raw_and_not_rejected_like_upstream()
    -> Result<(), ConfigError> {
        let raw = load_json_str(
            r#"{
              "listen": "127.0.0.1:0",
              "server": "127.0.0.1:1",
              "uuid": "00000000-0000-0000-0000-000000000001",
              "password": "password",
              "congestion_control": "bogus"
            }"#,
        )?;
        let config = validate_client(raw)?;
        assert_eq!(config.raw.congestion_control, "bogus");
        assert_eq!(config.congestion_control, None);
        Ok(())
    }

    #[test]
    fn client_missing_entrypoint_is_preserved_for_runtime_error_order_like_upstream()
    -> Result<(), ConfigError> {
        let raw = load_json_str(
            r#"{
              "server": "127.0.0.1:1",
              "uuid": "00000000-0000-0000-0000-000000000001",
              "password": "password"
            }"#,
        )?;
        let config = validate_client(raw)?;
        assert!(config.raw.listen.is_empty());
        assert!(config.raw.forward.is_empty());
        Ok(())
    }

    #[test]
    fn server_missing_listen_is_preserved_for_runtime_error_order_like_upstream()
    -> Result<(), ConfigError> {
        let raw = load_json_str(
            r#"{
              "users": {"00000000-0000-0000-0000-000000000001": "password"},
              "certificate": "/tmp/unused-fullchain.pem",
              "private_key": "/tmp/unused-private.key"
            }"#,
        )?;
        let config = validate_server(raw)?;
        assert!(config.raw.listen.is_empty());
        Ok(())
    }

    #[test]
    fn server_unknown_congestion_control_is_preserved_raw_and_not_rejected_like_upstream()
    -> Result<(), ConfigError> {
        let raw = load_json_str(
            r#"{
              "listen": "127.0.0.1:0",
              "users": {"00000000-0000-0000-0000-000000000001": "password"},
              "certificate": "/tmp/unused-fullchain.pem",
              "private_key": "/tmp/unused-private.key",
              "congestion_control": "bogus"
            }"#,
        )?;
        let config = validate_server(raw)?;
        assert_eq!(config.raw.congestion_control, "bogus");
        assert_eq!(config.congestion_control, None);
        Ok(())
    }

    #[test]
    fn client_pinned_hash_accepts_valid_short_base64_like_upstream() -> Result<(), ConfigError> {
        let raw = load_json_str(
            r#"{
              "listen": ":1080",
              "server": "example.com:23182",
              "uuid": "00000000-0000-0000-0000-000000000000",
              "password": "my_password",
              "pinned_certchain_sha256": "AQID"
            }"#,
        )?;
        let config = validate_client(raw)?;
        assert_eq!(
            config.pinned_certchain_sha256.as_deref(),
            Some(&[1, 2, 3][..])
        );
        Ok(())
    }

    #[test]
    fn client_pinned_hash_accepts_upstream_decode_formats() -> Result<(), ConfigError> {
        for (literal, expected) in [
            ("AQIDBA==", vec![1, 2, 3, 4]),
            ("AQIDBA", vec![1, 2, 3, 4]),
            ("010203", vec![1, 2, 3]),
        ] {
            let raw = load_json_str(&format!(
                r#"{{
                  "listen": ":1080",
                  "server": "example.com:23182",
                  "uuid": "00000000-0000-0000-0000-000000000000",
                  "password": "my_password",
                  "pinned_certchain_sha256": "{literal}"
                }}"#
            ))?;
            let config = validate_client(raw)?;
            assert_eq!(config.pinned_certchain_sha256, Some(expected), "{literal}");
        }
        Ok(())
    }

    #[test]
    fn client_pinned_hash_rejects_invalid_encoding_like_upstream() -> Result<(), ConfigError> {
        let raw = load_json_str(
            r#"{
              "listen": ":1080",
              "server": "example.com:23182",
              "uuid": "00000000-0000-0000-0000-000000000000",
              "password": "my_password",
              "pinned_certchain_sha256": "not@@valid@@"
            }"#,
        )?;
        let err = validate_client(raw).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPinnedCertChainSha256));
        Ok(())
    }

    #[test]
    fn client_tls_server_name_falls_back_to_server_host_like_upstream() -> Result<(), ConfigError> {
        let raw = load_json_str(
            r#"{
              "listen": ":1080",
              "server": "example.com:23182",
              "uuid": "00000000-0000-0000-0000-000000000000",
              "password": "my_password",
              "allow_insecure": false
            }"#,
        )?;
        let config = validate_client(raw)?;
        assert_eq!(config.tls_server_name().as_ref(), "example.com");
        Ok(())
    }

    #[test]
    fn client_forward_rule_parses_upstream_protocol_suffixes() {
        assert_eq!(
            parse_forward_rule("127.0.0.1:12322", "127.0.0.1:22"),
            ForwardRule {
                local_addr: "127.0.0.1:12322",
                remote_addr: "127.0.0.1:22",
                relay_tcp: true,
                relay_udp: true,
            }
        );
        assert_eq!(
            parse_forward_rule("0.0.0.0:5201/tcp", "127.0.0.1:5201"),
            ForwardRule {
                local_addr: "0.0.0.0:5201",
                remote_addr: "127.0.0.1:5201",
                relay_tcp: true,
                relay_udp: false,
            }
        );
        assert_eq!(
            parse_forward_rule("0.0.0.0:5353/udp", "8.8.8.8:53"),
            ForwardRule {
                local_addr: "0.0.0.0:5353",
                remote_addr: "8.8.8.8:53",
                relay_tcp: false,
                relay_udp: true,
            }
        );
        assert_eq!(
            parse_forward_rule("127.0.0.1:9000/tcp/udp", "example.com:9000"),
            ForwardRule {
                local_addr: "127.0.0.1:9000",
                remote_addr: "example.com:9000",
                relay_tcp: true,
                relay_udp: true,
            }
        );
    }

    #[test]
    fn client_forward_rules_allow_forward_without_listen_and_ignore_unknown_suffixes_like_upstream()
    -> Result<(), ConfigError> {
        let raw = load_json_str(
            r#"{
              "server": "example.com:23182",
              "uuid": "00000000-0000-0000-0000-000000000000",
              "password": "my_password",
              "forward": {
                "127.0.0.1:9000/quic": "example.com:9000"
              }
            }"#,
        )?;
        let config = validate_client(raw)?;
        let rules: Vec<_> = config.forward_rules().collect();
        assert_eq!(
            rules,
            vec![ForwardRule {
                local_addr: "127.0.0.1:9000",
                remote_addr: "example.com:9000",
                relay_tcp: false,
                relay_udp: false,
            }]
        );
        Ok(())
    }

    #[test]
    fn server_fwmark_accepts_go_parse_uint_base0_forms() -> Result<(), ConfigError> {
        for (literal, expected) in [
            ("0", 0),
            ("1_0", 10),
            ("0x1_000", 0x1000),
            ("0b10_10", 10),
            ("0o7_7", 63),
            ("077", 63),
        ] {
            let raw = load_json_str(&format!(r#"{{"listen":":23182","fwmark":"{literal}"}}"#))?;
            let config = validate_server(raw)?;
            assert_eq!(config.fwmark, Some(expected), "fwmark {literal}");
        }
        Ok(())
    }

    #[test]
    fn server_fwmark_distinguishes_syntax_and_range_errors_like_upstream() {
        let syntax_raw = load_json_str(r#"{"listen":":23182","fwmark":"bogus"}"#).unwrap();
        match validate_server(syntax_raw).unwrap_err() {
            ConfigError::InvalidFwmark { value, kind } => {
                assert_eq!(value, "bogus");
                assert_eq!(kind, FwmarkParseErrorKind::Syntax);
            }
            other => panic!("expected syntax fwmark error, got {other:?}"),
        }

        for literal in ["4294967296", "0x1FFFFFFFF"] {
            let raw =
                load_json_str(&format!(r#"{{"listen":":23182","fwmark":"{literal}"}}"#)).unwrap();
            match validate_server(raw).unwrap_err() {
                ConfigError::InvalidFwmark { value, kind } => {
                    assert_eq!(value, literal);
                    assert_eq!(kind, FwmarkParseErrorKind::Range, "fwmark {literal}");
                }
                other => panic!("expected range fwmark error for {literal}, got {other:?}"),
            }
        }
    }

    #[test]
    fn server_send_through_accepts_valid_ip_addresses_like_upstream() -> Result<(), ConfigError> {
        for literal in ["113.25.132.3", "::1", "2001:db8::1"] {
            let raw = load_json_str(&format!(
                r#"{{"listen":":23182","send_through":"{literal}"}}"#
            ))?;
            let config = validate_server(raw)?;
            assert_eq!(
                config.send_through,
                Some(literal.parse::<std::net::IpAddr>().unwrap()),
                "send_through {literal}"
            );
        }
        Ok(())
    }

    #[test]
    fn server_send_through_rejects_non_ip_values_like_upstream() -> Result<(), ConfigError> {
        for literal in ["[::1]", "example.com", "127.0.0.1:80"] {
            let raw = load_json_str(&format!(
                r#"{{"listen":":23182","send_through":"{literal}"}}"#
            ))?;
            let err = validate_server(raw).unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigError::InvalidSendThrough { ref value, .. } if value == literal
                ),
                "send_through {literal}: {err:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn parses_upstream_server_example_shape() -> Result<(), ConfigError> {
        let raw = load_json_str(
            r#"{
              "listen": ":23182",
              "users": {"00000000-0000-0000-0000-000000000000": "my_password"},
              "certificate": "/path/to/fullchain.cer",
              "private_key": "/path/to/private.key",
              "congestion_control": "bbr",
              "fwmark": "0x1000",
              "log_level": "info"
            }"#,
        )?;
        let config = validate_server(raw)?;
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.fwmark, Some(0x1000));
        assert_eq!(config.dialer_link, None);
        Ok(())
    }

    #[test]
    fn server_outbound_socks5_normalizes_to_dialer_link() -> Result<(), ConfigError> {
        let raw = load_json_str(
            r#"{
              "listen": ":23182",
              "users": {"00000000-0000-0000-0000-000000000000": "my_password"},
              "certificate": "/path/to/fullchain.cer",
              "private_key": "/path/to/private.key",
              "outbound": {
                "type": "socks5",
                "server": "127.0.0.1",
                "server_port": 10808
              }
            }"#,
        )?;
        let config = validate_server(raw)?;
        assert_eq!(
            config.dialer_link.as_deref(),
            Some("socks5://127.0.0.1:10808")
        );
        assert_eq!(config.raw.dialer_link, "socks5://127.0.0.1:10808");
        Ok(())
    }

    #[test]
    fn server_outbound_socks5_encodes_auth_and_ipv6_host() -> Result<(), ConfigError> {
        let raw = load_json_str(
            r#"{
              "listen": ":23182",
              "users": {"00000000-0000-0000-0000-000000000000": "my_password"},
              "certificate": "/path/to/fullchain.cer",
              "private_key": "/path/to/private.key",
              "outbound": {
                "type": "socks5",
                "server": "::1",
                "server_port": 1080,
                "username": "user name",
                "password": "p@ss:word"
              }
            }"#,
        )?;
        let config = validate_server(raw)?;
        assert_eq!(
            config.dialer_link.as_deref(),
            Some("socks5://user%20name:p%40ss%3Aword@[::1]:1080")
        );
        Ok(())
    }

    #[test]
    fn server_outbound_and_matching_dialer_link_are_accepted() -> Result<(), ConfigError> {
        let raw = load_json_str(
            r#"{
              "listen": ":23182",
              "users": {"00000000-0000-0000-0000-000000000000": "my_password"},
              "certificate": "/path/to/fullchain.cer",
              "private_key": "/path/to/private.key",
              "dialer_link": "socks5://127.0.0.1:10808",
              "outbound": {
                "type": "socks5",
                "server": "127.0.0.1",
                "server_port": 10808
              }
            }"#,
        )?;
        let config = validate_server(raw)?;
        assert_eq!(
            config.dialer_link.as_deref(),
            Some("socks5://127.0.0.1:10808")
        );
        Ok(())
    }

    #[test]
    fn server_outbound_and_conflicting_dialer_link_are_rejected() {
        let raw = load_json_str(
            r#"{
              "listen": ":23182",
              "users": {"00000000-0000-0000-0000-000000000000": "my_password"},
              "certificate": "/path/to/fullchain.cer",
              "private_key": "/path/to/private.key",
              "dialer_link": "socks5://127.0.0.1:1",
              "outbound": {
                "type": "socks5",
                "server": "127.0.0.1",
                "server_port": 10808
              }
            }"#,
        )
        .expect("decode");
        let err = validate_server(raw).unwrap_err();
        assert!(matches!(err, ConfigError::ConflictingOutboundAndDialerLink));
    }

    #[test]
    fn server_outbound_rejects_missing_port_and_unsupported_type() {
        let missing_port = load_json_str(
            r#"{
              "listen": ":23182",
              "users": {"00000000-0000-0000-0000-000000000000": "my_password"},
              "certificate": "/path/to/fullchain.cer",
              "private_key": "/path/to/private.key",
              "outbound": {"type":"socks5","server":"127.0.0.1"}
            }"#,
        )
        .expect("decode");
        assert!(matches!(
            validate_server(missing_port).unwrap_err(),
            ConfigError::InvalidOutbound(_)
        ));

        let zero_port = load_json_str(
            r#"{
              "listen": ":23182",
              "outbound": {"type":"socks5","server":"127.0.0.1","server_port":0}
            }"#,
        )
        .expect("decode");
        assert!(matches!(
            validate_server(zero_port).unwrap_err(),
            ConfigError::InvalidOutbound(message) if message.contains("non-zero")
        ));

        let bad_type = load_json_str(
            r#"{
              "listen": ":23182",
              "users": {"00000000-0000-0000-0000-000000000000": "my_password"},
              "certificate": "/path/to/fullchain.cer",
              "private_key": "/path/to/private.key",
              "outbound": {"type":"http","server":"127.0.0.1","server_port":8080}
            }"#,
        )
        .expect("decode");
        assert!(matches!(
            validate_server(bad_type).unwrap_err(),
            ConfigError::InvalidOutbound(_)
        ));
    }

    #[test]
    fn server_outbound_rejects_malformed_hosts_and_oversized_credentials() {
        for host in ["user@proxy.example", "proxy.example/path", "host:1080"] {
            let raw = load_json_str(&format!(
                r#"{{"listen":":23182","outbound":{{"server":"{host}","server_port":1080}}}}"#
            ))
            .expect("decode");
            assert!(
                matches!(validate_server(raw).unwrap_err(), ConfigError::InvalidOutbound(message) if message.contains("hostname or IP")),
                "host {host} must fail"
            );
        }

        for (field, value) in [("username", "u".repeat(256)), ("password", "p".repeat(256))] {
            let raw = load_json_str(&format!(
                r#"{{"listen":":23182","outbound":{{"server":"127.0.0.1","server_port":1080,"username":"user","{field}":"{value}"}}}}"#
            ))
            .expect("decode");
            assert!(
                matches!(validate_server(raw).unwrap_err(), ConfigError::InvalidOutbound(message) if message.contains("255 bytes")),
                "field {field} must fail"
            );
        }
    }

    #[test]
    fn server_outbound_env_only_normalizes_to_dialer_link() -> Result<(), ConfigError> {
        let mut raw = RawConfig::default();
        apply_server_outbound_env_values(
            &mut raw,
            ServerOutboundEnvValues {
                outbound_type: Some("socks5".to_owned()),
                server: Some("localhost".to_owned()),
                port: Some("10808".to_owned()),
                username: Some("vpn user".to_owned()),
                password: Some("p@ss:word".to_owned()),
            },
        )?;

        let config = validate_server(raw)?;
        assert_eq!(
            config.dialer_link.as_deref(),
            Some("socks5://vpn%20user:p%40ss%3Aword@localhost:10808")
        );
        Ok(())
    }

    #[test]
    fn server_outbound_empty_env_values_preserve_direct_mode() -> Result<(), ConfigError> {
        let mut raw = RawConfig::default();
        apply_server_outbound_env_values(
            &mut raw,
            ServerOutboundEnvValues {
                outbound_type: Some(String::new()),
                server: Some(String::new()),
                port: Some(String::new()),
                username: Some(String::new()),
                password: Some(String::new()),
            },
        )?;

        assert!(raw.outbound.is_none());
        assert_eq!(validate_server(raw)?.dialer_link, None);
        Ok(())
    }

    #[test]
    fn server_outbound_json_values_take_precedence_over_env() -> Result<(), ConfigError> {
        let mut raw = load_json_str(
            r#"{
              "listen": ":23182",
              "outbound": {
                "type":"socks5",
                "server":"127.0.0.1",
                "server_port":1080,
                "username":"json-user",
                "password":"json-password"
              }
            }"#,
        )?;
        apply_server_outbound_env_values(
            &mut raw,
            ServerOutboundEnvValues {
                outbound_type: Some("http".to_owned()),
                server: Some("proxy.example".to_owned()),
                port: Some("not-a-port".to_owned()),
                username: Some("env-user".to_owned()),
                password: Some("env-password".to_owned()),
            },
        )?;

        assert_eq!(
            validate_server(raw)?.dialer_link.as_deref(),
            Some("socks5://json-user:json-password@127.0.0.1:1080")
        );
        Ok(())
    }

    #[test]
    fn server_outbound_env_rejects_invalid_ports() {
        for value in ["0", "65536", "not-a-port"] {
            let mut raw = RawConfig::default();
            let error = apply_server_outbound_env_values(
                &mut raw,
                ServerOutboundEnvValues {
                    server: Some("127.0.0.1".to_owned()),
                    port: Some(value.to_owned()),
                    ..ServerOutboundEnvValues::default()
                },
            )
            .expect_err("invalid env port must fail");
            assert!(
                matches!(error, ConfigError::InvalidOutbound(ref message) if message.contains("ZUICITY_OUTBOUND_PORT")),
                "port {value}: {error:?}"
            );
        }
    }

    #[test]
    fn socks5_dialer_link_builder_defaults_type_to_socks5() -> Result<(), ConfigError> {
        let outbound = RawOutboundConfig {
            server: "127.0.0.1".to_owned(),
            server_port: Some(10808),
            ..RawOutboundConfig::default()
        };
        assert_eq!(
            socks5_dialer_link_from_outbound(&outbound)?,
            "socks5://127.0.0.1:10808"
        );
        Ok(())
    }

    #[test]
    fn socks5_outbound_accepts_alias_version_and_credential_boundaries() -> Result<(), ConfigError>
    {
        let boundary = "x".repeat(255);
        let outbound = RawOutboundConfig {
            outbound_type: "5".to_owned(),
            server: " proxy.example ".to_owned(),
            server_port: Some(1080),
            username: boundary.clone(),
            password: boundary.clone(),
            version: "5".to_owned(),
        };
        let link = socks5_dialer_link_from_outbound(&outbound)?;
        assert_eq!(
            link,
            format!("socks5://{boundary}:{boundary}@proxy.example:1080")
        );

        Ok(())
    }

    #[test]
    fn socks5_outbound_rejects_bad_version_password_without_username_and_blank_server() {
        for (outbound, expected) in [
            (
                RawOutboundConfig {
                    server: "127.0.0.1".to_owned(),
                    server_port: Some(1080),
                    version: "4".to_owned(),
                    ..RawOutboundConfig::default()
                },
                "unsupported version",
            ),
            (
                RawOutboundConfig {
                    server: "127.0.0.1".to_owned(),
                    server_port: Some(1080),
                    password: "password".to_owned(),
                    ..RawOutboundConfig::default()
                },
                "both be set",
            ),
            (
                RawOutboundConfig {
                    server: "127.0.0.1".to_owned(),
                    server_port: Some(1080),
                    username: "username".to_owned(),
                    ..RawOutboundConfig::default()
                },
                "both be set",
            ),
            (
                RawOutboundConfig {
                    server: "   ".to_owned(),
                    server_port: Some(1080),
                    ..RawOutboundConfig::default()
                },
                "server is required",
            ),
        ] {
            let error = socks5_dialer_link_from_outbound(&outbound)
                .expect_err("invalid SOCKS5 outbound must fail");
            assert!(
                error.to_string().contains(expected),
                "unexpected error: {error}"
            );
        }
    }
}
