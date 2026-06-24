//! Differential parity tests comparing the Rust `ProxyDialerLink` parser against
//! the upstream Go daeuniverse dialer surface that juicity registers.
//!
//! A small Go oracle (`differential/oracle`) parses each `dialer_link` with the
//! exact upstream creators and emits a normalized `{ok, protocol, host, port}`
//! result. This test generates structured and random links with proptest, parses
//! them with both implementations, and asserts that accept/reject decisions match
//! and that — for the simple endpoint-bearing schemes (socks/socks5/http/https) —
//! the parsed scheme family, host, and port agree.
//!
//! The test skips gracefully when the Go toolchain or built oracle is
//! unavailable, mirroring the capability-skip pattern used for SO_MARK tests.

use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

use proptest::prelude::*;
use zuicity_transport::ProxyDialerLink;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SchemeFamily {
    Socks,
    Http,
    Https,
    Other,
}

fn scheme_family(scheme: &str) -> SchemeFamily {
    match scheme.to_ascii_lowercase().as_str() {
        "socks" | "socks5" => SchemeFamily::Socks,
        "http" => SchemeFamily::Http,
        "https" => SchemeFamily::Https,
        _ => SchemeFamily::Other,
    }
}

fn canonical_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host)
}

fn oracle_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("ZUICITY_DIALER_ORACLE") {
        let path = PathBuf::from(explicit);
        return path.is_file().then_some(path);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest
        .join("..")
        .join("..")
        .join("differential")
        .join("oracle")
        .join("dialer-link-oracle");
    candidate.is_file().then_some(candidate)
}

fn run_oracle(path: &PathBuf, mode: &str, links: &[String]) -> std::io::Result<Vec<RawOracleLine>> {
    use base64::Engine as _;
    let mut child = Command::new(path)
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    {
        let mut stdin = child.stdin.take().expect("oracle stdin");
        for link in links {
            let encoded = base64::engine::general_purpose::STANDARD.encode(link.as_bytes());
            stdin.write_all(encoded.as_bytes())?;
            stdin.write_all(b"\n")?;
        }
    }
    let output = child.wait_with_output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut results = Vec::with_capacity(links.len());
    for line in text.lines() {
        results.push(parse_oracle_line(line));
    }
    Ok(results)
}

#[derive(Clone, Debug)]
struct RawOracleLine {
    ok: bool,
    protocol: String,
    host: String,
    port: i64,
}

fn parse_oracle_line(line: &str) -> RawOracleLine {
    let value: serde_json::Value = serde_json::from_str(line).unwrap_or(serde_json::Value::Null);
    RawOracleLine {
        ok: value
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        protocol: value
            .get("protocol")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned(),
        host: value
            .get("host")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned(),
        port: value
            .get("port")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0),
    }
}

fn rust_decision(link: &str) -> (bool, SchemeFamily, Option<String>, Option<u16>) {
    match ProxyDialerLink::parse(link) {
        Ok(parsed) => {
            let family = scheme_family(parsed.scheme());
            let (host, port) = match parsed.endpoint_host_port() {
                Some((host, port)) => (Some(host.to_owned()), Some(port)),
                None => (None, None),
            };
            (true, family, host, port)
        }
        Err(_) => (false, SchemeFamily::Other, None, None),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AllowedDivergence {
    EmptyHost,
    PortOverflow,
}

fn classify_allowed_divergence(oracle: &RawOracleLine) -> Option<AllowedDivergence> {
    if oracle.host.is_empty() {
        return Some(AllowedDivergence::EmptyHost);
    }
    if oracle.port > u16::MAX as i64 {
        return Some(AllowedDivergence::PortOverflow);
    }
    None
}

fn compare(link: &str, oracle: &RawOracleLine) -> Result<(), TestCaseError> {
    let (rust_ok, rust_family, rust_host, rust_port) = rust_decision(link);
    let oracle_family = scheme_family(&oracle.protocol);

    let comparable = matches!(
        rust_family,
        SchemeFamily::Socks | SchemeFamily::Http | SchemeFamily::Https
    ) || matches!(
        oracle_family,
        SchemeFamily::Socks | SchemeFamily::Http | SchemeFamily::Https
    );
    if !comparable {
        return Ok(());
    }

    match (oracle.ok, rust_ok) {
        (true, true) => {
            prop_assert_eq!(
                rust_family,
                oracle_family,
                "scheme-family divergence for {:?}: rust={:?} oracle={:?}",
                link,
                rust_family,
                oracle_family
            );
            if let (Some(host), Some(port)) = (rust_host.as_deref(), rust_port) {
                prop_assert_eq!(
                    canonical_host(host),
                    canonical_host(oracle.host.as_str()),
                    "host divergence for {:?}",
                    link
                );
                prop_assert_eq!(
                    i64::from(port),
                    oracle.port,
                    "port divergence for {:?}",
                    link
                );
            }
            Ok(())
        }
        (true, false) => {
            let class = classify_allowed_divergence(oracle);
            prop_assert!(
                class.is_some(),
                "unallowed divergence for {:?}: upstream accepts (host={:?} port={}) but Rust rejects, and it is not a documented EmptyHost/PortOverflow case",
                link,
                oracle.host,
                oracle.port
            );
            Ok(())
        }
        (false, true) => {
            prop_assert!(
                false,
                "Rust is MORE LENIENT than upstream for {:?}: upstream rejects but Rust accepts (rust_host={:?} rust_port={:?}). Rust must never accept what upstream rejects.",
                link,
                rust_host,
                rust_port
            );
            Ok(())
        }
        (false, false) => Ok(()),
    }
}

fn link_strategy() -> impl Strategy<Value = String> {
    let scheme = prop_oneof![
        Just("socks5"),
        Just("socks"),
        Just("http"),
        Just("https"),
        Just("trojan"),
        Just("vmess"),
        Just("vless"),
        Just("tuic"),
        Just("juicity"),
        Just("hysteria2"),
        Just("ss"),
        Just("zzz-unknown"),
    ];
    let host = prop_oneof![
        Just("127.0.0.1".to_owned()),
        Just("example.com".to_owned()),
        Just("[::1]".to_owned()),
        Just("0.0.0.0".to_owned()),
        "[a-z]{1,8}\\.[a-z]{2,3}",
        Just(String::new()),
    ];
    let port = prop_oneof![Just(None), (0_u32..=70000_u32).prop_map(Some),];
    let userinfo = prop_oneof![
        Just(String::new()),
        Just("user@".to_owned()),
        Just("user:pass@".to_owned()),
    ];
    (scheme, userinfo, host, port).prop_map(|(scheme, userinfo, host, port)| match port {
        Some(port) => format!("{scheme}://{userinfo}{host}:{port}"),
        None => format!("{scheme}://{userinfo}{host}"),
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn dialer_link_parser_matches_upstream_oracle(links in proptest::collection::vec(link_strategy(), 1..32)) {
        let Some(oracle) = oracle_path() else {
            return Ok(());
        };
        let results = run_oracle(&oracle, "dialer", &links)
            .map_err(|error| TestCaseError::fail(format!("run oracle: {error}")))?;
        prop_assert_eq!(results.len(), links.len(), "oracle result count mismatch");
        for (link, result) in links.iter().zip(results.iter()) {
            compare(link, result)?;
        }
    }
}

#[test]
fn dialer_link_oracle_is_available_or_skipped() {
    match oracle_path() {
        Some(path) => eprintln!("differential oracle present at {}", path.display()),
        None => eprintln!(
            "differential oracle not built; set ZUICITY_DIALER_ORACLE or build differential/oracle"
        ),
    }
}

fn rust_config_accepts(raw: &str) -> bool {
    zuicity_config::load_json_str(raw).is_ok()
}

fn config_json_strategy() -> impl Strategy<Value = String> {
    let string_field = prop_oneof![
        Just("\"listen\":\"127.0.0.1:1080\""),
        Just("\"server\":\"example.com:443\""),
        Just("\"uuid\":\"00000000-0000-0000-0000-000000000001\""),
        Just("\"password\":\"secret\""),
        Just("\"sni\":\"localhost\""),
        Just("\"congestion_control\":\"bbr\""),
        Just("\"log_level\":\"info\""),
        Just("\"fwmark\":\"0x20\""),
        Just("\"dialer_link\":\"socks5://127.0.0.1:1080\""),
    ];
    let bool_field = prop_oneof![
        Just("\"allow_insecure\":true"),
        Just("\"disable_outbound_udp443\":false"),
    ];
    let map_field = prop_oneof![
        Just("\"users\":{\"00000000-0000-0000-0000-000000000001\":\"pw\"}"),
        Just("\"forward\":{\"127.0.0.1:10000/tcp\":\"127.0.0.1:22\"}"),
    ];
    let type_mismatch = prop_oneof![
        Just("\"allow_insecure\":\"notabool\""),
        Just("\"listen\":123"),
        Just("\"forward\":\"notamap\""),
        Just("\"users\":[1,2,3]"),
        Just("\"disable_outbound_udp443\":\"yes\""),
    ];
    let unknown_field = prop_oneof![Just("\"totally_unknown\":\"x\""), Just("\"extra\":42"),];
    let fragment = prop_oneof![
        string_field.prop_map(str::to_owned),
        bool_field.prop_map(str::to_owned),
        map_field.prop_map(str::to_owned),
        type_mismatch.prop_map(str::to_owned),
        unknown_field.prop_map(str::to_owned),
    ];
    let object = proptest::collection::vec(fragment, 0..6).prop_map(|fragments| {
        let mut seen_keys = std::collections::BTreeSet::new();
        let mut unique = Vec::new();
        for fragment in fragments {
            let key = fragment.split(':').next().unwrap_or("").to_owned();
            if seen_keys.insert(key) {
                unique.push(fragment);
            }
        }
        format!("{{{}}}", unique.join(","))
    });
    prop_oneof![
        object,
        Just("{ not valid json".to_owned()),
        Just("[]".to_owned()),
        Just("null".to_owned()),
        Just("{}".to_owned()),
        Just("\"a string\"".to_owned()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3072))]

    #[test]
    fn config_json_parser_matches_upstream_oracle(configs in proptest::collection::vec(config_json_strategy(), 1..24)) {
        let Some(oracle) = oracle_path() else {
            return Ok(());
        };
        let results = run_oracle(&oracle, "config", &configs)
            .map_err(|error| TestCaseError::fail(format!("run config oracle: {error}")))?;
        prop_assert_eq!(results.len(), configs.len(), "config oracle result count mismatch");
        for (config, result) in configs.iter().zip(results.iter()) {
            let rust_ok = rust_config_accepts(config);
            prop_assert_eq!(
                rust_ok,
                result.ok,
                "config accept/reject divergence for {:?}: rust_ok={} oracle_ok={}",
                config,
                rust_ok,
                result.ok
            );
        }
    }
}
