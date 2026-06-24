//! zuicity-server helper runtime parity tests.

use std::process::Command;

#[test]
fn generate_certchain_hash_missing_file_matches_upstream_runtime() {
    let output = Command::new(env!("CARGO_BIN_EXE_zuicity-server"))
        .args([
            "generate-certchain-hash",
            "/tmp/zuicity-definitely-missing-a.pem",
            "/tmp/zuicity-definitely-missing-b.pem",
        ])
        .output()
        .expect("run zuicity-server generate-certchain-hash");

    assert!(
        output.status.success(),
        "upstream prints the open error and exits successfully; status={:?}, stderr={}, stdout={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("open /tmp/zuicity-definitely-missing-a.pem:"),
        "stdout should contain upstream-style open error, got: {stdout:?}"
    );
    assert!(
        stdout.contains("no such file or directory"),
        "stdout should contain upstream OS error, got: {stdout:?}"
    );
    assert!(
        output.stderr.is_empty(),
        "upstream writes this helper read error to stdout, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn generate_sharelink_no_config_matches_upstream_runtime() {
    let output = Command::new(env!("CARGO_BIN_EXE_zuicity-server"))
        .arg("generate-sharelink")
        .output()
        .expect("run zuicity-server generate-sharelink");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stderr.is_empty(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("argument \"--config\" or \"-c\" is required but not provided"),
        "stdout={stdout:?}"
    );
}

#[test]
fn generate_sharelink_positional_config_is_ignored_like_upstream() {
    let output = Command::new(env!("CARGO_BIN_EXE_zuicity-server"))
        .args(["generate-sharelink", "install/example-server.json"])
        .output()
        .expect("run zuicity-server generate-sharelink positional");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stderr.is_empty(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("argument \"--config\" or \"-c\" is required but not provided"),
        "stdout={stdout:?}"
    );
}

#[test]
fn generate_sharelink_missing_config_matches_upstream_runtime() {
    let missing = "/tmp/zuicity-sharelink-missing-config.json";
    let _ = std::fs::remove_file(missing);
    let output = Command::new(env!("CARGO_BIN_EXE_zuicity-server"))
        .args(["generate-sharelink", "-c", missing])
        .output()
        .expect("run zuicity-server generate-sharelink missing config");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stderr.is_empty(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(
            "ReadConfig: open /tmp/zuicity-sharelink-missing-config.json: no such file or directory"
        ),
        "stdout={stdout:?}"
    );
}

#[test]
fn generate_sharelink_missing_certificate_matches_upstream_runtime() {
    let config = "/tmp/zuicity-sharelink-missing-cert.json";
    std::fs::write(
        config,
        r#"{
  "listen": ":23182",
  "users": {"00000000-0000-0000-0000-000000000000": "my_password"},
  "certificate": "/tmp/zuicity-missing-fullchain.cer",
  "private_key": "/tmp/zuicity-missing-private.key",
  "congestion_control": "bbr"
}"#,
    )
    .expect("write missing-cert config");

    let output = Command::new(env!("CARGO_BIN_EXE_zuicity-server"))
        .args(["generate-sharelink", "-c", config])
        .output()
        .expect("run zuicity-server generate-sharelink missing certificate");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stderr.is_empty(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("open /tmp/zuicity-missing-fullchain.cer: no such file or directory"),
        "stdout={stdout:?}"
    );
}

#[test]
fn generate_sharelink_self_signed_output_matches_upstream_shape() {
    let dir = "/tmp/zuicity-sharelink-success-test";
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).expect("create sharelink success fixture dir");

    let mut params = rcgen::CertificateParams::new(vec!["example.com".to_owned()])
        .expect("create certificate parameters");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "example.com");
    let key_pair = rcgen::KeyPair::generate().expect("generate key pair");
    let cert = params
        .self_signed(&key_pair)
        .expect("generate self-signed certificate");
    let cert_path = format!("{dir}/fullchain.cer");
    let key_path = format!("{dir}/private.key");
    let config_path = format!("{dir}/server.json");
    std::fs::write(&cert_path, cert.pem()).expect("write certificate");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write private key");
    std::fs::write(
        &config_path,
        format!(
            r#"{{
  "listen": ":23182",
  "users": {{"00000000-0000-0000-0000-000000000000": "my_password"}},
  "certificate": "{cert_path}",
  "private_key": "{key_path}",
  "congestion_control": "cubic"
}}"#
        ),
    )
    .expect("write success config");

    let output = Command::new(env!("CARGO_BIN_EXE_zuicity-server"))
        .args(["generate-sharelink", "-c", &config_path])
        .output()
        .expect("run zuicity-server generate-sharelink success");

    assert!(
        output.status.success(),
        "status={:?}, stderr={}, stdout={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stderr.is_empty(),
        "upstream writes successful sharelink only to stdout, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let link = stdout.trim();
    assert!(
        link.starts_with("juicity://00000000-0000-0000-0000-000000000000:my_password@"),
        "link={link:?}"
    );
    assert!(link.contains(":23182?"), "link={link:?}");
    assert!(
        link.contains("?allow_insecure=1&congestion_control=bbr&pinned_certchain_sha256="),
        "upstream sorts query keys and forces bbr in generated sharelinks, link={link:?}"
    );
    assert!(link.ends_with("&sni=example.com"), "link={link:?}");
}
