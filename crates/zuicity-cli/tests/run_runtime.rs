//! zuicity client/server run-mode runtime parity tests.

use std::{
    net::SocketAddr,
    process::{Child, Command},
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose};

static PORT_BOUND_RUNTIME_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Channel-recv timeout for the multi-hop proxy-chain interop tests.
///
/// These tests drive an upstream subprocess through a two-hop proxy chain
/// (socks5 + shadowsocks). Under `--all-targets` many test binaries run in
/// parallel and starve the subprocess of CPU, so the first relayed packet can
/// take several seconds to arrive. A generous timeout makes the assertion
/// contention-tolerant without masking a genuinely broken chain, which never
/// delivers the packet regardless of timeout.
const CHAIN_RELAY_TIMEOUT: Duration = Duration::from_secs(30);

struct PortBoundRuntimeTestGuard {
    _cross_binary: zuicity_testkit::HeavySubprocessTestGuard,
    _in_binary: MutexGuard<'static, ()>,
}

fn port_bound_runtime_test_lock() -> PortBoundRuntimeTestGuard {
    let in_binary = PORT_BOUND_RUNTIME_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let cross_binary = zuicity_testkit::HeavySubprocessTestGuard::acquire();
    PortBoundRuntimeTestGuard {
        _cross_binary: cross_binary,
        _in_binary: in_binary,
    }
}

fn write_config(path: &str, contents: &str) {
    std::fs::write(path, contents).expect("write config fixture");
}

fn spawn_bin(bin: &str, args: &[&str]) -> Child {
    let path = match bin {
        "zuicity-client" => env!("CARGO_BIN_EXE_zuicity-client"),
        "zuicity-server" => env!("CARGO_BIN_EXE_zuicity-server"),
        other => panic!("unknown bin {other}"),
    };
    Command::new(path).args(args).spawn().expect("spawn binary")
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child still present")
    }

    fn terminate(mut self) -> std::process::Output {
        let mut child = self.child.take().expect("child still present");
        let _ = child.kill();
        child.wait_with_output().expect("collect terminated child")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn assert_stays_running_without_placeholder(bin: &str, config_path: &str) {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    let mut child = spawn_bin(bin, &["run", "-c", config_path]);
    std::thread::sleep(std::time::Duration::from_millis(300));
    match child.try_wait().expect("poll child") {
        Some(status) => {
            let output = child.wait_with_output().expect("collect exited child");
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            panic!("{bin} exited early with {status}; output={combined:?}");
        }
        None => {
            child.kill().expect("kill running child");
            let output = child.wait_with_output().expect("collect killed child");
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                !combined.contains("runtime is not implemented"),
                "output={combined:?}"
            );
        }
    }
}

fn run_bin(bin: &str, args: &[&str]) -> std::process::Output {
    let path = match bin {
        "zuicity-client" => env!("CARGO_BIN_EXE_zuicity-client"),
        "zuicity-server" => env!("CARGO_BIN_EXE_zuicity-server"),
        other => panic!("unknown bin {other}"),
    };
    Command::new(path).args(args).output().expect("run binary")
}

fn upstream_client_binary(dir: &std::path::Path) -> std::path::PathBuf {
    if let Some(prebuilt_dir) = std::env::var_os("UPSTREAM_JUICITY_BIN_DIR") {
        return std::path::PathBuf::from(prebuilt_dir).join("juicity-client");
    }
    let upstream_root = std::env::var_os("UPSTREAM_JUICITY_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/root/projects/juicity/juicity"));
    let bin_dir = dir.join("upstream-bin");
    std::fs::create_dir_all(&bin_dir).expect("create upstream client bin dir");
    let client = bin_dir.join("juicity-client");
    let build_log = dir.join("upstream-client-build.log");
    let output = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&client)
        .arg("./cmd/client")
        .current_dir(&upstream_root)
        .output()
        .expect("build upstream juicity-client");
    std::fs::write(
        &build_log,
        format!(
            "status={}\nstdout={}\nstderr={}\n",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
    .expect("write upstream client build log");
    assert!(
        output.status.success(),
        "upstream juicity-client build failed; see {}",
        build_log.display()
    );
    client
}

fn upstream_server_binary(dir: &std::path::Path) -> std::path::PathBuf {
    if let Some(prebuilt_dir) = std::env::var_os("UPSTREAM_JUICITY_BIN_DIR") {
        return std::path::PathBuf::from(prebuilt_dir).join("juicity-server");
    }
    let upstream_root = std::env::var_os("UPSTREAM_JUICITY_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/root/projects/juicity/juicity"));
    let bin_dir = dir.join("upstream-bin");
    std::fs::create_dir_all(&bin_dir).expect("create upstream server bin dir");
    let server = bin_dir.join("juicity-server");
    let build_log = dir.join("upstream-server-build.log");
    let output = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&server)
        .arg("./cmd/server")
        .current_dir(&upstream_root)
        .output()
        .expect("build upstream juicity-server");
    std::fs::write(
        &build_log,
        format!(
            "status={}\nstdout={}\nstderr={}\n",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
    .expect("write upstream server build log");
    assert!(
        output.status.success(),
        "upstream juicity-server build failed; see {}",
        build_log.display()
    );
    server
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ShadowsocksTcpRequest {
    target: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ShadowsocksUdpRequest {
    target: SocketAddr,
}

async fn start_shadowsocks_tcp_udp_proxy(
    password: &'static str,
    method: shadowsocks::crypto::CipherKind,
) -> std::io::Result<(
    SocketAddr,
    tokio::sync::mpsc::Receiver<ShadowsocksTcpRequest>,
    tokio::sync::mpsc::Receiver<ShadowsocksUdpRequest>,
    tokio::task::JoinHandle<std::io::Result<()>>,
)> {
    let udp_server_config = shadowsocks::config::ServerConfig::new(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        password,
        method,
    )
    .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidInput, source))?;
    let udp_context =
        shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Server);
    let udp_socket = shadowsocks::ProxySocket::bind(udp_context, &udp_server_config).await?;
    let local_addr = udp_socket.local_addr()?;
    let tcp_server_config = shadowsocks::config::ServerConfig::new(local_addr, password, method)
        .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidInput, source))?;
    let tcp_context =
        shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Server);
    let tcp_listener = shadowsocks::ProxyListener::bind(tcp_context, &tcp_server_config).await?;
    let (tcp_request_tx, tcp_request_rx) = tokio::sync::mpsc::channel(1);
    let (udp_request_tx, udp_request_rx) = tokio::sync::mpsc::channel(1);
    let tcp_task = tokio::spawn(async move {
        let (mut inbound, _) = tcp_listener.accept().await?;
        let target = inbound.handshake().await?;
        let target = shadowsocks_test_socket_addr(target).await?;
        tcp_request_tx
            .send(ShadowsocksTcpRequest { target })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
            })?;
        let mut outbound = tokio::net::TcpStream::connect(target).await?;
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
        Ok::<_, std::io::Error>(())
    });
    let udp_task = tokio::spawn(async move {
        let mut request_payload = vec![0_u8; 65_535];
        let (received, peer, target, _packet_len) = udp_socket
            .recv_from(&mut request_payload)
            .await
            .map_err(std::io::Error::from)?;
        request_payload.truncate(received);
        let target = shadowsocks_test_socket_addr(target).await?;
        udp_request_tx
            .send(ShadowsocksUdpRequest { target })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
            })?;
        let outbound = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        outbound.connect(target).await?;
        outbound.send(&request_payload).await?;
        let mut response = vec![0_u8; 65_535];
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            outbound.recv(&mut response),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Shadowsocks UDP proxy target did not respond",
            )
        })??;
        udp_socket
            .send_to(
                peer,
                &shadowsocks::relay::socks5::Address::SocketAddress(target),
                &response[..received],
            )
            .await
            .map_err(std::io::Error::from)?;
        Ok::<_, std::io::Error>(())
    });
    let task = tokio::spawn(async move {
        tcp_task.await.map_err(std::io::Error::other)??;
        udp_task.await.map_err(std::io::Error::other)??;
        Ok::<_, std::io::Error>(())
    });
    Ok((local_addr, tcp_request_rx, udp_request_rx, task))
}

async fn start_shadowsocks_udp_proxy(
    password: &'static str,
    method: shadowsocks::crypto::CipherKind,
) -> std::io::Result<(
    SocketAddr,
    tokio::sync::mpsc::Receiver<ShadowsocksUdpRequest>,
    tokio::task::JoinHandle<std::io::Result<()>>,
)> {
    let server_config = shadowsocks::config::ServerConfig::new(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        password,
        method,
    )
    .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidInput, source))?;
    let context =
        shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Server);
    let socket = shadowsocks::ProxySocket::bind(context, &server_config).await?;
    let local_addr = socket.local_addr()?;
    let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move {
        let mut request_payload = vec![0_u8; 65_535];
        let (received, peer, target, _packet_len) = socket
            .recv_from(&mut request_payload)
            .await
            .map_err(std::io::Error::from)?;
        request_payload.truncate(received);
        let target = shadowsocks_test_socket_addr(target).await?;
        request_tx
            .send(ShadowsocksUdpRequest { target })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
            })?;
        let outbound = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        outbound.connect(target).await?;
        outbound.send(&request_payload).await?;
        let mut response = vec![0_u8; 65_535];
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            outbound.recv(&mut response),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Shadowsocks UDP proxy target did not respond",
            )
        })??;
        socket
            .send_to(
                peer,
                &shadowsocks::relay::socks5::Address::SocketAddress(target),
                &response[..received],
            )
            .await
            .map_err(std::io::Error::from)?;
        Ok::<_, std::io::Error>(())
    });
    Ok((local_addr, request_rx, task))
}

async fn shadowsocks_test_socket_addr(
    address: shadowsocks::relay::socks5::Address,
) -> std::io::Result<SocketAddr> {
    match address {
        shadowsocks::relay::socks5::Address::SocketAddress(address) => Ok(address),
        shadowsocks::relay::socks5::Address::DomainNameAddress(domain, port) => {
            tokio::net::lookup_host((domain.as_str(), port))
                .await?
                .next()
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "Shadowsocks UDP test target did not resolve",
                    )
                })
        }
    }
}

#[test]
fn client_run_no_config_fails_like_upstream_before_runtime_start() {
    let output = run_bin("zuicity-client", &["run"]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(
        combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(
        combined.contains("argument \"--config\" or \"-c\" is required but not provided"),
        "output={combined:?}"
    );
}

#[test]
fn server_run_no_config_fails_like_upstream_before_runtime_start() {
    let output = run_bin("zuicity-server", &["run"]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(
        combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(
        combined.contains("argument \"--config\" or \"-c\" is required but not provided"),
        "output={combined:?}"
    );
}

#[test]
fn client_run_missing_config_fails_like_upstream_before_runtime_start() {
    let missing = "/tmp/zuicity-run-missing-client.json";
    let _ = std::fs::remove_file(missing);
    let output = run_bin("zuicity-client", &["run", "-c", missing]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(
        combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(
        combined.contains(
            "ReadConfig: open /tmp/zuicity-run-missing-client.json: no such file or directory"
        ),
        "output={combined:?}"
    );
    assert!(!combined.contains("(os error"), "output={combined:?}");
}

#[test]
fn server_run_missing_config_fails_like_upstream_before_runtime_start() {
    let missing = "/tmp/zuicity-run-missing-server.json";
    let _ = std::fs::remove_file(missing);
    let output = run_bin("zuicity-server", &["run", "-c", missing]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(
        combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(
        combined.contains(
            "ReadConfig: open /tmp/zuicity-run-missing-server.json: no such file or directory"
        ),
        "output={combined:?}"
    );
    assert!(!combined.contains("(os error"), "output={combined:?}");
}

#[test]
fn client_run_empty_config_fails_like_upstream_before_runtime_start() {
    let config = "/tmp/zuicity-client-run-empty.json";
    write_config(config, "");
    let output = run_bin("zuicity-client", &["run", "-c", config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(
        combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(combined.contains("ReadConfig: EOF"), "output={combined:?}");
    assert!(!combined.contains("unexpected EOF"), "output={combined:?}");
    assert!(
        !combined.contains("decode config json"),
        "output={combined:?}"
    );
}

#[test]
fn server_run_invalid_user_uuid_fails_like_upstream_runtime() {
    let config = "/tmp/zuicity-server-run-invalid-user-uuid.json";
    write_config(
        config,
        r#"{"listen":"127.0.0.1:0","users":{"not-a-uuid":"password"},"certificate":"/tmp/unused-fullchain.pem","private_key":"/tmp/unused-private.key","log_level":"debug"}"#,
    );
    let output = run_bin("zuicity-server", &["run", "-c", config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(combined.contains("run.go:49"), "output={combined:?}");
    assert!(
        combined.contains(r#"error="parse uuid(not-a-uuid): invalid UUID length: 10""#),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(!combined.contains("parse user uuid"), "output={combined:?}");
}

#[test]
fn server_run_invalid_fwmark_fails_like_upstream_runtime() {
    let config = "/tmp/zuicity-server-run-invalid-fwmark.json";
    write_config(
        config,
        r#"{"listen":"127.0.0.1:0","users":{"00000000-0000-0000-0000-000000000001":"password"},"certificate":"/tmp/unused-fullchain.pem","private_key":"/tmp/unused-private.key","fwmark":"bogus","log_level":"debug"}"#,
    );
    let output = run_bin("zuicity-server", &["run", "-c", config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(combined.contains("run.go:49"), "output={combined:?}");
    assert!(
        combined.contains(
            r#"error="parse fwmark: strconv.ParseUint: parsing "bogus": invalid syntax""#
        ),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(
        !combined.contains(r#"error="parse fwmark: bogus""#),
        "output={combined:?}"
    );
}

#[test]
fn server_run_fwmark_out_of_range_fails_like_upstream_runtime() {
    let config = "/tmp/zuicity-server-run-fwmark-out-of-range.json";
    write_config(
        config,
        r#"{"listen":"127.0.0.1:0","users":{"00000000-0000-0000-0000-000000000001":"password"},"certificate":"/tmp/unused-fullchain.pem","private_key":"/tmp/unused-private.key","fwmark":"4294967296","log_level":"debug"}"#,
    );
    let output = run_bin("zuicity-server", &["run", "-c", config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(combined.contains("run.go:49"), "output={combined:?}");
    assert!(
        combined.contains(
            r#"error="parse fwmark: strconv.ParseUint: parsing "4294967296": value out of range""#
        ),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(!combined.contains("invalid syntax"), "output={combined:?}");
}

#[test]
fn server_run_invalid_send_through_fails_like_upstream_runtime() {
    let config = "/tmp/zuicity-server-run-invalid-send-through.json";
    write_config(
        config,
        r#"{"listen":"127.0.0.1:0","users":{"00000000-0000-0000-0000-000000000001":"password"},"certificate":"/tmp/unused-fullchain.pem","private_key":"/tmp/unused-private.key","send_through":"not-an-ip","log_level":"debug"}"#,
    );
    let output = run_bin("zuicity-server", &["run", "-c", config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(combined.contains("run.go:49"), "output={combined:?}");
    assert!(
        combined
            .contains(r#"error="parse send_through: ParseAddr("not-an-ip"): unable to parse IP""#),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("invalid IP address syntax"),
        "output={combined:?}"
    );
}

#[test]
fn server_run_missing_certificate_fails_like_upstream_runtime() {
    let dir = "/tmp/zuicity-server-run-missing-cert";
    std::fs::create_dir_all(dir).expect("create fixture dir");
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("generate cert");
    let key_path = format!("{dir}/private.key");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
    let missing_cert = "/tmp/zuicity-server-run-missing-cert-file.pem";
    let _ = std::fs::remove_file(missing_cert);
    let config = format!("{dir}/server.json");
    write_config(
        &config,
        &format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"00000000-0000-0000-0000-000000000001":"password"}},"certificate":"{missing_cert}","private_key":"{key_path}","log_level":"debug"}}"#
        ),
    );
    let output = run_bin("zuicity-server", &["run", "-c", &config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(combined.contains("run.go:49"), "output={combined:?}");
    assert!(
        combined.contains(&format!(
            r#"error="open {missing_cert}: no such file or directory""#
        )),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(!combined.contains("(os error"), "output={combined:?}");
    assert!(!combined.contains("run.go:42"), "output={combined:?}");
}

#[test]
fn server_run_missing_private_key_fails_like_upstream_runtime() {
    let dir = "/tmp/zuicity-server-run-missing-key";
    std::fs::create_dir_all(dir).expect("create fixture dir");
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("generate cert");
    let cert_path = format!("{dir}/fullchain.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    let missing_key = "/tmp/zuicity-server-run-missing-key-file.pem";
    let _ = std::fs::remove_file(missing_key);
    let config = format!("{dir}/server.json");
    write_config(
        &config,
        &format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"00000000-0000-0000-0000-000000000001":"password"}},"certificate":"{cert_path}","private_key":"{missing_key}","log_level":"debug"}}"#
        ),
    );
    let output = run_bin("zuicity-server", &["run", "-c", &config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(combined.contains("run.go:49"), "output={combined:?}");
    assert!(
        combined.contains(&format!(
            r#"error="open {missing_key}: no such file or directory""#
        )),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(!combined.contains("(os error"), "output={combined:?}");
    assert!(!combined.contains("run.go:42"), "output={combined:?}");
}

#[test]
fn server_run_missing_listen_fails_like_upstream_runtime() {
    let dir = "/tmp/zuicity-server-run-missing-listen";
    std::fs::create_dir_all(dir).expect("create fixture dir");
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("generate cert");
    let cert_path = format!("{dir}/fullchain.pem");
    let key_path = format!("{dir}/private.key");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
    let config = format!("{dir}/server.json");
    write_config(
        &config,
        &format!(
            r#"{{"users":{{"00000000-0000-0000-0000-000000000001":"password"}},"certificate":"{cert_path}","private_key":"{key_path}","log_level":"debug"}}"#
        ),
    );
    let output = run_bin("zuicity-server", &["run", "-c", &config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(combined.contains("run.go:49"), "output={combined:?}");
    assert!(
        combined.contains(r#"error=""Listen" is required""#),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("missing server listen"),
        "output={combined:?}"
    );
}

#[test]
fn server_run_empty_config_fails_like_upstream_before_runtime_start() {
    let config = "/tmp/zuicity-server-run-empty.json";
    write_config(config, "");
    let output = run_bin("zuicity-server", &["run", "-c", config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(
        combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(combined.contains("ReadConfig: EOF"), "output={combined:?}");
    assert!(!combined.contains("unexpected EOF"), "output={combined:?}");
    assert!(
        !combined.contains("decode config json"),
        "output={combined:?}"
    );
}

#[test]
fn client_run_malformed_config_fails_like_upstream_before_runtime_start() {
    let config = "/tmp/zuicity-client-run-malformed.json";
    write_config(config, r#"{"server":"#);
    let output = run_bin("zuicity-client", &["run", "-c", config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(
        combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(
        combined.contains("ReadConfig: unexpected EOF"),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("decode config json"),
        "output={combined:?}"
    );
}

#[test]
fn server_run_malformed_config_fails_like_upstream_before_runtime_start() {
    let config = "/tmp/zuicity-server-run-malformed.json";
    write_config(config, r#"{"listen":"#);
    let output = run_bin("zuicity-server", &["run", "-c", config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(
        combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(
        combined.contains("ReadConfig: unexpected EOF"),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("decode config json"),
        "output={combined:?}"
    );
}

#[test]
fn client_run_no_entrypoint_invalid_pin_fails_like_upstream_before_entrypoint_check() {
    let config = "/tmp/zuicity-client-run-no-entrypoint-invalid-pin.json";
    write_config(
        config,
        r#"{"server":"127.0.0.1:1","uuid":"00000000-0000-0000-0000-000000000001","password":"password","pinned_certchain_sha256":"not-valid-pin","log_level":"debug"}"#,
    );
    let output = run_bin("zuicity-client", &["run", "-c", config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(combined.contains("run.go:63"), "output={combined:?}");
    assert!(
        combined.contains(r#"error="failed to decode PinnedCertChainSha256""#),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("Please fill in at least one"),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("Failed to read config"),
        "output={combined:?}"
    );
}

#[test]
fn client_run_no_entrypoint_invalid_uuid_fails_like_upstream_before_entrypoint_check() {
    let config = "/tmp/zuicity-client-run-no-entrypoint-invalid-uuid.json";
    write_config(
        config,
        r#"{"server":"127.0.0.1:1","uuid":"not-a-uuid","password":"password","log_level":"debug"}"#,
    );
    let output = run_bin("zuicity-client", &["run", "-c", config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(combined.contains("run.go:63"), "output={combined:?}");
    assert!(
        combined.contains(r#"error="parse UUID: invalid UUID length: 10""#),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("Please fill in at least one"),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("Failed to read config"),
        "output={combined:?}"
    );
}

#[test]
fn client_run_no_entrypoint_empty_log_level_exits_silently_like_upstream() {
    let config = "/tmp/zuicity-client-run-no-entrypoint-empty-log.json";
    write_config(
        config,
        r#"{"server":"127.0.0.1:1","uuid":"00000000-0000-0000-0000-000000000001","password":"password","sni":"localhost","allow_insecure":true}"#,
    );
    let output = run_bin("zuicity-client", &["run", "-c", config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(combined, "", "output={combined:?}");
}

#[test]
fn client_run_no_entrypoint_debug_config_fails_like_upstream_runtime() {
    let config = "/tmp/zuicity-client-run-no-entrypoint-debug.json";
    write_config(
        config,
        r#"{"server":"127.0.0.1:1","uuid":"00000000-0000-0000-0000-000000000001","password":"password","sni":"localhost","allow_insecure":true,"log_level":"debug"}"#,
    );
    let output = run_bin("zuicity-client", &["run", "-c", config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(combined.contains("run.go:118"), "output={combined:?}");
    assert!(
        combined
            .contains("Please fill in at least one of `listen` and `forward` in the config file."),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("either listen or forward is required"),
        "output={combined:?}"
    );
}

#[test]
fn client_run_invalid_uuid_fails_like_upstream_runtime() {
    let config = "/tmp/zuicity-client-run-invalid-uuid.json";
    write_config(
        config,
        r#"{"server":"127.0.0.1:1","uuid":"not-a-uuid","password":"password","sni":"localhost","allow_insecure":true,"listen":"127.0.0.1:0","log_level":"debug"}"#,
    );
    let output = run_bin("zuicity-client", &["run", "-c", config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(combined.contains("run.go:63"), "output={combined:?}");
    assert!(
        combined.contains(r#"error="parse UUID: invalid UUID length: 10""#),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(!combined.contains("parse uuid:"), "output={combined:?}");
}

#[test]
fn client_run_invalid_pinned_certchain_hash_fails_like_upstream_runtime() {
    let config = "/tmp/zuicity-client-run-invalid-pinned-certchain.json";
    write_config(
        config,
        r#"{"server":"127.0.0.1:1","uuid":"00000000-0000-0000-0000-000000000001","password":"password","sni":"localhost","allow_insecure":true,"listen":"127.0.0.1:0","log_level":"debug","pinned_certchain_sha256":"@@@"}"#,
    );
    let output = run_bin("zuicity-client", &["run", "-c", config]);
    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("FTL"), "output={combined:?}");
    assert!(combined.contains("run.go:63"), "output={combined:?}");
    assert!(
        combined.contains(r#"error="failed to decode PinnedCertChainSha256""#),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("Failed to read config"),
        "output={combined:?}"
    );
    assert!(
        !combined.contains("failed to decode pinned_certchain_sha256"),
        "output={combined:?}"
    );
}

#[test]
fn client_run_tcp_forward_reaches_rust_server_echo() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let artifact = zuicity_testkit::artifact_dir("cli client run tcp relay")
                .create()
                .expect("create artifact dir");
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved_server =
                zuicity_testkit::reserve_udp_socket().expect("reserve server UDP port");
            let server_addr = reserved_server.local_addr().expect("server local addr");
            drop(reserved_server);

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let server_config = zuicity_config::validate_server(
                zuicity_config::load_json_str(&format!(
                    r#"{{"listen":"{}","users":{{"{}":"{}"}}}}"#,
                    server_addr, uuid, password
                ))
                .expect("parse server config"),
            )
            .expect("validate server config");
            let runtime = zuicity_server::ServerRuntime::new(
                zuicity_server::ServerRuntimeConfig::from_config(server_config),
            );
            let cert_pem = std::fs::read(&cert.cert_path).expect("read cert PEM");
            let key_pem = std::fs::read(&cert.key_path).expect("read key PEM");
            let bound = runtime
                .bind_with_pem(server_addr, &cert_pem, &key_pem)
                .expect("bind rust server runtime");
            let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel();
            let server_task = tokio::spawn(async move {
                bound
                    .run_tcp_proxy_loop_until(async {
                        let _ = server_shutdown_rx.await;
                    })
                    .await
            });

            let echo = zuicity_testkit::TcpEchoServer::start()
                .await
                .expect("start TCP echo fixture");
            let reserved_forward =
                zuicity_testkit::reserve_tcp_listener().expect("reserve client forward TCP port");
            let forward_addr = reserved_forward.local_addr().expect("forward local addr");
            drop(reserved_forward);

            let config_path = artifact.path().join("client.json");
            write_config(
                config_path.to_str().expect("utf8 config path"),
                &format!(
                    r#"{{"server":"{}","uuid":"{}","password":"{}","sni":"localhost","allow_insecure":true,"log_level":"debug","forward":{{"{}/tcp":"{}"}}}}"#,
                    server_addr,
                    uuid,
                    password,
                    forward_addr,
                    echo.local_addr()
                ),
            );

            let bin = env!("CARGO_BIN_EXE_zuicity-client");
            let log_path = artifact.path().join("zuicity-client.log");
            let mut process = zuicity_testkit::ManagedProcessBuilder::new(bin)
                .arg("run")
                .arg("-c")
                .arg(config_path.to_str().expect("utf8 config path"))
                .log_path(&log_path)
                .start()
                .expect("spawn zuicity-client run");

            let payload = b"cli client tcp forward relay";
            let mut stream = connect_tcp_with_retry(forward_addr, &process).await;
            stream.write_all(payload).await.expect("write payload");
            stream.shutdown().await.expect("shutdown write half");
            let mut echoed = Vec::new();
            tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut echoed))
                .await
                .expect("TCP forward echo timeout")
                .expect("read echoed payload");
            assert_eq!(echoed, payload);

            let evidence = format!(
                "artifact_dir={}\nclient_forward={}\nrust_server={}\necho={}\nclient_log={}\nconfig={}\n",
                artifact.path().display(),
                forward_addr,
                server_addr,
                echo.local_addr(),
                log_path.display(),
                config_path.display()
            );
            std::fs::write(artifact.path().join("addresses.txt"), &evidence)
                .expect("write addresses evidence");
            std::fs::create_dir_all("/tmp/zuicity-workspace")
                .expect("create workspace evidence dir");
            std::fs::write(
                "/tmp/zuicity-workspace/client-run-tcp-forward-relay-artifacts.txt",
                evidence,
            )
            .expect("write workspace evidence");

            let exit = process
                .terminate(Duration::from_secs(2))
                .expect("terminate zuicity-client run");
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            assert!(
                !log.contains("runtime is not implemented"),
                "exit={exit:?}; log={log:?}"
            );

            server_shutdown_tx
                .send(())
                .expect("send server shutdown signal");
            let server_report = server_task
                .await
                .expect("join rust server task")
                .expect("rust server loop succeeds");
            assert_eq!(server_report.accepted_connections, 1);
            assert_eq!(server_report.completed_tcp_relays, 1);
            assert_eq!(server_report.bytes_from_client, payload.len() as u64);
            assert_eq!(server_report.bytes_from_target, payload.len() as u64);
            echo.shutdown().await.expect("shutdown TCP echo fixture");
        });
}

#[test]
fn client_run_valid_forward_config_starts_runtime_without_placeholder() {
    let config = "/tmp/zuicity-client-run-valid-forward.json";
    write_config(
        config,
        r#"{"server":"127.0.0.1:1","uuid":"00000000-0000-0000-0000-000000000001","password":"password","sni":"localhost","allow_insecure":true,"forward":{"127.0.0.1:0/tcp":"127.0.0.1:1"}}"#,
    );
    assert_stays_running_without_placeholder("zuicity-client", config);
}

#[test]
fn client_run_http_connect_reaches_rust_server_echo() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let artifact = zuicity_testkit::artifact_dir("cli client run http connect relay")
                .create()
                .expect("create artifact dir");
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved_server =
                zuicity_testkit::reserve_udp_socket().expect("reserve server UDP port");
            let server_addr = reserved_server.local_addr().expect("server local addr");
            drop(reserved_server);

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let server_config = zuicity_config::validate_server(
                zuicity_config::load_json_str(&format!(
                    r#"{{"listen":"{}","users":{{"{}":"{}"}}}}"#,
                    server_addr, uuid, password
                ))
                .expect("parse server config"),
            )
            .expect("validate server config");
            let runtime = zuicity_server::ServerRuntime::new(
                zuicity_server::ServerRuntimeConfig::from_config(server_config),
            );
            let cert_pem = std::fs::read(&cert.cert_path).expect("read cert PEM");
            let key_pem = std::fs::read(&cert.key_path).expect("read key PEM");
            let bound = runtime
                .bind_with_pem(server_addr, &cert_pem, &key_pem)
                .expect("bind rust server runtime");
            let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel();
            let server_task = tokio::spawn(async move {
                bound
                    .run_tcp_proxy_loop_until(async {
                        let _ = server_shutdown_rx.await;
                    })
                    .await
            });

            let echo = zuicity_testkit::TcpEchoServer::start()
                .await
                .expect("start TCP echo fixture");
            let (reserved_listener, reserved_listener_udp) = zuicity_testkit::reserve_tcp_udp_pair()
                .expect("reserve client mixed listen TCP/UDP port");
            let listen_addr = reserved_listener.local_addr().expect("client listen local addr");
            drop(reserved_listener);
            drop(reserved_listener_udp);

            let config_path = artifact.path().join("client.json");
            write_config(
                config_path.to_str().expect("utf8 config path"),
                &format!(
                    r#"{{"listen":"{}","server":"{}","uuid":"{}","password":"{}","sni":"localhost","allow_insecure":true,"log_level":"debug"}}"#,
                    listen_addr, server_addr, uuid, password
                ),
            );

            let bin = env!("CARGO_BIN_EXE_zuicity-client");
            let log_path = artifact.path().join("zuicity-client.log");
            let mut process = zuicity_testkit::ManagedProcessBuilder::new(bin)
                .arg("run")
                .arg("-c")
                .arg(config_path.to_str().expect("utf8 config path"))
                .log_path(&log_path)
                .start()
                .expect("spawn zuicity-client run");

            let echo_addr = echo.local_addr();
            let mut stream = connect_tcp_with_retry(listen_addr, &process).await;
            stream
                .write_all(format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n").as_bytes())
                .await
                .expect("write HTTP CONNECT request");
            let mut response = Vec::new();
            let mut byte = [0_u8; 1];
            while !response.ends_with(b"\r\n\r\n") {
                tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut byte))
                    .await
                    .expect("HTTP CONNECT response timeout")
                    .expect("read HTTP CONNECT response");
                response.push(byte[0]);
            }
            assert_eq!(response, b"HTTP/1.1 200 Connection established\r\n\r\n");

            let payload = b"cli client http connect relay";
            stream.write_all(payload).await.expect("write payload");
            stream.shutdown().await.expect("shutdown write half");
            let mut echoed = Vec::new();
            tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut echoed))
                .await
                .expect("HTTP CONNECT echo timeout")
                .expect("read echoed payload");
            assert_eq!(echoed, payload);

            let evidence = format!(
                "artifact_dir={}\nclient_listen={}\nrust_server={}\necho={}\nclient_log={}\nconfig={}\n",
                artifact.path().display(),
                listen_addr,
                server_addr,
                echo_addr,
                log_path.display(),
                config_path.display()
            );
            std::fs::write(artifact.path().join("addresses.txt"), &evidence)
                .expect("write addresses evidence");
            std::fs::create_dir_all("/tmp/zuicity-workspace")
                .expect("create workspace evidence dir");
            std::fs::write(
                "/tmp/zuicity-workspace/client-run-http-connect-relay-artifacts.txt",
                evidence,
            )
            .expect("write workspace evidence");

            let exit = process
                .terminate(Duration::from_secs(2))
                .expect("terminate zuicity-client run");
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            assert!(
                !log.contains("runtime is not implemented"),
                "exit={exit:?}; log={log:?}"
            );

            server_shutdown_tx
                .send(())
                .expect("send server shutdown signal");
            let server_report = server_task
                .await
                .expect("join rust server task")
                .expect("rust server loop succeeds");
            assert_eq!(server_report.accepted_connections, 1);
            assert_eq!(server_report.completed_tcp_relays, 1);
            assert_eq!(server_report.bytes_from_client, payload.len() as u64);
            assert_eq!(server_report.bytes_from_target, payload.len() as u64);
            echo.shutdown().await.expect("shutdown TCP echo fixture");
        });
}

#[test]
fn client_run_socks5_connect_reaches_rust_server_echo() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let artifact = zuicity_testkit::artifact_dir("cli client run socks5 connect relay")
                .create()
                .expect("create artifact dir");
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved_server =
                zuicity_testkit::reserve_udp_socket().expect("reserve server UDP port");
            let server_addr = reserved_server.local_addr().expect("server local addr");
            drop(reserved_server);

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let server_config = zuicity_config::validate_server(
                zuicity_config::load_json_str(&format!(
                    r#"{{"listen":"{}","users":{{"{}":"{}"}}}}"#,
                    server_addr, uuid, password
                ))
                .expect("parse server config"),
            )
            .expect("validate server config");
            let runtime = zuicity_server::ServerRuntime::new(
                zuicity_server::ServerRuntimeConfig::from_config(server_config),
            );
            let cert_pem = std::fs::read(&cert.cert_path).expect("read cert PEM");
            let key_pem = std::fs::read(&cert.key_path).expect("read key PEM");
            let bound = runtime
                .bind_with_pem(server_addr, &cert_pem, &key_pem)
                .expect("bind rust server runtime");
            let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel();
            let server_task = tokio::spawn(async move {
                bound
                    .run_tcp_proxy_loop_until(async {
                        let _ = server_shutdown_rx.await;
                    })
                    .await
            });

            let echo = zuicity_testkit::TcpEchoServer::start()
                .await
                .expect("start TCP echo fixture");
            let (reserved_listener, reserved_listener_udp) = zuicity_testkit::reserve_tcp_udp_pair()
                .expect("reserve client mixed listen TCP/UDP port");
            let listen_addr = reserved_listener.local_addr().expect("client listen local addr");
            drop(reserved_listener);
            drop(reserved_listener_udp);

            let config_path = artifact.path().join("client.json");
            write_config(
                config_path.to_str().expect("utf8 config path"),
                &format!(
                    r#"{{"listen":"{}","server":"{}","uuid":"{}","password":"{}","sni":"localhost","allow_insecure":true,"log_level":"debug"}}"#,
                    listen_addr, server_addr, uuid, password
                ),
            );

            let bin = env!("CARGO_BIN_EXE_zuicity-client");
            let log_path = artifact.path().join("zuicity-client.log");
            let mut process = zuicity_testkit::ManagedProcessBuilder::new(bin)
                .arg("run")
                .arg("-c")
                .arg(config_path.to_str().expect("utf8 config path"))
                .log_path(&log_path)
                .start()
                .expect("spawn zuicity-client run");

            let echo_addr = echo.local_addr();
            let mut stream = connect_tcp_with_retry(listen_addr, &process).await;
            stream
                .write_all(&[0x05, 0x01, 0x00])
                .await
                .expect("write SOCKS5 greeting");
            let mut greeting_response = [0_u8; 2];
            tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut greeting_response))
                .await
                .expect("SOCKS5 greeting timeout")
                .expect("read SOCKS5 greeting response");
            assert_eq!(greeting_response, [0x05, 0x00]);

            let std::net::SocketAddr::V4(echo_v4) = echo_addr else {
                panic!("TCP echo fixture should bind IPv4 loopback")
            };
            let mut request = vec![0x05, 0x01, 0x00, 0x01];
            request.extend_from_slice(&echo_v4.ip().octets());
            request.extend_from_slice(&echo_v4.port().to_be_bytes());
            stream
                .write_all(&request)
                .await
                .expect("write SOCKS5 CONNECT request");
            let mut connect_response = [0_u8; 10];
            tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut connect_response))
                .await
                .expect("SOCKS5 CONNECT response timeout")
                .expect("read SOCKS5 CONNECT response");
            assert_eq!(connect_response, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

            let payload = b"cli client socks5 connect relay";
            stream.write_all(payload).await.expect("write payload");
            stream.shutdown().await.expect("shutdown write half");
            let mut echoed = Vec::new();
            tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut echoed))
                .await
                .expect("SOCKS5 CONNECT echo timeout")
                .expect("read echoed payload");
            assert_eq!(echoed, payload);

            let evidence = format!(
                "artifact_dir={}\nclient_listen={}\nrust_server={}\necho={}\nclient_log={}\nconfig={}\n",
                artifact.path().display(),
                listen_addr,
                server_addr,
                echo_addr,
                log_path.display(),
                config_path.display()
            );
            std::fs::write(artifact.path().join("addresses.txt"), &evidence)
                .expect("write addresses evidence");
            std::fs::create_dir_all("/tmp/zuicity-workspace")
                .expect("create workspace evidence dir");
            std::fs::write(
                "/tmp/zuicity-workspace/client-run-socks5-connect-relay-artifacts.txt",
                evidence,
            )
            .expect("write workspace evidence");

            let exit = process
                .terminate(Duration::from_secs(2))
                .expect("terminate zuicity-client run");
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            assert!(
                !log.contains("runtime is not implemented"),
                "exit={exit:?}; log={log:?}"
            );

            server_shutdown_tx
                .send(())
                .expect("send server shutdown signal");
            let server_report = server_task
                .await
                .expect("join rust server task")
                .expect("rust server loop succeeds");
            assert_eq!(server_report.accepted_connections, 1);
            assert_eq!(server_report.completed_tcp_relays, 1);
            assert_eq!(server_report.bytes_from_client, payload.len() as u64);
            assert_eq!(server_report.bytes_from_target, payload.len() as u64);
            echo.shutdown().await.expect("shutdown TCP echo fixture");
        });
}

#[test]
fn client_run_socks5_udp_associate_reaches_rust_server_echo() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let artifact = zuicity_testkit::artifact_dir("cli client run socks5 udp associate")
                .create()
                .expect("create artifact dir");
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved_server =
                zuicity_testkit::reserve_udp_socket().expect("reserve server UDP port");
            let server_addr = reserved_server.local_addr().expect("server local addr");
            drop(reserved_server);

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let server_config = zuicity_config::validate_server(
                zuicity_config::load_json_str(&format!(
                    r#"{{"listen":"{}","users":{{"{}":"{}"}}}}"#,
                    server_addr, uuid, password
                ))
                .expect("parse server config"),
            )
            .expect("validate server config");
            let runtime = zuicity_server::ServerRuntime::new(
                zuicity_server::ServerRuntimeConfig::from_config(server_config),
            );
            let cert_pem = std::fs::read(&cert.cert_path).expect("read cert PEM");
            let key_pem = std::fs::read(&cert.key_path).expect("read key PEM");
            let bound = runtime
                .bind_with_pem(server_addr, &cert_pem, &key_pem)
                .expect("bind rust server runtime");
            let server_task = tokio::spawn(async move { bound.accept_one_udp_over_stream().await });

            let echo = zuicity_testkit::UdpEchoServer::start()
                .await
                .expect("start UDP echo fixture");
            let (reserved_listener, reserved_listener_udp) = zuicity_testkit::reserve_tcp_udp_pair()
                .expect("reserve client mixed listen TCP/UDP port");
            let listen_addr = reserved_listener.local_addr().expect("client listen local addr");
            drop(reserved_listener);
            drop(reserved_listener_udp);

            let config_path = artifact.path().join("client.json");
            write_config(
                config_path.to_str().expect("utf8 config path"),
                &format!(
                    r#"{{"listen":"{}","server":"{}","uuid":"{}","password":"{}","sni":"localhost","allow_insecure":true,"log_level":"debug"}}"#,
                    listen_addr, server_addr, uuid, password
                ),
            );

            let bin = env!("CARGO_BIN_EXE_zuicity-client");
            let log_path = artifact.path().join("zuicity-client.log");
            let mut process = zuicity_testkit::ManagedProcessBuilder::new(bin)
                .arg("run")
                .arg("-c")
                .arg(config_path.to_str().expect("utf8 config path"))
                .log_path(&log_path)
                .start()
                .expect("spawn zuicity-client run");

            let echo_addr = echo.local_addr();
            let mut control = connect_tcp_with_retry(listen_addr, &process).await;
            control
                .write_all(&[0x05, 0x01, 0x00])
                .await
                .expect("write SOCKS5 greeting");
            let mut greeting_response = [0_u8; 2];
            tokio::time::timeout(Duration::from_secs(3), control.read_exact(&mut greeting_response))
                .await
                .expect("SOCKS5 greeting timeout")
                .expect("read SOCKS5 greeting response");
            assert_eq!(greeting_response, [0x05, 0x00]);

            control
                .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .expect("write SOCKS5 UDP ASSOCIATE request");
            let mut associate_response = [0_u8; 10];
            tokio::time::timeout(Duration::from_secs(3), control.read_exact(&mut associate_response))
                .await
                .expect("SOCKS5 UDP ASSOCIATE response timeout")
                .expect("read SOCKS5 UDP ASSOCIATE response");
            assert_eq!(&associate_response[..4], &[0x05, 0x00, 0x00, 0x01]);
            let associate_addr = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    associate_response[4],
                    associate_response[5],
                    associate_response[6],
                    associate_response[7],
                )),
                u16::from_be_bytes([associate_response[8], associate_response[9]]),
            );
            assert_eq!(associate_addr.port(), listen_addr.port());

            let std::net::SocketAddr::V4(echo_v4) = echo_addr else {
                panic!("UDP echo fixture should bind IPv4 loopback")
            };
            let payload = b"cli client socks5 udp associate";
            let mut udp_request = vec![0x00, 0x00, 0x00, 0x01];
            udp_request.extend_from_slice(&echo_v4.ip().octets());
            udp_request.extend_from_slice(&echo_v4.port().to_be_bytes());
            udp_request.extend_from_slice(payload);

            let udp_client = tokio::net::UdpSocket::bind(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                0,
            )))
            .await
            .expect("bind local UDP client");
            udp_client
                .send_to(&udp_request, associate_addr)
                .await
                .expect("send SOCKS5 UDP datagram");
            let mut response = [0_u8; 1024];
            let (received, from) =
                tokio::time::timeout(Duration::from_secs(3), udp_client.recv_from(&mut response))
                    .await
                    .expect("SOCKS5 UDP associate response timeout")
                    .expect("receive SOCKS5 UDP associate response");
            assert_eq!(from, associate_addr);
            assert_eq!(&response[..4], &[0x00, 0x00, 0x00, 0x01]);
            assert_eq!(&response[4..8], &echo_v4.ip().octets());
            assert_eq!(
                u16::from_be_bytes([response[8], response[9]]),
                echo_v4.port()
            );
            assert_eq!(&response[10..received], payload);

            let evidence = format!(
                "artifact_dir={}\nclient_listen={}\nassociate={}\nrust_server={}\necho={}\nclient_log={}\nconfig={}\n",
                artifact.path().display(),
                listen_addr,
                associate_addr,
                server_addr,
                echo_addr,
                log_path.display(),
                config_path.display()
            );
            std::fs::write(artifact.path().join("addresses.txt"), &evidence)
                .expect("write addresses evidence");
            std::fs::create_dir_all("/tmp/zuicity-workspace")
                .expect("create workspace evidence dir");
            std::fs::write(
                "/tmp/zuicity-workspace/client-run-socks5-udp-associate-artifacts.txt",
                evidence,
            )
            .expect("write workspace evidence");

            control.shutdown().await.expect("shutdown SOCKS5 control");
            let server_report = tokio::time::timeout(Duration::from_secs(5), server_task)
                .await
                .expect("server UDP relay task timeout")
                .expect("join rust server task")
                .expect("rust server UDP relay succeeds");
            assert_eq!(server_report.target, echo_addr);
            assert_eq!(server_report.bytes_from_client, payload.len() as u64);
            assert_eq!(server_report.bytes_from_target, payload.len() as u64);

            let exit = process
                .terminate(Duration::from_secs(2))
                .expect("terminate zuicity-client run");
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            assert!(
                !log.contains("runtime is not implemented"),
                "exit={exit:?}; log={log:?}"
            );
            echo.shutdown().await.expect("shutdown UDP echo fixture");
        });
}

#[test]
fn client_run_unknown_congestion_control_starts_like_upstream() {
    let config = "/tmp/zuicity-client-run-unknown-congestion.json";
    write_config(
        config,
        r#"{"listen":"127.0.0.1:0","server":"127.0.0.1:1","uuid":"00000000-0000-0000-0000-000000000001","password":"password","sni":"localhost","allow_insecure":true,"congestion_control":"bogus","log_level":"debug"}"#,
    );
    assert_stays_running_without_placeholder("zuicity-client", config);
}

#[test]
fn client_run_listen_without_server_starts_like_upstream() {
    let config = "/tmp/zuicity-client-run-listen-without-server.json";
    write_config(
        config,
        r#"{"listen":"127.0.0.1:0","uuid":"00000000-0000-0000-0000-000000000001","password":"password","sni":"localhost","allow_insecure":true,"log_level":"debug"}"#,
    );
    assert_stays_running_without_placeholder("zuicity-client", config);
}

#[test]
fn client_run_valid_listen_config_starts_mixed_listener_without_placeholder() {
    let config = "/tmp/zuicity-client-run-valid-listen.json";
    write_config(
        config,
        r#"{"listen":"127.0.0.1:0","server":"127.0.0.1:1","uuid":"00000000-0000-0000-0000-000000000001","password":"password","sni":"localhost","allow_insecure":true}"#,
    );
    assert_stays_running_without_placeholder("zuicity-client", config);
}

#[test]
fn client_run_valid_listen_config_logs_upstream_mixed_listener_ready() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    let artifact = zuicity_testkit::artifact_dir("cli client mixed ready log")
        .create()
        .expect("create artifact dir");
    let (reserved_listener, reserved_listener_udp) =
        zuicity_testkit::reserve_tcp_udp_pair().expect("reserve client mixed listen TCP/UDP port");
    let listen_addr = reserved_listener
        .local_addr()
        .expect("reserved listener addr");
    drop(reserved_listener_udp);
    drop(reserved_listener);

    let config_path = artifact.path().join("client.json");
    write_config(
        config_path.to_str().expect("utf8 config path"),
        &format!(
            r#"{{"listen":"{}","server":"127.0.0.1:1","uuid":"00000000-0000-0000-0000-000000000001","password":"password","sni":"localhost","allow_insecure":true,"log_level":"debug"}}"#,
            listen_addr
        ),
    );

    let bin = env!("CARGO_BIN_EXE_zuicity-client");
    let log_path = artifact.path().join("zuicity-client.log");
    let mut process = zuicity_testkit::ManagedProcessBuilder::new(bin)
        .arg("run")
        .arg("-c")
        .arg(config_path.to_str().expect("utf8 config path"))
        .arg("--log-disable-timestamp")
        .log_path(&log_path)
        .start()
        .expect("spawn zuicity-client run");

    let expected = format!("[mixed] http & socks5 server listening TCP on {listen_addr}");
    process
        .wait_for_log_contains(&expected, Duration::from_secs(2))
        .unwrap_or_else(|error| {
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            panic!("missing mixed ready log {expected:?}: {error}; log={log:?}");
        });
    let exit = process
        .terminate(Duration::from_secs(2))
        .expect("terminate zuicity-client run");
    assert_eq!(exit.pid, process.pid());
    assert!(
        !exit.forced,
        "zuicity-client should handle termination without SIGKILL"
    );

    let evidence = format!(
        "artifact_dir={}\nlisten={}\nclient_log={}\nconfig={}\n",
        artifact.path().display(),
        listen_addr,
        log_path.display(),
        config_path.display()
    );
    std::fs::write(artifact.path().join("addresses.txt"), &evidence)
        .expect("write addresses evidence");
    std::fs::create_dir_all("/tmp/zuicity-workspace/logging-mixed")
        .expect("create workspace evidence dir");
    std::fs::write(
        "/tmp/zuicity-workspace/logging-mixed/client-mixed-ready-log-artifacts.txt",
        evidence,
    )
    .expect("write workspace evidence");
}

#[test]
fn client_run_valid_listen_config_handles_sigterm_like_upstream() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    let artifact = zuicity_testkit::artifact_dir("cli client run sigterm")
        .create()
        .expect("create artifact dir");
    let (reserved_listener, reserved_listener_udp) =
        zuicity_testkit::reserve_tcp_udp_pair().expect("reserve client mixed listen TCP/UDP port");
    let listen_addr = reserved_listener
        .local_addr()
        .expect("reserved listener addr");
    drop(reserved_listener_udp);
    drop(reserved_listener);

    let config_path = artifact.path().join("client.json");
    write_config(
        config_path.to_str().expect("utf8 config path"),
        &format!(
            r#"{{"listen":"{}","server":"127.0.0.1:1","uuid":"00000000-0000-0000-0000-000000000001","password":"password","sni":"localhost","allow_insecure":true,"log_level":"debug"}}"#,
            listen_addr
        ),
    );

    let bin = env!("CARGO_BIN_EXE_zuicity-client");
    let log_path = artifact.path().join("zuicity-client.log");
    let mut process = zuicity_testkit::ManagedProcessBuilder::new(bin)
        .arg("run")
        .arg("-c")
        .arg(config_path.to_str().expect("utf8 config path"))
        .arg("--log-disable-timestamp")
        .log_path(&log_path)
        .start()
        .expect("spawn zuicity-client run");

    let ready = format!("[mixed] http & socks5 server listening TCP on {listen_addr}");
    process
        .wait_for_log_contains(&ready, Duration::from_secs(2))
        .unwrap_or_else(|error| {
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            panic!("missing mixed ready log {ready:?}: {error}; log={log:?}");
        });
    let exit = process
        .terminate(Duration::from_secs(2))
        .expect("terminate zuicity-client run");
    assert_eq!(exit.pid, process.pid());
    assert!(!exit.forced, "zuicity-client should not need SIGKILL");
    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(exit.status.success(), "exit={exit:?}; log={log:?}");
    assert!(
        log.contains("Exiting"),
        "missing upstream Exiting log: {log:?}"
    );

    let evidence = format!(
        "artifact_dir={}\nlisten={}\nclient_log={}\nconfig={}\nexit={:?}\n",
        artifact.path().display(),
        listen_addr,
        log_path.display(),
        config_path.display(),
        exit
    );
    std::fs::write(artifact.path().join("sigterm.txt"), &evidence).expect("write SIGTERM evidence");
    std::fs::create_dir_all("/tmp/zuicity-workspace/client-signal")
        .expect("create workspace evidence dir");
    std::fs::write(
        "/tmp/zuicity-workspace/client-signal/client-run-sigterm-artifacts.txt",
        evidence,
    )
    .expect("write workspace evidence");
}

#[test]
fn client_run_forward_only_config_handles_sigterm_like_upstream() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    let artifact = zuicity_testkit::artifact_dir("cli client forward sigterm")
        .create()
        .expect("create artifact dir");
    let (reserved_forward, _reserved_forward_udp) =
        zuicity_testkit::reserve_tcp_udp_pair().expect("reserve client forward TCP/UDP port");
    let forward_addr = reserved_forward
        .local_addr()
        .expect("reserved forward addr");
    drop(reserved_forward);

    let config_path = artifact.path().join("client.json");
    write_config(
        config_path.to_str().expect("utf8 config path"),
        &format!(
            r#"{{"server":"127.0.0.1:1","uuid":"00000000-0000-0000-0000-000000000001","password":"password","sni":"localhost","allow_insecure":true,"log_level":"debug","forward":{{"{}/tcp":"127.0.0.1:9"}}}}"#,
            forward_addr
        ),
    );

    let bin = env!("CARGO_BIN_EXE_zuicity-client");
    let log_path = artifact.path().join("zuicity-client.log");
    let mut process = zuicity_testkit::ManagedProcessBuilder::new(bin)
        .arg("run")
        .arg("-c")
        .arg(config_path.to_str().expect("utf8 config path"))
        .arg("--log-disable-timestamp")
        .log_path(&log_path)
        .start()
        .expect("spawn zuicity-client run");

    for attempt in 0..50 {
        if tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime")
            .block_on(tokio::net::TcpStream::connect(forward_addr))
            .is_ok()
        {
            break;
        }
        if attempt == 49 {
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            panic!("client forward listener did not become ready; log={log:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let exit = process
        .terminate(Duration::from_secs(2))
        .expect("terminate zuicity-client forward run");
    assert_eq!(exit.pid, process.pid());
    assert!(
        !exit.forced,
        "zuicity-client forward run should not need SIGKILL"
    );
    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(exit.status.success(), "exit={exit:?}; log={log:?}");
    assert!(
        log.contains("Exiting"),
        "missing upstream Exiting log: {log:?}"
    );

    let evidence = format!(
        "artifact_dir={}\nforward={}\nclient_log={}\nconfig={}\nexit={:?}\n",
        artifact.path().display(),
        forward_addr,
        log_path.display(),
        config_path.display(),
        exit
    );
    std::fs::write(artifact.path().join("forward-sigterm.txt"), &evidence)
        .expect("write forward SIGTERM evidence");
    std::fs::create_dir_all("/tmp/zuicity-workspace/client-signal")
        .expect("create workspace evidence dir");
    std::fs::write(
        "/tmp/zuicity-workspace/client-signal/client-forward-sigterm-artifacts.txt",
        evidence,
    )
    .expect("write workspace evidence");
}

#[test]
fn server_run_valid_config_starts_runtime_without_placeholder() {
    let dir = "/tmp/zuicity-server-run-valid";
    std::fs::create_dir_all(dir).expect("create server fixture dir");
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("generate cert");
    let cert_path = format!("{dir}/fullchain.pem");
    let key_path = format!("{dir}/private.key");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
    let config = format!("{dir}/server.json");
    write_config(
        &config,
        &format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"00000000-0000-0000-0000-000000000001":"password"}},"certificate":"{}","private_key":"{}"}}"#,
            cert_path, key_path
        ),
    );
    assert_stays_running_without_placeholder("zuicity-server", &config);
}

#[test]
fn server_run_unknown_congestion_control_starts_like_upstream() {
    let dir = "/tmp/zuicity-server-run-unknown-congestion";
    std::fs::create_dir_all(dir).expect("create server fixture dir");
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("generate cert");
    let cert_path = format!("{dir}/fullchain.pem");
    let key_path = format!("{dir}/private.key");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
    let config = format!("{dir}/server.json");
    write_config(
        &config,
        &format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"00000000-0000-0000-0000-000000000001":"password"}},"certificate":"{}","private_key":"{}","congestion_control":"bogus"}}"#,
            cert_path, key_path
        ),
    );
    assert_stays_running_without_placeholder("zuicity-server", &config);
}

#[test]
fn server_run_sigterm_exits_successfully_without_force() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            let artifact = zuicity_testkit::artifact_dir("cli server run sigterm")
                .create()
                .expect("create artifact dir");
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved = zuicity_testkit::reserve_udp_socket().expect("reserve server UDP port");
            let server_addr = reserved.local_addr().expect("server local addr");
            drop(reserved);

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let config_path = artifact.path().join("server.json");
            write_config(
                config_path.to_str().expect("utf8 config path"),
                &format!(
                    r#"{{"listen":"{}","users":{{"{}":"{}"}},"certificate":"{}","private_key":"{}"}}"#,
                    server_addr,
                    uuid,
                    password,
                    cert.cert_path.display(),
                    cert.key_path.display()
                ),
            );

            let bin = env!("CARGO_BIN_EXE_zuicity-server");
            let log_path = artifact.path().join("zuicity-server.log");
            let mut process = zuicity_testkit::ManagedProcessBuilder::new(bin)
                .arg("run")
                .arg("-c")
                .arg(config_path.to_str().expect("utf8 config path"))
                .log_path(&log_path)
                .start()
                .expect("spawn zuicity-server run");
            assert_ne!(process.pid(), 0);
            assert_eq!(process.log_path(), log_path.as_path());

            let roots_pem = std::fs::read(&cert.cert_path).expect("read cert roots");
            let _connection = connect_managed_with_retry(
                server_addr,
                &roots_pem,
                uuid,
                password.as_bytes(),
                &process,
            )
            .await;

            let exit = process
                .terminate(Duration::from_secs(2))
                .expect("terminate zuicity-server run");
            assert_eq!(exit.pid, process.pid());
            assert!(!exit.forced, "zuicity-server should handle SIGTERM without SIGKILL");
            assert!(exit.status.success(), "exit={exit:?}; log={}", log_path.display());
        });
}

#[test]
fn server_run_relay_tcp_proxy_from_rust_client() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            let artifact = zuicity_testkit::artifact_dir("cli server run tcp relay")
                .create()
                .expect("create artifact dir");
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved = zuicity_testkit::reserve_udp_socket().expect("reserve server UDP port");
            let server_addr = reserved.local_addr().expect("server local addr");
            drop(reserved);

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let config_path = artifact.path().join("server.json");
            write_config(
                config_path.to_str().expect("utf8 config path"),
                &format!(
                    r#"{{"listen":"{}","users":{{"{}":"{}"}},"certificate":"{}","private_key":"{}","log_level":"debug"}}"#,
                    server_addr,
                    uuid,
                    password,
                    cert.cert_path.display(),
                    cert.key_path.display()
                ),
            );

            let echo = zuicity_testkit::TcpEchoServer::start()
                .await
                .expect("start TCP echo fixture");
            let bin = env!("CARGO_BIN_EXE_zuicity-server");
            let log_path = artifact.path().join("zuicity-server.log");
            let mut process = zuicity_testkit::ManagedProcessBuilder::new(bin)
                .arg("run")
                .arg("-c")
                .arg(config_path.to_str().expect("utf8 config path"))
                .log_path(&log_path)
                .start()
                .expect("spawn zuicity-server run");

            let roots_pem = std::fs::read(&cert.cert_path).expect("read cert roots");
            let connection = connect_managed_with_retry(
                server_addr,
                &roots_pem,
                uuid,
                password.as_bytes(),
                &process,
            )
            .await;

            let payload = b"cli server tcp relay";
            let echo_addr = echo.local_addr();
            let mut stream = connection
                .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
                .await
                .expect("open TCP proxy stream");
            stream.write_all(payload).await.expect("write TCP payload");
            stream.finish().expect("finish TCP proxy stream");
            let echoed = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(1024))
                .await
                .expect("TCP proxy echo timeout")
                .expect("read echoed TCP payload");
            assert_eq!(echoed, payload);

            let evidence = format!(
                "artifact_dir={}\nserver={}\necho={}\nserver_log={}\nconfig={}\n",
                artifact.path().display(),
                server_addr,
                echo_addr,
                log_path.display(),
                config_path.display()
            );
            std::fs::write(artifact.path().join("addresses.txt"), &evidence)
                .expect("write addresses evidence");
            std::fs::create_dir_all("/tmp/zuicity-workspace")
                .expect("create workspace evidence dir");
            std::fs::write(
                "/tmp/zuicity-workspace/server-run-tcp-relay-artifacts.txt",
                evidence,
            )
            .expect("write workspace evidence");

            echo.shutdown().await.expect("shutdown TCP echo fixture");
            let exit = process
                .terminate(Duration::from_secs(2))
                .expect("terminate zuicity-server run");
            assert_eq!(exit.pid, process.pid());
            assert!(!exit.forced, "zuicity-server should handle SIGTERM without SIGKILL");
            assert!(
                exit.status.success(),
                "exit={exit:?}; log={}",
                log_path.display()
            );
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            assert!(
                !log.contains("runtime is not implemented"),
                "exit={exit:?}; log={log:?}"
            );
        });
}

#[test]
fn rust_client_forwarder_reaches_spawned_upstream_server_run_tcp_echo() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let artifact = zuicity_testkit::artifact_dir("rust client spawned upstream server tcp")
                .create()
                .expect("create artifact dir");
            let upstream_server = upstream_server_binary(artifact.path());
            assert!(
                upstream_server.is_file(),
                "missing upstream juicity-server at {}",
                upstream_server.display()
            );
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved_server =
                zuicity_testkit::reserve_udp_socket().expect("reserve upstream server UDP port");
            let server_addr = reserved_server.local_addr().expect("server local addr");
            drop(reserved_server);
            let reserved_forward =
                zuicity_testkit::reserve_tcp_listener().expect("reserve rust forward TCP port");
            let forward_addr = reserved_forward.local_addr().expect("forward local addr");
            drop(reserved_forward);

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let server_config_path = artifact.path().join("upstream-server.json");
            write_config(
                server_config_path.to_str().expect("utf8 upstream server config path"),
                &format!(
                    r#"{{"listen":"{}","users":{{"{}":"{}"}},"certificate":"{}","private_key":"{}","log_level":"debug"}}"#,
                    server_addr,
                    uuid,
                    password,
                    cert.cert_path.display(),
                    cert.key_path.display()
                ),
            );
            let server_log_path = artifact.path().join("upstream-server.log");
            let mut server = zuicity_testkit::ManagedProcessBuilder::new(
                upstream_server.to_string_lossy().into_owned(),
            )
            .arg("run")
            .arg("-c")
            .arg(server_config_path.to_string_lossy().into_owned())
            .log_path(&server_log_path)
            .start()
            .expect("spawn upstream juicity-server run");

            let roots_pem = std::fs::read(&cert.cert_path).expect("read cert roots");
            let _ready = connect_managed_with_retry(
                server_addr,
                &roots_pem,
                uuid,
                password.as_bytes(),
                &server,
            )
            .await;

            let echo = zuicity_testkit::TcpEchoServer::start()
                .await
                .expect("start TCP echo fixture");
            let client_config_path = artifact.path().join("rust-client.json");
            write_config(
                client_config_path.to_str().expect("utf8 rust client config path"),
                &format!(
                    r#"{{"server":"{}","uuid":"{}","password":"{}","sni":"localhost","allow_insecure":true,"log_level":"debug","forward":{{"{}/tcp":"{}"}}}}"#,
                    server_addr,
                    uuid,
                    password,
                    forward_addr,
                    echo.local_addr()
                ),
            );
            let client_log_path = artifact.path().join("rust-client.log");
            let mut client = zuicity_testkit::ManagedProcessBuilder::new(env!(
                "CARGO_BIN_EXE_zuicity-client"
            ))
            .arg("run")
            .arg("-c")
            .arg(client_config_path.to_str().expect("utf8 rust client config path"))
            .log_path(&client_log_path)
            .start()
            .expect("spawn rust zuicity-client run");

            let payload = b"rust client spawned upstream server tcp";
            let mut stream = connect_tcp_with_retry(forward_addr, &client).await;
            stream.write_all(payload).await.expect("write payload");
            let mut echoed = vec![0_u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
                .await
                .expect("rust client TCP echo timeout")
                .expect("read echoed payload");
            assert_eq!(echoed, payload);
            stream.shutdown().await.expect("shutdown rust forward stream");

            let evidence = format!(
                "artifact_dir={}\nupstream_server={}\nrust_forwarder={}\necho={}\nupstream_server_log={}\nrust_client_log={}\nbuild_log={}\nserver_config={}\nclient_config={}\n",
                artifact.path().display(),
                server_addr,
                forward_addr,
                echo.local_addr(),
                server_log_path.display(),
                client_log_path.display(),
                artifact.path().join("upstream-server-build.log").display(),
                server_config_path.display(),
                client_config_path.display()
            );
            std::fs::write(artifact.path().join("addresses.txt"), &evidence)
                .expect("write addresses evidence");
            std::fs::create_dir_all("/tmp/zuicity-workspace")
                .expect("create workspace evidence dir");
            std::fs::write(
                "/tmp/zuicity-workspace/rust-client-spawned-upstream-server-tcp-artifacts.txt",
                evidence,
            )
            .expect("write workspace evidence");

            echo.shutdown().await.expect("shutdown TCP echo fixture");
            let client_exit = client
                .terminate(Duration::from_secs(2))
                .expect("terminate rust zuicity-client run");
            assert_eq!(client_exit.pid, client.pid());
            let server_exit = server
                .terminate(Duration::from_secs(2))
                .expect("terminate upstream juicity-server run");
            assert_eq!(server_exit.pid, server.pid());
            let client_log = std::fs::read_to_string(&client_log_path).unwrap_or_default();
            assert!(
                !client_log.contains("runtime is not implemented"),
                "client_exit={client_exit:?}; log={client_log:?}"
            );
        });
}

#[test]
fn rust_client_forwarder_reaches_spawned_upstream_server_run_tcp_echo_through_socks5_dialer_link() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let artifact = zuicity_testkit::artifact_dir("rust client upstream server tcp dialer link")
                .create()
                .expect("create artifact dir");
            let upstream_server = upstream_server_binary(artifact.path());
            assert!(
                upstream_server.is_file(),
                "missing upstream juicity-server at {}",
                upstream_server.display()
            );
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved_server =
                zuicity_testkit::reserve_udp_socket().expect("reserve upstream server UDP port");
            let server_addr = reserved_server.local_addr().expect("server local addr");
            drop(reserved_server);
            let reserved_forward =
                zuicity_testkit::reserve_tcp_listener().expect("reserve rust forward TCP port");
            let forward_addr = reserved_forward.local_addr().expect("forward local addr");
            drop(reserved_forward);
            let (proxy_addr, mut proxy_requests, proxy_task) =
                zuicity_testkit::start_socks5_tcp_connect_proxy()
                    .await
                    .expect("start SOCKS5 TCP connect proxy");

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let server_config_path = artifact.path().join("upstream-server.json");
            write_config(
                server_config_path.to_str().expect("utf8 upstream server config path"),
                &format!(
                    r#"{{"listen":"{}","dialer_link":"socks5://{proxy_addr}","users":{{"{}":"{}"}},"certificate":"{}","private_key":"{}","log_level":"debug"}}"#,
                    server_addr,
                    uuid,
                    password,
                    cert.cert_path.display(),
                    cert.key_path.display()
                ),
            );
            let server_log_path = artifact.path().join("upstream-server.log");
            let mut server = zuicity_testkit::ManagedProcessBuilder::new(
                upstream_server.to_string_lossy().into_owned(),
            )
            .arg("run")
            .arg("-c")
            .arg(server_config_path.to_string_lossy().into_owned())
            .log_path(&server_log_path)
            .start()
            .expect("spawn upstream juicity-server run");

            let roots_pem = std::fs::read(&cert.cert_path).expect("read cert roots");
            let _ready = connect_managed_with_retry(
                server_addr,
                &roots_pem,
                uuid,
                password.as_bytes(),
                &server,
            )
            .await;

            let echo = zuicity_testkit::TcpEchoServer::start()
                .await
                .expect("start TCP echo fixture");
            let client_config_path = artifact.path().join("rust-client.json");
            write_config(
                client_config_path.to_str().expect("utf8 rust client config path"),
                &format!(
                    r#"{{"server":"{}","uuid":"{}","password":"{}","sni":"localhost","allow_insecure":true,"log_level":"debug","forward":{{"{}/tcp":"{}"}}}}"#,
                    server_addr,
                    uuid,
                    password,
                    forward_addr,
                    echo.local_addr()
                ),
            );
            let client_log_path = artifact.path().join("rust-client.log");
            let mut client = zuicity_testkit::ManagedProcessBuilder::new(env!(
                "CARGO_BIN_EXE_zuicity-client"
            ))
            .arg("run")
            .arg("-c")
            .arg(client_config_path.to_str().expect("utf8 rust client config path"))
            .log_path(&client_log_path)
            .start()
            .expect("spawn rust zuicity-client run");

            let payload = b"rust client spawned upstream server tcp";
            let mut stream = connect_tcp_with_retry(forward_addr, &client).await;
            stream.write_all(payload).await.expect("write payload");
            let mut echoed = vec![0_u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
                .await
                .expect("rust client TCP echo timeout")
                .expect("read echoed payload");
            assert_eq!(echoed, payload);
            stream.shutdown().await.expect("shutdown rust forward stream");
            let proxy_request = tokio::time::timeout(Duration::from_secs(5), proxy_requests.recv())
                .await
                .expect("SOCKS5 proxy CONNECT request timeout")
                .expect("SOCKS5 proxy request channel closed");
            assert_eq!(proxy_request.target, echo.local_addr());
            drop(stream);
            proxy_task
                .await
                .expect("SOCKS5 TCP proxy task joins")
                .expect("SOCKS5 TCP proxy succeeds");

            let evidence = format!(
                "artifact_dir={}\nupstream_server={}\nrust_forwarder={}\nsocks5_proxy={proxy_addr}\necho={}\nupstream_server_log={}\nrust_client_log={}\nbuild_log={}\nserver_config={}\nclient_config={}\n",
                artifact.path().display(),
                server_addr,
                forward_addr,
                echo.local_addr(),
                server_log_path.display(),
                client_log_path.display(),
                artifact.path().join("upstream-server-build.log").display(),
                server_config_path.display(),
                client_config_path.display()
            );
            std::fs::write(artifact.path().join("addresses.txt"), &evidence)
                .expect("write addresses evidence");
            std::fs::create_dir_all("/tmp/zuicity-workspace/egress")
                .expect("create egress evidence dir");
            std::fs::write(
                "/tmp/zuicity-workspace/egress/rust-client-upstream-server-tcp-dialer-link-artifacts.txt",
                evidence,
            )
            .expect("write workspace evidence");

            echo.shutdown().await.expect("shutdown TCP echo fixture");
            let client_exit = client
                .terminate(Duration::from_secs(2))
                .expect("terminate rust zuicity-client run");
            assert_eq!(client_exit.pid, client.pid());
            let server_exit = server
                .terminate(Duration::from_secs(2))
                .expect("terminate upstream juicity-server run");
            assert_eq!(server_exit.pid, server.pid());
            let client_log = std::fs::read_to_string(&client_log_path).unwrap_or_default();
            assert!(
                !client_log.contains("runtime is not implemented"),
                "client_exit={client_exit:?}; log={client_log:?}"
            );
        });
}

#[test]
fn rust_client_forwarder_reaches_spawned_upstream_server_run_udp_echo() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            let artifact = zuicity_testkit::artifact_dir("rust client spawned upstream server udp")
                .create()
                .expect("create artifact dir");
            let upstream_server = upstream_server_binary(artifact.path());
            assert!(
                upstream_server.is_file(),
                "missing upstream juicity-server at {}",
                upstream_server.display()
            );
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved_server =
                zuicity_testkit::reserve_udp_socket().expect("reserve upstream server UDP port");
            let server_addr = reserved_server.local_addr().expect("server local addr");
            drop(reserved_server);
            let reserved_forward =
                zuicity_testkit::reserve_udp_socket().expect("reserve rust forward UDP port");
            let forward_addr = reserved_forward.local_addr().expect("forward local addr");
            drop(reserved_forward);

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let server_config_path = artifact.path().join("upstream-server.json");
            write_config(
                server_config_path.to_str().expect("utf8 upstream server config path"),
                &format!(
                    r#"{{"listen":"{}","users":{{"{}":"{}"}},"certificate":"{}","private_key":"{}","log_level":"debug"}}"#,
                    server_addr,
                    uuid,
                    password,
                    cert.cert_path.display(),
                    cert.key_path.display()
                ),
            );
            let server_log_path = artifact.path().join("upstream-server.log");
            let mut server = zuicity_testkit::ManagedProcessBuilder::new(
                upstream_server.to_string_lossy().into_owned(),
            )
            .arg("run")
            .arg("-c")
            .arg(server_config_path.to_string_lossy().into_owned())
            .log_path(&server_log_path)
            .start()
            .expect("spawn upstream juicity-server run");

            let roots_pem = std::fs::read(&cert.cert_path).expect("read cert roots");
            let _ready = connect_managed_with_retry(
                server_addr,
                &roots_pem,
                uuid,
                password.as_bytes(),
                &server,
            )
            .await;

            let echo = zuicity_testkit::UdpEchoServer::start()
                .await
                .expect("start UDP echo fixture");
            let client_config_path = artifact.path().join("rust-client.json");
            write_config(
                client_config_path.to_str().expect("utf8 rust client config path"),
                &format!(
                    r#"{{"server":"{}","uuid":"{}","password":"{}","sni":"localhost","allow_insecure":true,"log_level":"debug","forward":{{"{}/udp":"{}"}}}}"#,
                    server_addr,
                    uuid,
                    password,
                    forward_addr,
                    echo.local_addr()
                ),
            );
            let client_log_path = artifact.path().join("rust-client.log");
            let mut client = zuicity_testkit::ManagedProcessBuilder::new(env!(
                "CARGO_BIN_EXE_zuicity-client"
            ))
            .arg("run")
            .arg("-c")
            .arg(client_config_path.to_str().expect("utf8 rust client config path"))
            .log_path(&client_log_path)
            .start()
            .expect("spawn rust zuicity-client run");

            let socket = tokio::net::UdpSocket::bind(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                0,
            )))
            .await
            .expect("bind local UDP client");
            let payload = b"rust client spawned upstream server udp";
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut buf = [0_u8; 1024];
            loop {
                if !client.is_running().expect("poll rust client process") {
                    let log = std::fs::read_to_string(&client_log_path).unwrap_or_default();
                    panic!(
                        "rust zuicity-client exited before UDP echo; log_path={}; log={log:?}",
                        client_log_path.display()
                    );
                }
                socket
                    .send_to(payload, forward_addr)
                    .await
                    .expect("send UDP payload to rust forwarder");
                match tokio::time::timeout(Duration::from_millis(250), socket.recv_from(&mut buf))
                    .await
                {
                    Ok(Ok((received, from))) => {
                        assert_eq!(from, forward_addr);
                        assert_eq!(&buf[..received], payload);
                        break;
                    }
                    Ok(Err(error)) => panic!("receive UDP echo from rust forwarder: {error}"),
                    Err(_) if tokio::time::Instant::now() < deadline => {}
                    Err(_) => panic!("timed out waiting for rust client UDP echo"),
                }
            }

            let evidence = format!(
                "artifact_dir={}\nupstream_server={}\nrust_forwarder={}\necho={}\nupstream_server_log={}\nrust_client_log={}\nbuild_log={}\nserver_config={}\nclient_config={}\n",
                artifact.path().display(),
                server_addr,
                forward_addr,
                echo.local_addr(),
                server_log_path.display(),
                client_log_path.display(),
                artifact.path().join("upstream-server-build.log").display(),
                server_config_path.display(),
                client_config_path.display()
            );
            std::fs::write(artifact.path().join("addresses.txt"), &evidence)
                .expect("write addresses evidence");
            std::fs::create_dir_all("/tmp/zuicity-workspace")
                .expect("create workspace evidence dir");
            std::fs::write(
                "/tmp/zuicity-workspace/rust-client-spawned-upstream-server-udp-artifacts.txt",
                evidence,
            )
            .expect("write workspace evidence");

            echo.shutdown().await.expect("shutdown UDP echo fixture");
            let client_exit = client
                .terminate(Duration::from_secs(2))
                .expect("terminate rust zuicity-client run");
            assert_eq!(client_exit.pid, client.pid());
            let server_exit = server
                .terminate(Duration::from_secs(2))
                .expect("terminate upstream juicity-server run");
            assert_eq!(server_exit.pid, server.pid());
            let client_log = std::fs::read_to_string(&client_log_path).unwrap_or_default();
            assert!(
                !client_log.contains("runtime is not implemented"),
                "client_exit={client_exit:?}; log={client_log:?}"
            );
        });
}

#[test]
fn rust_client_forwarder_reaches_spawned_upstream_server_run_udp_echo_through_socks5_dialer_link() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            let artifact = zuicity_testkit::artifact_dir("rust client upstream server udp dialer link")
                .create()
                .expect("create artifact dir");
            let upstream_server = upstream_server_binary(artifact.path());
            assert!(
                upstream_server.is_file(),
                "missing upstream juicity-server at {}",
                upstream_server.display()
            );
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved_server =
                zuicity_testkit::reserve_udp_socket().expect("reserve upstream server UDP port");
            let server_addr = reserved_server.local_addr().expect("server local addr");
            drop(reserved_server);
            let reserved_forward =
                zuicity_testkit::reserve_udp_socket().expect("reserve rust forward UDP port");
            let forward_addr = reserved_forward.local_addr().expect("forward local addr");
            drop(reserved_forward);
            let (proxy_addr, mut proxy_requests, proxy_task) =
                zuicity_testkit::start_socks5_udp_associate_proxy()
                    .await
                    .expect("start SOCKS5 UDP associate proxy");

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let server_config_path = artifact.path().join("upstream-server.json");
            write_config(
                server_config_path.to_str().expect("utf8 upstream server config path"),
                &format!(
                    r#"{{"listen":"{}","dialer_link":"socks5://{proxy_addr}","users":{{"{}":"{}"}},"certificate":"{}","private_key":"{}","log_level":"debug"}}"#,
                    server_addr,
                    uuid,
                    password,
                    cert.cert_path.display(),
                    cert.key_path.display()
                ),
            );
            let server_log_path = artifact.path().join("upstream-server.log");
            let mut server = zuicity_testkit::ManagedProcessBuilder::new(
                upstream_server.to_string_lossy().into_owned(),
            )
            .arg("run")
            .arg("-c")
            .arg(server_config_path.to_string_lossy().into_owned())
            .log_path(&server_log_path)
            .start()
            .expect("spawn upstream juicity-server run");

            let roots_pem = std::fs::read(&cert.cert_path).expect("read cert roots");
            let _ready = connect_managed_with_retry(
                server_addr,
                &roots_pem,
                uuid,
                password.as_bytes(),
                &server,
            )
            .await;

            let echo = zuicity_testkit::UdpEchoServer::start()
                .await
                .expect("start UDP echo fixture");
            let client_config_path = artifact.path().join("rust-client.json");
            write_config(
                client_config_path.to_str().expect("utf8 rust client config path"),
                &format!(
                    r#"{{"server":"{}","uuid":"{}","password":"{}","sni":"localhost","allow_insecure":true,"log_level":"debug","forward":{{"{}/udp":"{}"}}}}"#,
                    server_addr,
                    uuid,
                    password,
                    forward_addr,
                    echo.local_addr()
                ),
            );
            let client_log_path = artifact.path().join("rust-client.log");
            let mut client = zuicity_testkit::ManagedProcessBuilder::new(env!(
                "CARGO_BIN_EXE_zuicity-client"
            ))
            .arg("run")
            .arg("-c")
            .arg(client_config_path.to_str().expect("utf8 rust client config path"))
            .log_path(&client_log_path)
            .start()
            .expect("spawn rust zuicity-client run");

            let socket = tokio::net::UdpSocket::bind(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                0,
            )))
            .await
            .expect("bind local UDP client");
            let payload = b"rust client spawned upstream server udp";
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut buf = [0_u8; 1024];
            loop {
                if !client.is_running().expect("poll rust client process") {
                    let log = std::fs::read_to_string(&client_log_path).unwrap_or_default();
                    panic!(
                        "rust zuicity-client exited before UDP echo; log_path={}; log={log:?}",
                        client_log_path.display()
                    );
                }
                socket
                    .send_to(payload, forward_addr)
                    .await
                    .expect("send UDP payload to rust forwarder");
                match tokio::time::timeout(Duration::from_millis(250), socket.recv_from(&mut buf))
                    .await
                {
                    Ok(Ok((received, from))) => {
                        assert_eq!(from, forward_addr);
                        assert_eq!(&buf[..received], payload);
                        break;
                    }
                    Ok(Err(error)) => panic!("receive UDP echo from rust forwarder: {error}"),
                    Err(_) if tokio::time::Instant::now() < deadline => {}
                    Err(_) => panic!("timed out waiting for rust client UDP echo"),
                }
            }

            let proxy_request = tokio::time::timeout(Duration::from_secs(5), proxy_requests.recv())
                .await
                .expect("SOCKS5 proxy UDP ASSOCIATE request timeout")
                .expect("SOCKS5 proxy request channel closed");
            assert_eq!(proxy_request.target, echo.local_addr());

            let evidence = format!(
                "artifact_dir={}\nupstream_server={}\nrust_forwarder={}\nsocks5_proxy={proxy_addr}\necho={}\nupstream_server_log={}\nrust_client_log={}\nbuild_log={}\nserver_config={}\nclient_config={}\n",
                artifact.path().display(),
                server_addr,
                forward_addr,
                echo.local_addr(),
                server_log_path.display(),
                client_log_path.display(),
                artifact.path().join("upstream-server-build.log").display(),
                server_config_path.display(),
                client_config_path.display()
            );
            std::fs::write(artifact.path().join("addresses.txt"), &evidence)
                .expect("write addresses evidence");
            std::fs::create_dir_all("/tmp/zuicity-workspace/egress")
                .expect("create egress evidence dir");
            std::fs::write(
                "/tmp/zuicity-workspace/egress/rust-client-upstream-server-udp-dialer-link-artifacts.txt",
                evidence,
            )
            .expect("write workspace evidence");

            echo.shutdown().await.expect("shutdown UDP echo fixture");
            let client_exit = client
                .terminate(Duration::from_secs(2))
                .expect("terminate rust zuicity-client run");
            assert_eq!(client_exit.pid, client.pid());
            let server_exit = server
                .terminate(Duration::from_secs(2))
                .expect("terminate upstream juicity-server run");
            assert_eq!(server_exit.pid, server.pid());
            proxy_task
                .await
                .expect("SOCKS5 UDP proxy task joins")
                .expect("SOCKS5 UDP proxy succeeds");
            let client_log = std::fs::read_to_string(&client_log_path).unwrap_or_default();
            assert!(
                !client_log.contains("runtime is not implemented"),
                "client_exit={client_exit:?}; log={client_log:?}"
            );
        });
}

#[test]
fn rust_client_forwarder_reaches_spawned_upstream_server_run_udp_echo_through_socks5_shadowsocks_dialer_chain()
 {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            let artifact = zuicity_testkit::artifact_dir(
                "rust client upstream server udp socks5 shadowsocks chain",
            )
            .create()
            .expect("create artifact dir");
            let upstream_server = upstream_server_binary(artifact.path());
            assert!(
                upstream_server.is_file(),
                "missing upstream juicity-server at {}",
                upstream_server.display()
            );
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved_server =
                zuicity_testkit::reserve_udp_socket().expect("reserve upstream server UDP port");
            let server_addr = reserved_server.local_addr().expect("server local addr");
            drop(reserved_server);
            let reserved_forward =
                zuicity_testkit::reserve_udp_socket().expect("reserve rust forward UDP port");
            let forward_addr = reserved_forward.local_addr().expect("forward local addr");
            drop(reserved_forward);
            let (socks_proxy_addr, mut socks_requests, socks_proxy_task) =
                zuicity_testkit::start_socks5_udp_associate_proxy()
                    .await
                    .expect("start SOCKS5 UDP associate proxy");
            let shadowsocks_password = "rust client upstream server socks5 shadowsocks udp chain proxy password";
            let (
                shadowsocks_proxy_addr,
                mut shadowsocks_tcp_requests,
                mut shadowsocks_udp_requests,
                shadowsocks_proxy_task,
            ) = start_shadowsocks_tcp_udp_proxy(
                shadowsocks_password,
                shadowsocks::crypto::CipherKind::AES_128_GCM,
            )
            .await
            .expect("start Shadowsocks TCP/UDP proxy");
            let userinfo = general_purpose::URL_SAFE_NO_PAD
                .encode(format!("aes-128-gcm:{shadowsocks_password}"));

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let server_config_path = artifact.path().join("upstream-server.json");
            write_config(
                server_config_path.to_str().expect("utf8 upstream server config path"),
                &format!(
                    r#"{{"listen":"{}","dialer_link":"socks5://{socks_proxy_addr} -> ss://{userinfo}@{shadowsocks_proxy_addr}","users":{{"{}":"{}"}},"certificate":"{}","private_key":"{}","log_level":"debug"}}"#,
                    server_addr,
                    uuid,
                    password,
                    cert.cert_path.display(),
                    cert.key_path.display()
                ),
            );
            let server_log_path = artifact.path().join("upstream-server.log");
            let mut server = zuicity_testkit::ManagedProcessBuilder::new(
                upstream_server.to_string_lossy().into_owned(),
            )
            .arg("run")
            .arg("-c")
            .arg(server_config_path.to_string_lossy().into_owned())
            .log_path(&server_log_path)
            .start()
            .expect("spawn upstream juicity-server run");

            let roots_pem = std::fs::read(&cert.cert_path).expect("read cert roots");
            let _ready = connect_managed_with_retry(
                server_addr,
                &roots_pem,
                uuid,
                password.as_bytes(),
                &server,
            )
            .await;

            let echo = zuicity_testkit::UdpEchoServer::start()
                .await
                .expect("start UDP echo fixture");
            let client_config_path = artifact.path().join("rust-client.json");
            write_config(
                client_config_path.to_str().expect("utf8 rust client config path"),
                &format!(
                    r#"{{"server":"{}","uuid":"{}","password":"{}","sni":"localhost","allow_insecure":true,"log_level":"debug","forward":{{"{}/udp":"{}"}}}}"#,
                    server_addr,
                    uuid,
                    password,
                    forward_addr,
                    echo.local_addr()
                ),
            );
            let client_log_path = artifact.path().join("rust-client.log");
            let mut client = zuicity_testkit::ManagedProcessBuilder::new(env!(
                "CARGO_BIN_EXE_zuicity-client"
            ))
            .arg("run")
            .arg("-c")
            .arg(client_config_path.to_str().expect("utf8 rust client config path"))
            .log_path(&client_log_path)
            .start()
            .expect("spawn rust zuicity-client run");

            let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .expect("bind local UDP client");
            let payload = b"rust client spawned upstream server udp socks5 shadowsocks chain";
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut buf = [0_u8; 1024];
            loop {
                if !client.is_running().expect("poll rust client process") {
                    let log = std::fs::read_to_string(&client_log_path).unwrap_or_default();
                    panic!(
                        "rust zuicity-client exited before UDP echo; log_path={}; log={log:?}",
                        client_log_path.display()
                    );
                }
                socket
                    .send_to(payload, forward_addr)
                    .await
                    .expect("send UDP payload to rust forwarder");
                match tokio::time::timeout(Duration::from_millis(250), socket.recv_from(&mut buf))
                    .await
                {
                    Ok(Ok((received, from))) => {
                        assert_eq!(from, forward_addr);
                        assert_eq!(&buf[..received], payload);
                        break;
                    }
                    Ok(Err(error)) => panic!("receive UDP echo from rust forwarder: {error}"),
                    Err(_) if tokio::time::Instant::now() < deadline => {}
                    Err(_) => panic!("timed out waiting for rust client UDP chain echo"),
                }
            }

            let shadowsocks_tcp_request =
                tokio::time::timeout(CHAIN_RELAY_TIMEOUT, shadowsocks_tcp_requests.recv())
                    .await
                    .expect("Shadowsocks TCP request timeout")
                    .expect("Shadowsocks TCP request channel closed");
            assert_eq!(shadowsocks_tcp_request.target, socks_proxy_addr);
            let shadowsocks_udp_request =
                tokio::time::timeout(CHAIN_RELAY_TIMEOUT, shadowsocks_udp_requests.recv())
                    .await
                    .expect("Shadowsocks UDP request timeout")
                    .expect("Shadowsocks UDP request channel closed");
            assert_eq!(shadowsocks_udp_request.target.ip(), socks_proxy_addr.ip());
            let socks_request = tokio::time::timeout(CHAIN_RELAY_TIMEOUT, socks_requests.recv())
                .await
                .expect("SOCKS5 proxy UDP ASSOCIATE request timeout")
                .expect("SOCKS5 proxy request channel closed");
            assert_eq!(socks_request.target, echo.local_addr());

            let evidence = format!(
                "artifact_dir={}\nupstream_server={}\nrust_forwarder={}\nsocks5_proxy={socks_proxy_addr}\nshadowsocks_proxy={shadowsocks_proxy_addr}\necho={}\nupstream_server_log={}\nrust_client_log={}\nbuild_log={}\nserver_config={}\nclient_config={}\n",
                artifact.path().display(),
                server_addr,
                forward_addr,
                echo.local_addr(),
                server_log_path.display(),
                client_log_path.display(),
                artifact.path().join("upstream-server-build.log").display(),
                server_config_path.display(),
                client_config_path.display()
            );
            std::fs::write(artifact.path().join("addresses.txt"), &evidence)
                .expect("write addresses evidence");
            std::fs::create_dir_all("/tmp/zuicity-workspace/egress")
                .expect("create egress evidence dir");
            std::fs::write(
                "/tmp/zuicity-workspace/egress/rust-client-upstream-server-udp-socks5-shadowsocks-chain-artifacts.txt",
                evidence,
            )
            .expect("write workspace evidence");

            echo.shutdown().await.expect("shutdown UDP echo fixture");
            let client_exit = client
                .terminate(Duration::from_secs(2))
                .expect("terminate rust zuicity-client run");
            assert_eq!(client_exit.pid, client.pid());
            let server_exit = server
                .terminate(Duration::from_secs(2))
                .expect("terminate upstream juicity-server run");
            assert_eq!(server_exit.pid, server.pid());
            socks_proxy_task
                .await
                .expect("SOCKS5 UDP proxy task joins")
                .expect("SOCKS5 UDP proxy succeeds");
            shadowsocks_proxy_task
                .await
                .expect("Shadowsocks proxy task joins")
                .expect("Shadowsocks proxy succeeds");
            let client_log = std::fs::read_to_string(&client_log_path).unwrap_or_default();
            assert!(
                !client_log.contains("runtime is not implemented"),
                "client_exit={client_exit:?}; log={client_log:?}"
            );
        });
}

#[test]
fn rust_client_forwarder_reaches_spawned_upstream_server_run_udp_echo_through_shadowsocks_socks5_dialer_chain()
 {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            let artifact = zuicity_testkit::artifact_dir(
                "rust client upstream server udp shadowsocks socks5 chain",
            )
            .create()
            .expect("create artifact dir");
            let upstream_server = upstream_server_binary(artifact.path());
            assert!(
                upstream_server.is_file(),
                "missing upstream juicity-server at {}",
                upstream_server.display()
            );
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved_server =
                zuicity_testkit::reserve_udp_socket().expect("reserve upstream server UDP port");
            let server_addr = reserved_server.local_addr().expect("server local addr");
            drop(reserved_server);
            let reserved_forward =
                zuicity_testkit::reserve_udp_socket().expect("reserve rust forward UDP port");
            let forward_addr = reserved_forward.local_addr().expect("forward local addr");
            drop(reserved_forward);
            let (socks_proxy_addr, mut socks_requests, socks_proxy_task) =
                zuicity_testkit::start_socks5_udp_associate_proxy()
                    .await
                    .expect("start SOCKS5 UDP associate proxy");
            let shadowsocks_password = "rust client upstream server shadowsocks socks5 udp chain proxy password";
            let (shadowsocks_proxy_addr, mut shadowsocks_requests, shadowsocks_proxy_task) =
                start_shadowsocks_udp_proxy(
                    shadowsocks_password,
                    shadowsocks::crypto::CipherKind::AES_128_GCM,
                )
                .await
                .expect("start Shadowsocks UDP proxy");
            let userinfo = general_purpose::URL_SAFE_NO_PAD
                .encode(format!("aes-128-gcm:{shadowsocks_password}"));

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let server_config_path = artifact.path().join("upstream-server.json");
            write_config(
                server_config_path.to_str().expect("utf8 upstream server config path"),
                &format!(
                    r#"{{"listen":"{}","dialer_link":"ss://{userinfo}@{shadowsocks_proxy_addr} -> socks5://{socks_proxy_addr}","users":{{"{}":"{}"}},"certificate":"{}","private_key":"{}","log_level":"debug"}}"#,
                    server_addr,
                    uuid,
                    password,
                    cert.cert_path.display(),
                    cert.key_path.display()
                ),
            );
            let server_log_path = artifact.path().join("upstream-server.log");
            let mut server = zuicity_testkit::ManagedProcessBuilder::new(
                upstream_server.to_string_lossy().into_owned(),
            )
            .arg("run")
            .arg("-c")
            .arg(server_config_path.to_string_lossy().into_owned())
            .log_path(&server_log_path)
            .start()
            .expect("spawn upstream juicity-server run");

            let roots_pem = std::fs::read(&cert.cert_path).expect("read cert roots");
            let _ready = connect_managed_with_retry(
                server_addr,
                &roots_pem,
                uuid,
                password.as_bytes(),
                &server,
            )
            .await;

            let echo = zuicity_testkit::UdpEchoServer::start()
                .await
                .expect("start UDP echo fixture");
            let client_config_path = artifact.path().join("rust-client.json");
            write_config(
                client_config_path.to_str().expect("utf8 rust client config path"),
                &format!(
                    r#"{{"server":"{}","uuid":"{}","password":"{}","sni":"localhost","allow_insecure":true,"log_level":"debug","forward":{{"{}/udp":"{}"}}}}"#,
                    server_addr,
                    uuid,
                    password,
                    forward_addr,
                    echo.local_addr()
                ),
            );
            let client_log_path = artifact.path().join("rust-client.log");
            let mut client = zuicity_testkit::ManagedProcessBuilder::new(env!(
                "CARGO_BIN_EXE_zuicity-client"
            ))
            .arg("run")
            .arg("-c")
            .arg(client_config_path.to_str().expect("utf8 rust client config path"))
            .log_path(&client_log_path)
            .start()
            .expect("spawn rust zuicity-client run");

            let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .expect("bind local UDP client");
            let payload = b"rust client spawned upstream server udp shadowsocks socks5 chain";
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut buf = [0_u8; 1024];
            loop {
                if !client.is_running().expect("poll rust client process") {
                    let log = std::fs::read_to_string(&client_log_path).unwrap_or_default();
                    panic!(
                        "rust zuicity-client exited before UDP echo; log_path={}; log={log:?}",
                        client_log_path.display()
                    );
                }
                socket
                    .send_to(payload, forward_addr)
                    .await
                    .expect("send UDP payload to rust forwarder");
                match tokio::time::timeout(Duration::from_millis(250), socket.recv_from(&mut buf))
                    .await
                {
                    Ok(Ok((received, from))) => {
                        assert_eq!(from, forward_addr);
                        assert_eq!(&buf[..received], payload);
                        break;
                    }
                    Ok(Err(error)) => panic!("receive UDP echo from rust forwarder: {error}"),
                    Err(_) if tokio::time::Instant::now() < deadline => {}
                    Err(_) => panic!("timed out waiting for rust client UDP reverse chain echo"),
                }
            }

            let socks_request = tokio::time::timeout(CHAIN_RELAY_TIMEOUT, socks_requests.recv())
                .await
                .expect("SOCKS5 proxy UDP ASSOCIATE request timeout")
                .expect("SOCKS5 proxy request channel closed");
            assert_eq!(socks_request.target, shadowsocks_proxy_addr);
            let shadowsocks_request =
                tokio::time::timeout(CHAIN_RELAY_TIMEOUT, shadowsocks_requests.recv())
                    .await
                    .expect("Shadowsocks UDP request timeout")
                    .expect("Shadowsocks UDP request channel closed");
            assert_eq!(shadowsocks_request.target, echo.local_addr());

            let evidence = format!(
                "artifact_dir={}\nupstream_server={}\nrust_forwarder={}\nshadowsocks_proxy={shadowsocks_proxy_addr}\nsocks5_proxy={socks_proxy_addr}\necho={}\nupstream_server_log={}\nrust_client_log={}\nbuild_log={}\nserver_config={}\nclient_config={}\n",
                artifact.path().display(),
                server_addr,
                forward_addr,
                echo.local_addr(),
                server_log_path.display(),
                client_log_path.display(),
                artifact.path().join("upstream-server-build.log").display(),
                server_config_path.display(),
                client_config_path.display()
            );
            std::fs::write(artifact.path().join("addresses.txt"), &evidence)
                .expect("write addresses evidence");
            std::fs::create_dir_all("/tmp/zuicity-workspace/egress")
                .expect("create egress evidence dir");
            std::fs::write(
                "/tmp/zuicity-workspace/egress/rust-client-upstream-server-udp-shadowsocks-socks5-chain-artifacts.txt",
                evidence,
            )
            .expect("write workspace evidence");

            echo.shutdown().await.expect("shutdown UDP echo fixture");
            let client_exit = client
                .terminate(Duration::from_secs(2))
                .expect("terminate rust zuicity-client run");
            assert_eq!(client_exit.pid, client.pid());
            let server_exit = server
                .terminate(Duration::from_secs(2))
                .expect("terminate upstream juicity-server run");
            assert_eq!(server_exit.pid, server.pid());
            socks_proxy_task
                .await
                .expect("SOCKS5 UDP proxy task joins")
                .expect("SOCKS5 UDP proxy succeeds");
            shadowsocks_proxy_task
                .await
                .expect("Shadowsocks proxy task joins")
                .expect("Shadowsocks proxy succeeds");
            let client_log = std::fs::read_to_string(&client_log_path).unwrap_or_default();
            assert!(
                !client_log.contains("runtime is not implemented"),
                "client_exit={client_exit:?}; log={client_log:?}"
            );
        });
}

#[test]
fn rust_client_http_connect_reaches_spawned_upstream_server_run_tcp_echo() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let artifact = zuicity_testkit::artifact_dir("rust client http upstream server tcp")
                .create()
                .expect("create artifact dir");
            let upstream_server = upstream_server_binary(artifact.path());
            assert!(
                upstream_server.is_file(),
                "missing upstream juicity-server at {}",
                upstream_server.display()
            );
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved_server =
                zuicity_testkit::reserve_udp_socket().expect("reserve upstream server UDP port");
            let server_addr = reserved_server.local_addr().expect("server local addr");
            drop(reserved_server);
            let (reserved_listener, reserved_listener_udp) = zuicity_testkit::reserve_tcp_udp_pair()
                .expect("reserve rust client mixed listen TCP/UDP port");
            let listen_addr = reserved_listener.local_addr().expect("client listen local addr");
            drop(reserved_listener);
            drop(reserved_listener_udp);

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let server_config_path = artifact.path().join("upstream-server.json");
            write_config(
                server_config_path.to_str().expect("utf8 upstream server config path"),
                &format!(
                    r#"{{"listen":"{}","users":{{"{}":"{}"}},"certificate":"{}","private_key":"{}","log_level":"debug"}}"#,
                    server_addr,
                    uuid,
                    password,
                    cert.cert_path.display(),
                    cert.key_path.display()
                ),
            );
            let server_log_path = artifact.path().join("upstream-server.log");
            let mut server = zuicity_testkit::ManagedProcessBuilder::new(
                upstream_server.to_string_lossy().into_owned(),
            )
            .arg("run")
            .arg("-c")
            .arg(server_config_path.to_string_lossy().into_owned())
            .log_path(&server_log_path)
            .start()
            .expect("spawn upstream juicity-server run");

            let roots_pem = std::fs::read(&cert.cert_path).expect("read cert roots");
            let _ready = connect_managed_with_retry(
                server_addr,
                &roots_pem,
                uuid,
                password.as_bytes(),
                &server,
            )
            .await;

            let echo = zuicity_testkit::TcpEchoServer::start()
                .await
                .expect("start TCP echo fixture");
            let client_config_path = artifact.path().join("rust-client.json");
            write_config(
                client_config_path.to_str().expect("utf8 rust client config path"),
                &format!(
                    r#"{{"listen":"{}","server":"{}","uuid":"{}","password":"{}","sni":"localhost","allow_insecure":true,"log_level":"debug"}}"#,
                    listen_addr,
                    server_addr,
                    uuid,
                    password
                ),
            );
            let client_log_path = artifact.path().join("rust-client.log");
            let mut client = zuicity_testkit::ManagedProcessBuilder::new(env!(
                "CARGO_BIN_EXE_zuicity-client"
            ))
            .arg("run")
            .arg("-c")
            .arg(client_config_path.to_str().expect("utf8 rust client config path"))
            .log_path(&client_log_path)
            .start()
            .expect("spawn rust zuicity-client run");

            let echo_addr = echo.local_addr();
            let mut stream = connect_tcp_with_retry(listen_addr, &client).await;
            stream
                .write_all(format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n").as_bytes())
                .await
                .expect("write HTTP CONNECT request");
            let mut response = Vec::new();
            let mut byte = [0_u8; 1];
            while !response.ends_with(b"\r\n\r\n") {
                tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut byte))
                    .await
                    .expect("HTTP CONNECT response timeout")
                    .expect("read HTTP CONNECT response");
                response.push(byte[0]);
            }
            assert_eq!(response, b"HTTP/1.1 200 Connection established\r\n\r\n");

            let payload = b"rust client http upstream server tcp";
            stream.write_all(payload).await.expect("write payload");
            stream.shutdown().await.expect("shutdown write half");
            let mut echoed = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut echoed))
                .await
                .expect("HTTP CONNECT echo timeout")
                .expect("read echoed payload");
            assert_eq!(echoed, payload);

            let evidence = format!(
                "artifact_dir={}\nupstream_server={}\nrust_listener={}\necho={}\nupstream_server_log={}\nrust_client_log={}\nbuild_log={}\nserver_config={}\nclient_config={}\n",
                artifact.path().display(),
                server_addr,
                listen_addr,
                echo_addr,
                server_log_path.display(),
                client_log_path.display(),
                artifact.path().join("upstream-server-build.log").display(),
                server_config_path.display(),
                client_config_path.display()
            );
            std::fs::write(artifact.path().join("addresses.txt"), &evidence)
                .expect("write addresses evidence");
            std::fs::create_dir_all("/tmp/zuicity-workspace")
                .expect("create workspace evidence dir");
            std::fs::write(
                "/tmp/zuicity-workspace/rust-client-http-spawned-upstream-server-tcp-artifacts.txt",
                evidence,
            )
            .expect("write workspace evidence");

            echo.shutdown().await.expect("shutdown TCP echo fixture");
            let client_exit = client
                .terminate(Duration::from_secs(2))
                .expect("terminate rust zuicity-client run");
            assert_eq!(client_exit.pid, client.pid());
            let server_exit = server
                .terminate(Duration::from_secs(2))
                .expect("terminate upstream juicity-server run");
            assert_eq!(server_exit.pid, server.pid());
            let client_log = std::fs::read_to_string(&client_log_path).unwrap_or_default();
            assert!(
                !client_log.contains("runtime is not implemented"),
                "client_exit={client_exit:?}; log={client_log:?}"
            );
        });
}

#[test]
fn rust_client_socks5_connect_reaches_spawned_upstream_server_run_tcp_echo() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let artifact = zuicity_testkit::artifact_dir("rust client socks5 upstream server tcp")
                .create()
                .expect("create artifact dir");
            let upstream_server = upstream_server_binary(artifact.path());
            assert!(
                upstream_server.is_file(),
                "missing upstream juicity-server at {}",
                upstream_server.display()
            );
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved_server =
                zuicity_testkit::reserve_udp_socket().expect("reserve upstream server UDP port");
            let server_addr = reserved_server.local_addr().expect("server local addr");
            drop(reserved_server);
            let (reserved_listener, reserved_listener_udp) = zuicity_testkit::reserve_tcp_udp_pair()
                .expect("reserve rust client mixed listen TCP/UDP port");
            let listen_addr = reserved_listener.local_addr().expect("client listen local addr");
            drop(reserved_listener);
            drop(reserved_listener_udp);

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let server_config_path = artifact.path().join("upstream-server.json");
            write_config(
                server_config_path.to_str().expect("utf8 upstream server config path"),
                &format!(
                    r#"{{"listen":"{}","users":{{"{}":"{}"}},"certificate":"{}","private_key":"{}","log_level":"debug"}}"#,
                    server_addr,
                    uuid,
                    password,
                    cert.cert_path.display(),
                    cert.key_path.display()
                ),
            );
            let server_log_path = artifact.path().join("upstream-server.log");
            let mut server = zuicity_testkit::ManagedProcessBuilder::new(
                upstream_server.to_string_lossy().into_owned(),
            )
            .arg("run")
            .arg("-c")
            .arg(server_config_path.to_string_lossy().into_owned())
            .log_path(&server_log_path)
            .start()
            .expect("spawn upstream juicity-server run");

            let roots_pem = std::fs::read(&cert.cert_path).expect("read cert roots");
            let _ready = connect_managed_with_retry(
                server_addr,
                &roots_pem,
                uuid,
                password.as_bytes(),
                &server,
            )
            .await;

            let echo = zuicity_testkit::TcpEchoServer::start()
                .await
                .expect("start TCP echo fixture");
            let client_config_path = artifact.path().join("rust-client.json");
            write_config(
                client_config_path.to_str().expect("utf8 rust client config path"),
                &format!(
                    r#"{{"listen":"{}","server":"{}","uuid":"{}","password":"{}","sni":"localhost","allow_insecure":true,"log_level":"debug"}}"#,
                    listen_addr,
                    server_addr,
                    uuid,
                    password
                ),
            );
            let client_log_path = artifact.path().join("rust-client.log");
            let mut client = zuicity_testkit::ManagedProcessBuilder::new(env!(
                "CARGO_BIN_EXE_zuicity-client"
            ))
            .arg("run")
            .arg("-c")
            .arg(client_config_path.to_str().expect("utf8 rust client config path"))
            .log_path(&client_log_path)
            .start()
            .expect("spawn rust zuicity-client run");

            let echo_addr = echo.local_addr();
            let mut stream = connect_tcp_with_retry(listen_addr, &client).await;
            stream
                .write_all(&[0x05, 0x01, 0x00])
                .await
                .expect("write SOCKS5 greeting");
            let mut greeting_response = [0_u8; 2];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut greeting_response))
                .await
                .expect("SOCKS5 greeting timeout")
                .expect("read SOCKS5 greeting response");
            assert_eq!(greeting_response, [0x05, 0x00]);

            let std::net::SocketAddr::V4(echo_v4) = echo_addr else {
                panic!("TCP echo fixture should bind IPv4 loopback")
            };
            let mut request = vec![0x05, 0x01, 0x00, 0x01];
            request.extend_from_slice(&echo_v4.ip().octets());
            request.extend_from_slice(&echo_v4.port().to_be_bytes());
            stream
                .write_all(&request)
                .await
                .expect("write SOCKS5 CONNECT request");
            let mut connect_response = [0_u8; 10];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut connect_response))
                .await
                .expect("SOCKS5 CONNECT response timeout")
                .expect("read SOCKS5 CONNECT response");
            assert_eq!(connect_response, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

            let payload = b"rust client socks5 upstream server tcp";
            stream.write_all(payload).await.expect("write payload");
            stream.shutdown().await.expect("shutdown write half");
            let mut echoed = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut echoed))
                .await
                .expect("SOCKS5 CONNECT echo timeout")
                .expect("read echoed payload");
            assert_eq!(echoed, payload);

            let evidence = format!(
                "artifact_dir={}\nupstream_server={}\nrust_listener={}\necho={}\nupstream_server_log={}\nrust_client_log={}\nbuild_log={}\nserver_config={}\nclient_config={}\n",
                artifact.path().display(),
                server_addr,
                listen_addr,
                echo_addr,
                server_log_path.display(),
                client_log_path.display(),
                artifact.path().join("upstream-server-build.log").display(),
                server_config_path.display(),
                client_config_path.display()
            );
            std::fs::write(artifact.path().join("addresses.txt"), &evidence)
                .expect("write addresses evidence");
            std::fs::create_dir_all("/tmp/zuicity-workspace")
                .expect("create workspace evidence dir");
            std::fs::write(
                "/tmp/zuicity-workspace/rust-client-socks5-spawned-upstream-server-tcp-artifacts.txt",
                evidence,
            )
            .expect("write workspace evidence");

            echo.shutdown().await.expect("shutdown TCP echo fixture");
            let client_exit = client
                .terminate(Duration::from_secs(2))
                .expect("terminate rust zuicity-client run");
            assert_eq!(client_exit.pid, client.pid());
            let server_exit = server
                .terminate(Duration::from_secs(2))
                .expect("terminate upstream juicity-server run");
            assert_eq!(server_exit.pid, server.pid());
            let client_log = std::fs::read_to_string(&client_log_path).unwrap_or_default();
            assert!(
                !client_log.contains("runtime is not implemented"),
                "client_exit={client_exit:?}; log={client_log:?}"
            );
        });
}

#[test]
fn rust_client_socks5_udp_associate_reaches_spawned_upstream_server_run_udp_echo() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let artifact = zuicity_testkit::artifact_dir("rust client socks5 udp upstream server")
                .create()
                .expect("create artifact dir");
            let upstream_server = upstream_server_binary(artifact.path());
            assert!(
                upstream_server.is_file(),
                "missing upstream juicity-server at {}",
                upstream_server.display()
            );
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved_server =
                zuicity_testkit::reserve_udp_socket().expect("reserve upstream server UDP port");
            let server_addr = reserved_server.local_addr().expect("server local addr");
            drop(reserved_server);
            let (reserved_listener, reserved_listener_udp) = zuicity_testkit::reserve_tcp_udp_pair()
                .expect("reserve rust client mixed listen TCP/UDP port");
            let listen_addr = reserved_listener.local_addr().expect("client listen local addr");
            drop(reserved_listener);
            drop(reserved_listener_udp);

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let server_config_path = artifact.path().join("upstream-server.json");
            write_config(
                server_config_path.to_str().expect("utf8 upstream server config path"),
                &format!(
                    r#"{{"listen":"{}","users":{{"{}":"{}"}},"certificate":"{}","private_key":"{}","log_level":"debug"}}"#,
                    server_addr,
                    uuid,
                    password,
                    cert.cert_path.display(),
                    cert.key_path.display()
                ),
            );
            let server_log_path = artifact.path().join("upstream-server.log");
            let mut server = zuicity_testkit::ManagedProcessBuilder::new(
                upstream_server.to_string_lossy().into_owned(),
            )
            .arg("run")
            .arg("-c")
            .arg(server_config_path.to_string_lossy().into_owned())
            .log_path(&server_log_path)
            .start()
            .expect("spawn upstream juicity-server run");

            let roots_pem = std::fs::read(&cert.cert_path).expect("read cert roots");
            let _ready = connect_managed_with_retry(
                server_addr,
                &roots_pem,
                uuid,
                password.as_bytes(),
                &server,
            )
            .await;

            let echo = zuicity_testkit::UdpEchoServer::start()
                .await
                .expect("start UDP echo fixture");
            let client_config_path = artifact.path().join("rust-client.json");
            write_config(
                client_config_path.to_str().expect("utf8 rust client config path"),
                &format!(
                    r#"{{"listen":"{}","server":"{}","uuid":"{}","password":"{}","sni":"localhost","allow_insecure":true,"log_level":"debug"}}"#,
                    listen_addr,
                    server_addr,
                    uuid,
                    password
                ),
            );
            let client_log_path = artifact.path().join("rust-client.log");
            let mut client = zuicity_testkit::ManagedProcessBuilder::new(env!(
                "CARGO_BIN_EXE_zuicity-client"
            ))
            .arg("run")
            .arg("-c")
            .arg(client_config_path.to_str().expect("utf8 rust client config path"))
            .log_path(&client_log_path)
            .start()
            .expect("spawn rust zuicity-client run");

            let echo_addr = echo.local_addr();
            let mut control = connect_tcp_with_retry(listen_addr, &client).await;
            control
                .write_all(&[0x05, 0x01, 0x00])
                .await
                .expect("write SOCKS5 greeting");
            let mut greeting_response = [0_u8; 2];
            tokio::time::timeout(Duration::from_secs(5), control.read_exact(&mut greeting_response))
                .await
                .expect("SOCKS5 greeting timeout")
                .expect("read SOCKS5 greeting response");
            assert_eq!(greeting_response, [0x05, 0x00]);

            control
                .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .expect("write SOCKS5 UDP ASSOCIATE request");
            let mut associate_response = [0_u8; 10];
            tokio::time::timeout(Duration::from_secs(5), control.read_exact(&mut associate_response))
                .await
                .expect("SOCKS5 UDP ASSOCIATE response timeout")
                .expect("read SOCKS5 UDP ASSOCIATE response");
            assert_eq!(&associate_response[..4], &[0x05, 0x00, 0x00, 0x01]);
            let associate_addr = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    associate_response[4],
                    associate_response[5],
                    associate_response[6],
                    associate_response[7],
                )),
                u16::from_be_bytes([associate_response[8], associate_response[9]]),
            );
            assert_eq!(associate_addr.port(), listen_addr.port());

            let std::net::SocketAddr::V4(echo_v4) = echo_addr else {
                panic!("UDP echo fixture should bind IPv4 loopback")
            };
            let payload = b"rust client socks5 udp upstream server";
            let mut udp_request = vec![0x00, 0x00, 0x00, 0x01];
            udp_request.extend_from_slice(&echo_v4.ip().octets());
            udp_request.extend_from_slice(&echo_v4.port().to_be_bytes());
            udp_request.extend_from_slice(payload);

            let udp_client = tokio::net::UdpSocket::bind(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                0,
            )))
            .await
            .expect("bind local UDP client");
            udp_client
                .send_to(&udp_request, associate_addr)
                .await
                .expect("send SOCKS5 UDP datagram");
            let mut response = [0_u8; 1024];
            let (received, from) =
                tokio::time::timeout(Duration::from_secs(5), udp_client.recv_from(&mut response))
                    .await
                    .expect("SOCKS5 UDP associate response timeout")
                    .expect("receive SOCKS5 UDP associate response");
            assert_eq!(from, associate_addr);
            assert_eq!(&response[..4], &[0x00, 0x00, 0x00, 0x01]);
            assert_eq!(&response[4..8], &echo_v4.ip().octets());
            assert_eq!(
                u16::from_be_bytes([response[8], response[9]]),
                echo_v4.port()
            );
            assert_eq!(&response[10..received], payload);

            let evidence = format!(
                "artifact_dir={}\nupstream_server={}\nrust_listener={}\nassociate={}\necho={}\nupstream_server_log={}\nrust_client_log={}\nbuild_log={}\nserver_config={}\nclient_config={}\n",
                artifact.path().display(),
                server_addr,
                listen_addr,
                associate_addr,
                echo_addr,
                server_log_path.display(),
                client_log_path.display(),
                artifact.path().join("upstream-server-build.log").display(),
                server_config_path.display(),
                client_config_path.display()
            );
            std::fs::write(artifact.path().join("addresses.txt"), &evidence)
                .expect("write addresses evidence");
            std::fs::create_dir_all("/tmp/zuicity-workspace")
                .expect("create workspace evidence dir");
            std::fs::write(
                "/tmp/zuicity-workspace/rust-client-socks5-udp-spawned-upstream-server-artifacts.txt",
                evidence,
            )
            .expect("write workspace evidence");

            control.shutdown().await.expect("shutdown SOCKS5 control");
            echo.shutdown().await.expect("shutdown UDP echo fixture");
            let client_exit = client
                .terminate(Duration::from_secs(2))
                .expect("terminate rust zuicity-client run");
            assert_eq!(client_exit.pid, client.pid());
            let server_exit = server
                .terminate(Duration::from_secs(2))
                .expect("terminate upstream juicity-server run");
            assert_eq!(server_exit.pid, server.pid());
            let client_log = std::fs::read_to_string(&client_log_path).unwrap_or_default();
            assert!(
                !client_log.contains("runtime is not implemented"),
                "client_exit={client_exit:?}; log={client_log:?}"
            );
        });
}

#[test]
fn upstream_client_forwarder_reaches_spawned_server_run_tcp_echo() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let artifact = zuicity_testkit::artifact_dir("upstream client spawned server tcp")
                .create()
                .expect("create artifact dir");
            let upstream_client = upstream_client_binary(artifact.path());
            assert!(
                upstream_client.is_file(),
                "missing upstream juicity-client at {}",
                upstream_client.display()
            );
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved_server =
                zuicity_testkit::reserve_udp_socket().expect("reserve server UDP port");
            let server_addr = reserved_server.local_addr().expect("server local addr");
            drop(reserved_server);
            let reserved_forward =
                zuicity_testkit::reserve_tcp_listener().expect("reserve upstream forward TCP port");
            let forward_addr = reserved_forward.local_addr().expect("forward local addr");
            drop(reserved_forward);

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let server_config_path = artifact.path().join("server.json");
            write_config(
                server_config_path.to_str().expect("utf8 server config path"),
                &format!(
                    r#"{{"listen":"{}","users":{{"{}":"{}"}},"certificate":"{}","private_key":"{}","log_level":"debug"}}"#,
                    server_addr,
                    uuid,
                    password,
                    cert.cert_path.display(),
                    cert.key_path.display()
                ),
            );
            let server_log_path = artifact.path().join("zuicity-server.log");
            let mut server = zuicity_testkit::ManagedProcessBuilder::new(env!(
                "CARGO_BIN_EXE_zuicity-server"
            ))
            .arg("run")
            .arg("-c")
            .arg(server_config_path.to_str().expect("utf8 server config path"))
            .log_path(&server_log_path)
            .start()
            .expect("spawn zuicity-server run");

            let roots_pem = std::fs::read(&cert.cert_path).expect("read cert roots");
            let _ready = connect_managed_with_retry(
                server_addr,
                &roots_pem,
                uuid,
                password.as_bytes(),
                &server,
            )
            .await;

            let echo = zuicity_testkit::TcpEchoServer::start()
                .await
                .expect("start TCP echo fixture");
            let client_config_path = artifact.path().join("upstream-client.json");
            write_config(
                client_config_path.to_str().expect("utf8 upstream client config path"),
                &format!(
                    r#"{{"server":"{}","uuid":"{}","password":"{}","sni":"localhost","allow_insecure":true,"log_level":"debug","forward":{{"{}/tcp":"{}"}}}}"#,
                    server_addr,
                    uuid,
                    password,
                    forward_addr,
                    echo.local_addr()
                ),
            );
            let upstream_log_path = artifact.path().join("upstream-client.log");
            let mut upstream = zuicity_testkit::ManagedProcessBuilder::new(
                upstream_client.to_string_lossy().into_owned(),
            )
            .arg("run")
            .arg("-c")
            .arg(client_config_path.to_string_lossy().into_owned())
            .log_path(&upstream_log_path)
            .start()
            .expect("spawn upstream juicity-client run");

            let payload = b"upstream client spawned server tcp";
            let mut stream = connect_tcp_with_retry(forward_addr, &upstream).await;
            stream.write_all(payload).await.expect("write payload");
            let mut echoed = vec![0_u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
                .await
                .expect("upstream client TCP echo timeout")
                .expect("read echoed payload");
            assert_eq!(echoed, payload);
            stream.shutdown().await.expect("shutdown upstream forward stream");

            let evidence = format!(
                "artifact_dir={}\nserver={}\nupstream_forwarder={}\necho={}\nserver_log={}\nupstream_client_log={}\nbuild_log={}\nserver_config={}\nclient_config={}\n",
                artifact.path().display(),
                server_addr,
                forward_addr,
                echo.local_addr(),
                server_log_path.display(),
                upstream_log_path.display(),
                artifact.path().join("upstream-client-build.log").display(),
                server_config_path.display(),
                client_config_path.display()
            );
            std::fs::write(artifact.path().join("addresses.txt"), &evidence)
                .expect("write addresses evidence");
            std::fs::create_dir_all("/tmp/zuicity-workspace")
                .expect("create workspace evidence dir");
            std::fs::write(
                "/tmp/zuicity-workspace/upstream-client-spawned-server-tcp-artifacts.txt",
                evidence,
            )
            .expect("write workspace evidence");

            echo.shutdown().await.expect("shutdown TCP echo fixture");
            let upstream_exit = upstream
                .terminate(Duration::from_secs(2))
                .expect("terminate upstream juicity-client run");
            assert_eq!(upstream_exit.pid, upstream.pid());
            let server_exit = server
                .terminate(Duration::from_secs(2))
                .expect("terminate zuicity-server run");
            assert_eq!(server_exit.pid, server.pid());
            assert!(
                !server_exit.forced,
                "zuicity-server should handle SIGTERM without SIGKILL"
            );
            assert!(
                server_exit.status.success(),
                "server_exit={server_exit:?}; log={}",
                server_log_path.display()
            );
            let server_log = std::fs::read_to_string(&server_log_path).unwrap_or_default();
            assert!(
                !server_log.contains("runtime is not implemented"),
                "server_exit={server_exit:?}; log={server_log:?}"
            );
        });
}

#[test]
fn upstream_client_forwarder_reaches_spawned_server_run_udp_echo() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            let artifact = zuicity_testkit::artifact_dir("upstream client spawned server udp")
                .create()
                .expect("create artifact dir");
            let upstream_client = upstream_client_binary(artifact.path());
            assert!(
                upstream_client.is_file(),
                "missing upstream juicity-client at {}",
                upstream_client.display()
            );
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved_server =
                zuicity_testkit::reserve_udp_socket().expect("reserve server UDP port");
            let server_addr = reserved_server.local_addr().expect("server local addr");
            drop(reserved_server);
            let reserved_forward =
                zuicity_testkit::reserve_udp_socket().expect("reserve upstream forward UDP port");
            let forward_addr = reserved_forward.local_addr().expect("forward local addr");
            drop(reserved_forward);

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let server_config_path = artifact.path().join("server.json");
            write_config(
                server_config_path.to_str().expect("utf8 server config path"),
                &format!(
                    r#"{{"listen":"{}","users":{{"{}":"{}"}},"certificate":"{}","private_key":"{}","log_level":"debug"}}"#,
                    server_addr,
                    uuid,
                    password,
                    cert.cert_path.display(),
                    cert.key_path.display()
                ),
            );
            let server_log_path = artifact.path().join("zuicity-server.log");
            let mut server = zuicity_testkit::ManagedProcessBuilder::new(env!(
                "CARGO_BIN_EXE_zuicity-server"
            ))
            .arg("run")
            .arg("-c")
            .arg(server_config_path.to_str().expect("utf8 server config path"))
            .log_path(&server_log_path)
            .start()
            .expect("spawn zuicity-server run");

            let roots_pem = std::fs::read(&cert.cert_path).expect("read cert roots");
            let _ready = connect_managed_with_retry(
                server_addr,
                &roots_pem,
                uuid,
                password.as_bytes(),
                &server,
            )
            .await;

            let echo = zuicity_testkit::UdpEchoServer::start()
                .await
                .expect("start UDP echo fixture");
            let client_config_path = artifact.path().join("upstream-client.json");
            write_config(
                client_config_path.to_str().expect("utf8 upstream client config path"),
                &format!(
                    r#"{{"server":"{}","uuid":"{}","password":"{}","sni":"localhost","allow_insecure":true,"log_level":"debug","forward":{{"{}/udp":"{}"}}}}"#,
                    server_addr,
                    uuid,
                    password,
                    forward_addr,
                    echo.local_addr()
                ),
            );
            let upstream_log_path = artifact.path().join("upstream-client.log");
            let mut upstream = zuicity_testkit::ManagedProcessBuilder::new(
                upstream_client.to_string_lossy().into_owned(),
            )
            .arg("run")
            .arg("-c")
            .arg(client_config_path.to_string_lossy().into_owned())
            .log_path(&upstream_log_path)
            .start()
            .expect("spawn upstream juicity-client run");

            let socket = tokio::net::UdpSocket::bind(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                0,
            )))
            .await
            .expect("bind local UDP client");
            let payload = b"upstream client spawned server udp";
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut buf = [0_u8; 1024];
            loop {
                socket
                    .send_to(payload, forward_addr)
                    .await
                    .expect("send UDP payload to upstream forwarder");
                match tokio::time::timeout(Duration::from_millis(250), socket.recv_from(&mut buf))
                    .await
                {
                    Ok(Ok((received, from))) => {
                        assert_eq!(from, forward_addr);
                        assert_eq!(&buf[..received], payload);
                        break;
                    }
                    Ok(Err(error)) => panic!("receive UDP echo from upstream forwarder: {error}"),
                    Err(_) if tokio::time::Instant::now() < deadline => {}
                    Err(_) => panic!("timed out waiting for upstream client UDP echo"),
                }
            }

            let evidence = format!(
                "artifact_dir={}\nserver={}\nupstream_forwarder={}\necho={}\nserver_log={}\nupstream_client_log={}\nbuild_log={}\nserver_config={}\nclient_config={}\n",
                artifact.path().display(),
                server_addr,
                forward_addr,
                echo.local_addr(),
                server_log_path.display(),
                upstream_log_path.display(),
                artifact.path().join("upstream-client-build.log").display(),
                server_config_path.display(),
                client_config_path.display()
            );
            std::fs::write(artifact.path().join("addresses.txt"), &evidence)
                .expect("write addresses evidence");
            std::fs::create_dir_all("/tmp/zuicity-workspace")
                .expect("create workspace evidence dir");
            std::fs::write(
                "/tmp/zuicity-workspace/upstream-client-spawned-server-udp-artifacts.txt",
                evidence,
            )
            .expect("write workspace evidence");

            echo.shutdown().await.expect("shutdown UDP echo fixture");
            let upstream_exit = upstream
                .terminate(Duration::from_secs(2))
                .expect("terminate upstream juicity-client run");
            assert_eq!(upstream_exit.pid, upstream.pid());
            let server_exit = server
                .terminate(Duration::from_secs(2))
                .expect("terminate zuicity-server run");
            assert_eq!(server_exit.pid, server.pid());
            assert!(
                !server_exit.forced,
                "zuicity-server should handle SIGTERM without SIGKILL"
            );
            assert!(
                server_exit.status.success(),
                "server_exit={server_exit:?}; log={}",
                server_log_path.display()
            );
            let server_log = std::fs::read_to_string(&server_log_path).unwrap_or_default();
            assert!(
                !server_log.contains("runtime is not implemented"),
                "server_exit={server_exit:?}; log={server_log:?}"
            );
        });
}

#[test]
fn server_run_relay_udp_over_stream_from_rust_client() {
    let _port_bound_runtime_test = port_bound_runtime_test_lock();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(async {
            let artifact = zuicity_testkit::artifact_dir("cli server run udp relay")
                .create()
                .expect("create artifact dir");
            let cert = zuicity_testkit::write_self_signed_cert_fixture(artifact.path(), "localhost")
                .expect("write cert fixture");
            let reserved = zuicity_testkit::reserve_udp_socket().expect("reserve server UDP port");
            let server_addr = reserved.local_addr().expect("server local addr");
            drop(reserved);

            let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("parse uuid");
            let password = "password";
            let config_path = artifact.path().join("server.json");
            write_config(
                config_path.to_str().expect("utf8 config path"),
                &format!(
                    r#"{{"listen":"{}","users":{{"{}":"{}"}},"certificate":"{}","private_key":"{}"}}"#,
                    server_addr,
                    uuid,
                    password,
                    cert.cert_path.display(),
                    cert.key_path.display()
                ),
            );

            let echo = zuicity_testkit::UdpEchoServer::start()
                .await
                .expect("start UDP echo fixture");
            let mut child = ChildGuard::new(spawn_bin(
                "zuicity-server",
                &["run", "-c", config_path.to_str().expect("utf8 config path")],
            ));
            let roots_pem = std::fs::read(&cert.cert_path).expect("read cert roots");
            let connection = connect_with_retry(
                server_addr,
                &roots_pem,
                uuid,
                password.as_bytes(),
                child.child_mut(),
            )
            .await;

            let payload = b"cli server udp relay";
            let echo_addr = echo.local_addr();
            let mut stream = connection
                .open_udp_over_stream(echo_addr.ip(), echo_addr.port())
                .await
                .expect("open UDP-over-stream");
            stream.send_datagram(payload).await.expect("send datagram");
            let echoed = tokio::time::timeout(Duration::from_secs(2), stream.recv_datagram(1024))
                .await
                .expect("UDP relay response timeout")
                .expect("receive datagram");
            assert_eq!(echoed.target, echo_addr);
            assert_eq!(echoed.payload, payload);
            stream.finish().expect("finish UDP stream");
            echo.shutdown().await.expect("shutdown UDP echo fixture");

            let output = child.terminate();
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                !combined.contains("runtime is not implemented"),
                "output={combined:?}"
            );
        });
}

async fn connect_tcp_with_retry(
    addr: std::net::SocketAddr,
    process: &zuicity_testkit::ManagedProcess,
) -> tokio::net::TcpStream {
    let mut last_error = String::new();
    for _ in 0..40 {
        if !process.is_running().expect("poll client process") {
            let log = std::fs::read_to_string(process.log_path()).unwrap_or_default();
            panic!(
                "zuicity-client exited before TCP forwarder readiness; log_path={}; log={log:?}",
                process.log_path().display()
            );
        }
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => return stream,
            Err(error) => last_error = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let log = std::fs::read_to_string(process.log_path()).unwrap_or_default();
    panic!(
        "zuicity-client TCP forwarder did not become ready: {last_error}; log_path={}; log={log:?}",
        process.log_path().display()
    );
}

async fn connect_managed_with_retry(
    server_addr: std::net::SocketAddr,
    roots_pem: &[u8],
    uuid: uuid::Uuid,
    password: &[u8],
    process: &zuicity_testkit::ManagedProcess,
) -> zuicity_transport::AuthenticatedConnection {
    let mut last_error = String::new();
    for _ in 0..40 {
        if !process.is_running().expect("poll server process") {
            let log = std::fs::read_to_string(process.log_path()).unwrap_or_default();
            panic!(
                "zuicity-server exited before readiness; log_path={}; log={log:?}",
                process.log_path().display()
            );
        }
        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())
            .expect("bind QUIC client");
        match client
            .connect_with_roots(server_addr, "localhost", roots_pem, false, uuid, password)
            .await
        {
            Ok(connection) => return connection,
            Err(error) => last_error = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let log = std::fs::read_to_string(process.log_path()).unwrap_or_default();
    panic!(
        "zuicity-server did not become ready: {last_error}; log_path={}; log={log:?}",
        process.log_path().display()
    );
}

async fn connect_with_retry(
    server_addr: std::net::SocketAddr,
    roots_pem: &[u8],
    uuid: uuid::Uuid,
    password: &[u8],
    child: &mut Child,
) -> zuicity_transport::AuthenticatedConnection {
    let mut last_error = String::new();
    for _ in 0..40 {
        if let Some(status) = child.try_wait().expect("poll server child") {
            panic!("zuicity-server exited before readiness: {status}");
        }
        let client = zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into())
            .expect("bind QUIC client");
        match client
            .connect_with_roots(server_addr, "localhost", roots_pem, false, uuid, password)
            .await
        {
            Ok(connection) => return connection,
            Err(error) => last_error = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("zuicity-server did not become ready: {last_error}");
}
