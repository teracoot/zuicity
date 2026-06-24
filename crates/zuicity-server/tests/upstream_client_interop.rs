//! Upstream Juicity client interoperability tests for the Rust server runtime.

use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{Instant, sleep, timeout},
};
use zuicity_config::{load_json_str, validate_server};
use zuicity_server::{ServerRuntime, ServerRuntimeConfig};
use zuicity_testkit::{
    ManagedProcessBuilder, TcpEchoServer, UdpEchoServer, UpstreamBinaries, artifact_dir,
    reserve_tcp_listener, reserve_udp_socket, write_self_signed_cert_fixture,
};

const INTEROP_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_EXIT_TIMEOUT: Duration = Duration::from_secs(2);
static INTEROP_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

use zuicity_testkit::retry_on_addr_in_use;

struct InteropTestGuard {
    _cross_binary: zuicity_testkit::HeavySubprocessTestGuard,
    _in_binary: tokio::sync::MutexGuard<'static, ()>,
}

async fn interop_test_lock() -> InteropTestGuard {
    let in_binary = INTEROP_TEST_LOCK.lock().await;
    let cross_binary = zuicity_testkit::HeavySubprocessTestGuard::acquire();
    InteropTestGuard {
        _cross_binary: cross_binary,
        _in_binary: in_binary,
    }
}

fn upstream_binaries(dir: &Path) -> Result<UpstreamBinaries, Box<dyn std::error::Error>> {
    if let Some(prebuilt_dir) = std::env::var_os("UPSTREAM_JUICITY_BIN_DIR").map(PathBuf::from) {
        return Ok(UpstreamBinaries::from_dir(prebuilt_dir));
    }

    let upstream_root = std::env::var_os("UPSTREAM_JUICITY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root/projects/juicity/juicity"));
    let bin_dir = dir.join("upstream-bin");
    fs::create_dir_all(&bin_dir)?;
    let client = bin_dir.join("juicity-client");
    let build_log = dir.join("upstream-client-build.log");
    let output = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&client)
        .arg("./cmd/client")
        .current_dir(&upstream_root)
        .output()?;
    fs::write(
        &build_log,
        format!(
            "status={}\nstdout={}\nstderr={}\n",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    if !output.status.success() {
        return Err(format!(
            "upstream juicity-client build failed; see {}",
            build_log.display()
        )
        .into());
    }

    Ok(UpstreamBinaries {
        client,
        server: bin_dir.join("juicity-server"),
    })
}

async fn connect_with_retry(
    addr: SocketAddr,
    deadline: Duration,
) -> Result<tokio::net::TcpStream, std::io::Error> {
    let stop_at = Instant::now() + deadline;
    loop {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(error) if Instant::now() >= stop_at => return Err(error),
            Err(_) => sleep(Duration::from_millis(25)).await,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Socks5ConnectRequest {
    target: SocketAddr,
}

async fn start_socks5_tcp_connect_proxy() -> std::io::Result<(
    SocketAddr,
    tokio::sync::mpsc::Receiver<Socks5ConnectRequest>,
    tokio::task::JoinHandle<std::io::Result<()>>,
)> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let local_addr = listener.local_addr()?;
    let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await?;
        let mut greeting = [0_u8; 2];
        inbound.read_exact(&mut greeting).await?;
        if greeting[0] != 0x05 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid SOCKS version",
            ));
        }
        let mut methods = vec![0_u8; greeting[1] as usize];
        inbound.read_exact(&mut methods).await?;
        if !methods.contains(&0x00) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS5 client did not offer no-auth",
            ));
        }
        inbound.write_all(&[0x05, 0x00]).await?;

        let mut request = [0_u8; 4];
        inbound.read_exact(&mut request).await?;
        if request[..3] != [0x05, 0x01, 0x00] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid SOCKS5 CONNECT request",
            ));
        }
        let target = match request[3] {
            0x01 => {
                let mut raw = [0_u8; 6];
                inbound.read_exact(&mut raw).await?;
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
                    u16::from_be_bytes([raw[4], raw[5]]),
                )
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "test proxy only supports IPv4 CONNECT targets",
                ));
            }
        };
        request_tx
            .send(Socks5ConnectRequest { target })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
            })?;
        let mut outbound = tokio::net::TcpStream::connect(target).await?;
        inbound
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
        Ok(())
    });
    Ok((local_addr, request_rx, task))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HttpConnectRequest {
    authority: String,
}

async fn start_http_connect_proxy() -> std::io::Result<(
    SocketAddr,
    tokio::sync::mpsc::Receiver<HttpConnectRequest>,
    tokio::task::JoinHandle<std::io::Result<()>>,
)> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let local_addr = listener.local_addr()?;
    let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await?;
        let mut request = Vec::with_capacity(512);
        let mut byte = [0_u8; 1];
        loop {
            inbound.read_exact(&mut byte).await?;
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
            if request.len() > 8192 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP CONNECT request header too large",
                ));
            }
        }
        let request = String::from_utf8(request)
            .map_err(|source| std::io::Error::new(std::io::ErrorKind::InvalidData, source))?;
        let request_line = request.lines().next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing HTTP request line")
        })?;
        let mut parts = request_line.split_whitespace();
        if parts.next() != Some("CONNECT") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid HTTP CONNECT method",
            ));
        }
        let authority = parts
            .next()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing CONNECT target")
            })?
            .to_owned();
        if parts.next() != Some("HTTP/1.1") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid HTTP CONNECT version",
            ));
        }
        request_tx
            .send(HttpConnectRequest {
                authority: authority.clone(),
            })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
            })?;
        let mut outbound = tokio::net::TcpStream::connect(authority.as_str()).await?;
        inbound
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
        Ok(())
    });
    Ok((local_addr, request_rx, task))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Socks5UdpAssociateRequest {
    target: SocketAddr,
}

async fn start_socks5_udp_associate_proxy() -> std::io::Result<(
    SocketAddr,
    tokio::sync::mpsc::Receiver<Socks5UdpAssociateRequest>,
    tokio::task::JoinHandle<std::io::Result<()>>,
)> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let local_addr = listener.local_addr()?;
    let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move {
        let (mut control, _) = listener.accept().await?;
        let mut greeting = [0_u8; 2];
        control.read_exact(&mut greeting).await?;
        if greeting[0] != 0x05 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid SOCKS version",
            ));
        }
        let mut methods = vec![0_u8; greeting[1] as usize];
        control.read_exact(&mut methods).await?;
        if !methods.contains(&0x00) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS5 client did not offer no-auth",
            ));
        }
        control.write_all(&[0x05, 0x00]).await?;

        let mut request = [0_u8; 4];
        control.read_exact(&mut request).await?;
        if request[..3] != [0x05, 0x03, 0x00] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid SOCKS5 UDP ASSOCIATE request",
            ));
        }
        match request[3] {
            0x01 => {
                let mut raw = [0_u8; 6];
                control.read_exact(&mut raw).await?;
            }
            0x03 => {
                let mut len = [0_u8; 1];
                control.read_exact(&mut len).await?;
                let mut raw = vec![0_u8; len[0] as usize + 2];
                control.read_exact(&mut raw).await?;
            }
            0x04 => {
                let mut raw = [0_u8; 18];
                control.read_exact(&mut raw).await?;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported UDP ASSOCIATE address type",
                ));
            }
        }

        let udp = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let relay_addr = udp.local_addr()?;
        let relay_port = relay_addr.port().to_be_bytes();
        control
            .write_all(&[
                0x05,
                0x00,
                0x00,
                0x01,
                127,
                0,
                0,
                1,
                relay_port[0],
                relay_port[1],
            ])
            .await?;

        let mut datagram = vec![0_u8; 65_535];
        let (received, client_udp_addr) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            udp.recv_from(&mut datagram),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "no UDP packet"))??;
        if received < 10 || datagram[..4] != [0x00, 0x00, 0x00, 0x01] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid SOCKS5 UDP datagram header",
            ));
        }
        let target = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                datagram[4],
                datagram[5],
                datagram[6],
                datagram[7],
            )),
            u16::from_be_bytes([datagram[8], datagram[9]]),
        );
        let payload = datagram[10..received].to_vec();
        request_tx
            .send(Socks5UdpAssociateRequest { target })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
            })?;

        udp.send_to(&payload, target).await?;
        let (response_len, response_peer) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            udp.recv_from(&mut datagram),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "no UDP response"))??;
        let IpAddr::V4(peer_ip) = response_peer.ip() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "test proxy only supports IPv4 UDP responses",
            ));
        };
        let peer_port = response_peer.port().to_be_bytes();
        let mut encoded = Vec::with_capacity(10 + response_len);
        encoded.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        encoded.extend_from_slice(&peer_ip.octets());
        encoded.extend_from_slice(&peer_port);
        encoded.extend_from_slice(&datagram[..response_len]);
        udp.send_to(&encoded, client_udp_addr).await?;
        let mut drain = [0_u8; 1];
        let _ = control.read(&mut drain).await;
        Ok(())
    });
    Ok((local_addr, request_rx, task))
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

#[tokio::test]
async fn upstream_client_forwarder_reaches_rust_server_tcp_echo_with_real_auth()
-> Result<(), Box<dyn std::error::Error>> {
    let _interop_guard = interop_test_lock().await;
    let artifacts = artifact_dir("upstream client rust server tcp interop").create()?;
    let bins = upstream_binaries(artifacts.path())?;
    assert!(
        bins.client.is_file(),
        "missing upstream juicity-client at {}",
        bins.client.display()
    );

    let cert = write_self_signed_cert_fixture(artifacts.path(), "server.local")?;
    let echo = TcpEchoServer::start().await?;
    let reserved_forward = reserve_tcp_listener()?;
    let forward_addr = reserved_forward.local_addr()?;
    drop(reserved_forward);

    let uuid = "00000000-0000-0000-0000-000000000101";
    let password = "upstream client rust tcp password";
    let server_config = validate_server(load_json_str(&format!(
        r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
    ))?)?;
    let runtime = ServerRuntime::new(ServerRuntimeConfig::from_config(server_config));
    let cert_pem = fs::read(&cert.cert_path)?;
    let key_pem = fs::read(&cert.key_path)?;
    let bound = runtime.bind_with_pem(([127, 0, 0, 1], 0).into(), &cert_pem, &key_pem)?;
    let server_addr = bound.local_addr()?;
    let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

    let client_config_path = artifacts.path().join("upstream-client.json");
    fs::write(
        &client_config_path,
        format!(
            r#"{{"server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"{}","allow_insecure":true,"log_level":"debug","forward":{{"{forward_addr}/tcp":"{}"}}}}"#,
            cert.common_name,
            echo.local_addr()
        ),
    )?;

    let client_log_path = artifacts.path().join("upstream-client.log");
    let mut upstream = ManagedProcessBuilder::new(bins.client.to_string_lossy().into_owned())
        .arg("run")
        .arg("-c")
        .arg(client_config_path.to_string_lossy().into_owned())
        .log_path(&client_log_path)
        .start()?;
    fs::write(
        artifacts.path().join("upstream-client.pid"),
        upstream.pid().to_string(),
    )?;
    sleep(Duration::from_millis(150)).await;
    assert!(upstream.is_running()?, "upstream client exited early");

    let evidence = format!(
        "artifact_dir={}\nrust_server={server_addr}\nupstream_forwarder={forward_addr}\necho={}\nupstream_client_log={}\nbuild_log={}\npid_file={}\n",
        artifacts.path().display(),
        echo.local_addr(),
        client_log_path.display(),
        artifacts.path().join("upstream-client-build.log").display(),
        artifacts.path().join("upstream-client.pid").display()
    );
    fs::write(artifacts.path().join("addresses.txt"), &evidence)?;
    fs::create_dir_all("/tmp/zuicity-workspace")?;
    fs::write(
        "/tmp/zuicity-workspace/upstream-client-rust-server-tcp-interop-artifacts.txt",
        evidence,
    )?;

    let payload = b"upstream client rust server tcp interop";
    let mut stream = connect_with_retry(forward_addr, INTEROP_TIMEOUT).await?;
    stream.write_all(payload).await?;
    let mut echoed = vec![0_u8; payload.len()];
    timeout(INTEROP_TIMEOUT, stream.read_exact(&mut echoed)).await??;
    assert_eq!(echoed, payload);
    stream.shutdown().await?;
    let mut eof = Vec::new();
    timeout(INTEROP_TIMEOUT, stream.read_to_end(&mut eof)).await??;
    assert!(
        eof.is_empty(),
        "expected EOF after echoed payload, got {eof:?}"
    );

    let report = timeout(INTEROP_TIMEOUT, server_task).await???;
    assert_eq!(report.target, echo.local_addr());
    assert_eq!(
        report.bytes_from_client,
        b"upstream client rust server tcp interop".len() as u64
    );
    assert_eq!(
        report.bytes_from_target,
        b"upstream client rust server tcp interop".len() as u64
    );

    echo.shutdown().await?;
    let exit = upstream.terminate(PROCESS_EXIT_TIMEOUT)?;
    fs::write(
        artifacts.path().join("upstream-client-teardown.txt"),
        format!("{exit:?}\n"),
    )?;
    Ok(())
}

#[tokio::test]
async fn upstream_client_forwarder_reaches_rust_server_tcp_echo_through_socks5_dialer_link()
-> Result<(), Box<dyn std::error::Error>> {
    let _interop_guard = interop_test_lock().await;
    let artifacts = artifact_dir("upstream client rust server tcp dialer link").create()?;
    let bins = upstream_binaries(artifacts.path())?;
    assert!(
        bins.client.is_file(),
        "missing upstream juicity-client at {}",
        bins.client.display()
    );

    let cert = write_self_signed_cert_fixture(artifacts.path(), "server.local")?;
    let echo = TcpEchoServer::start().await?;
    let reserved_forward = reserve_tcp_listener()?;
    let forward_addr = reserved_forward.local_addr()?;
    drop(reserved_forward);
    let (proxy_addr, mut requests, proxy_task) = start_socks5_tcp_connect_proxy().await?;

    let uuid = "00000000-0000-0000-0000-000000000104";
    let password = "upstream client rust tcp dialer link password";
    let server_config = validate_server(load_json_str(&format!(
        r#"{{"listen":"127.0.0.1:0","dialer_link":"socks5://{proxy_addr}","users":{{"{uuid}":"{password}"}}}}"#
    ))?)?;
    let runtime = ServerRuntime::new(ServerRuntimeConfig::from_config(server_config));
    let cert_pem = fs::read(&cert.cert_path)?;
    let key_pem = fs::read(&cert.key_path)?;
    let bound = runtime.bind_with_pem(([127, 0, 0, 1], 0).into(), &cert_pem, &key_pem)?;
    let server_addr = bound.local_addr()?;
    let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

    let client_config_path = artifacts.path().join("upstream-client.json");
    fs::write(
        &client_config_path,
        format!(
            r#"{{"server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"{}","allow_insecure":true,"log_level":"debug","forward":{{"{forward_addr}/tcp":"{}"}}}}"#,
            cert.common_name,
            echo.local_addr()
        ),
    )?;

    let client_log_path = artifacts.path().join("upstream-client.log");
    let mut upstream = ManagedProcessBuilder::new(bins.client.to_string_lossy().into_owned())
        .arg("run")
        .arg("-c")
        .arg(client_config_path.to_string_lossy().into_owned())
        .log_path(&client_log_path)
        .start()?;
    fs::write(
        artifacts.path().join("upstream-client.pid"),
        upstream.pid().to_string(),
    )?;
    sleep(Duration::from_millis(150)).await;
    assert!(upstream.is_running()?, "upstream client exited early");

    let evidence = format!(
        "artifact_dir={}\nrust_server={server_addr}\nupstream_forwarder={forward_addr}\nsocks5_proxy={proxy_addr}\necho={}\nupstream_client_log={}\nbuild_log={}\npid_file={}\n",
        artifacts.path().display(),
        echo.local_addr(),
        client_log_path.display(),
        artifacts.path().join("upstream-client-build.log").display(),
        artifacts.path().join("upstream-client.pid").display()
    );
    fs::write(artifacts.path().join("addresses.txt"), &evidence)?;
    fs::create_dir_all("/tmp/zuicity-workspace/egress")?;
    fs::write(
        "/tmp/zuicity-workspace/egress/upstream-client-rust-server-tcp-dialer-link-artifacts.txt",
        evidence,
    )?;

    let payload = b"upstream client rust server tcp dialer link";
    let mut stream = connect_with_retry(forward_addr, INTEROP_TIMEOUT).await?;
    stream.write_all(payload).await?;
    let mut echoed = vec![0_u8; payload.len()];
    timeout(INTEROP_TIMEOUT, stream.read_exact(&mut echoed)).await??;
    assert_eq!(echoed, payload);
    stream.shutdown().await?;
    let mut eof = Vec::new();
    timeout(INTEROP_TIMEOUT, stream.read_to_end(&mut eof)).await??;
    assert!(
        eof.is_empty(),
        "expected EOF after echoed payload, got {eof:?}"
    );

    let request = timeout(INTEROP_TIMEOUT, requests.recv())
        .await?
        .ok_or("SOCKS5 proxy request channel closed")?;
    assert_eq!(request.target, echo.local_addr());
    let report = timeout(INTEROP_TIMEOUT, server_task).await???;
    assert_eq!(report.target, proxy_addr);
    assert_eq!(report.bytes_from_client, payload.len() as u64);
    assert_eq!(report.bytes_from_target, payload.len() as u64);
    drop(stream);
    proxy_task.await??;

    echo.shutdown().await?;
    let exit = upstream.terminate(PROCESS_EXIT_TIMEOUT)?;
    fs::write(
        artifacts.path().join("upstream-client-teardown.txt"),
        format!("{exit:?}\n"),
    )?;
    Ok(())
}

#[tokio::test]
async fn upstream_client_forwarder_reaches_rust_server_tcp_echo_through_http_dialer_link()
-> Result<(), Box<dyn std::error::Error>> {
    let _interop_guard = interop_test_lock().await;
    let artifacts = artifact_dir("upstream client rust server tcp http dialer link").create()?;
    let bins = upstream_binaries(artifacts.path())?;
    assert!(
        bins.client.is_file(),
        "missing upstream juicity-client at {}",
        bins.client.display()
    );

    let cert = write_self_signed_cert_fixture(artifacts.path(), "server.local")?;
    let echo = TcpEchoServer::start().await?;
    let reserved_forward = reserve_tcp_listener()?;
    let forward_addr = reserved_forward.local_addr()?;
    drop(reserved_forward);
    let (proxy_addr, mut requests, proxy_task) = start_http_connect_proxy().await?;

    let uuid = "00000000-0000-0000-0000-000000000106";
    let password = "upstream client rust tcp http dialer link password";
    let server_config = validate_server(load_json_str(&format!(
        r#"{{"listen":"127.0.0.1:0","dialer_link":"http://{proxy_addr}","users":{{"{uuid}":"{password}"}}}}"#
    ))?)?;
    let runtime = ServerRuntime::new(ServerRuntimeConfig::from_config(server_config));
    let cert_pem = fs::read(&cert.cert_path)?;
    let key_pem = fs::read(&cert.key_path)?;
    let bound = runtime.bind_with_pem(([127, 0, 0, 1], 0).into(), &cert_pem, &key_pem)?;
    let server_addr = bound.local_addr()?;
    let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

    let client_config_path = artifacts.path().join("upstream-client.json");
    fs::write(
        &client_config_path,
        format!(
            r#"{{"server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"{}","allow_insecure":true,"log_level":"debug","forward":{{"{forward_addr}/tcp":"{}"}}}}"#,
            cert.common_name,
            echo.local_addr()
        ),
    )?;

    let client_log_path = artifacts.path().join("upstream-client.log");
    let mut upstream = ManagedProcessBuilder::new(bins.client.to_string_lossy().into_owned())
        .arg("run")
        .arg("-c")
        .arg(client_config_path.to_string_lossy().into_owned())
        .log_path(&client_log_path)
        .start()?;
    fs::write(
        artifacts.path().join("upstream-client.pid"),
        upstream.pid().to_string(),
    )?;
    sleep(Duration::from_millis(150)).await;
    assert!(upstream.is_running()?, "upstream client exited early");

    let evidence = format!(
        "artifact_dir={}
rust_server={server_addr}
upstream_forwarder={forward_addr}
http_proxy={proxy_addr}
echo={}
upstream_client_log={}
build_log={}
pid_file={}
",
        artifacts.path().display(),
        echo.local_addr(),
        client_log_path.display(),
        artifacts.path().join("upstream-client-build.log").display(),
        artifacts.path().join("upstream-client.pid").display()
    );
    fs::write(artifacts.path().join("addresses.txt"), &evidence)?;
    fs::create_dir_all("/tmp/zuicity-workspace/egress")?;
    fs::write(
        "/tmp/zuicity-workspace/egress/upstream-client-rust-server-tcp-http-dialer-link-artifacts.txt",
        evidence,
    )?;

    let payload = b"upstream client rust server tcp http dialer link";
    let mut stream = connect_with_retry(forward_addr, INTEROP_TIMEOUT).await?;
    stream.write_all(payload).await?;
    let mut echoed = vec![0_u8; payload.len()];
    timeout(INTEROP_TIMEOUT, stream.read_exact(&mut echoed)).await??;
    assert_eq!(echoed, payload);
    stream.shutdown().await?;
    let mut eof = Vec::new();
    timeout(INTEROP_TIMEOUT, stream.read_to_end(&mut eof)).await??;
    assert!(
        eof.is_empty(),
        "expected EOF after echoed payload, got {eof:?}"
    );

    let request = timeout(INTEROP_TIMEOUT, requests.recv())
        .await?
        .ok_or("HTTP proxy request channel closed")?;
    assert_eq!(request.authority, echo.local_addr().to_string());
    let report = timeout(INTEROP_TIMEOUT, server_task).await???;
    assert_eq!(report.target, proxy_addr);
    assert_eq!(report.bytes_from_client, payload.len() as u64);
    assert_eq!(report.bytes_from_target, payload.len() as u64);
    drop(stream);
    proxy_task.await??;

    echo.shutdown().await?;
    let exit = upstream.terminate(PROCESS_EXIT_TIMEOUT)?;
    fs::write(
        artifacts.path().join("upstream-client-teardown.txt"),
        format!(
            "{exit:?}
"
        ),
    )?;
    Ok(())
}

#[tokio::test]
async fn upstream_client_forwarder_reaches_rust_server_udp_echo_with_real_auth()
-> Result<(), Box<dyn std::error::Error>> {
    let _interop_guard = interop_test_lock().await;
    let artifacts = artifact_dir("upstream client rust server udp interop").create()?;
    let bins = upstream_binaries(artifacts.path())?;
    assert!(
        bins.client.is_file(),
        "missing upstream juicity-client at {}",
        bins.client.display()
    );

    let cert = write_self_signed_cert_fixture(artifacts.path(), "server.local")?;
    let echo = UdpEchoServer::start().await?;
    let reserved_forward = reserve_udp_socket()?;
    let forward_addr = reserved_forward.local_addr()?;
    drop(reserved_forward);

    let uuid = "00000000-0000-0000-0000-000000000102";
    let password = "upstream client rust udp password";
    let server_config = validate_server(load_json_str(&format!(
        r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
    ))?)?;
    let runtime = ServerRuntime::new(ServerRuntimeConfig::from_config(server_config));
    let cert_pem = fs::read(&cert.cert_path)?;
    let key_pem = fs::read(&cert.key_path)?;
    let bound = runtime.bind_with_pem(([127, 0, 0, 1], 0).into(), &cert_pem, &key_pem)?;
    let server_addr = bound.local_addr()?;
    let server_task = tokio::spawn(async move {
        bound
            .accept_one_udp_over_stream_with_idle_timeout(INTEROP_TIMEOUT)
            .await
    });

    let client_config_path = artifacts.path().join("upstream-client.json");
    fs::write(
        &client_config_path,
        format!(
            r#"{{"server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"{}","allow_insecure":true,"log_level":"debug","forward":{{"{forward_addr}/udp":"{}"}}}}"#,
            cert.common_name,
            echo.local_addr()
        ),
    )?;

    let client_log_path = artifacts.path().join("upstream-client.log");
    let mut upstream = ManagedProcessBuilder::new(bins.client.to_string_lossy().into_owned())
        .arg("run")
        .arg("-c")
        .arg(client_config_path.to_string_lossy().into_owned())
        .log_path(&client_log_path)
        .start()?;
    fs::write(
        artifacts.path().join("upstream-client.pid"),
        upstream.pid().to_string(),
    )?;
    sleep(Duration::from_millis(150)).await;
    assert!(upstream.is_running()?, "upstream client exited early");

    let evidence = format!(
        "artifact_dir={}\nrust_server={server_addr}\nupstream_forwarder={forward_addr}\necho={}\nupstream_client_log={}\nbuild_log={}\npid_file={}\n",
        artifacts.path().display(),
        echo.local_addr(),
        client_log_path.display(),
        artifacts.path().join("upstream-client-build.log").display(),
        artifacts.path().join("upstream-client.pid").display()
    );
    fs::write(artifacts.path().join("addresses.txt"), &evidence)?;
    fs::create_dir_all("/tmp/zuicity-workspace")?;
    fs::write(
        "/tmp/zuicity-workspace/upstream-client-rust-server-udp-interop-artifacts.txt",
        evidence,
    )?;

    let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let payload = b"upstream client rust server udp interop";
    let deadline = Instant::now() + INTEROP_TIMEOUT;
    let mut buf = [0_u8; 1024];
    loop {
        socket.send_to(payload, forward_addr).await?;
        match timeout(Duration::from_millis(250), socket.recv_from(&mut buf)).await {
            Ok(Ok((received, from))) => {
                assert_eq!(from, forward_addr);
                assert_eq!(&buf[..received], payload);
                break;
            }
            Ok(Err(error)) => return Err(error.into()),
            Err(_) if Instant::now() < deadline => {}
            Err(_) => return Err("timed out waiting for upstream client UDP echo".into()),
        }
    }

    let exit = upstream.terminate(PROCESS_EXIT_TIMEOUT)?;
    fs::write(
        artifacts.path().join("upstream-client-teardown.txt"),
        format!("{exit:?}\n"),
    )?;

    let report = timeout(INTEROP_TIMEOUT, server_task).await???;
    assert_eq!(report.target, echo.local_addr());
    assert!(report.bytes_from_client >= payload.len() as u64);
    assert!(report.bytes_from_target >= payload.len() as u64);

    echo.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn upstream_client_forwarder_reaches_rust_server_udp_echo_through_socks5_dialer_link()
-> Result<(), Box<dyn std::error::Error>> {
    let _interop_guard = interop_test_lock().await;
    let artifacts = artifact_dir("upstream client rust server udp dialer link").create()?;
    let bins = upstream_binaries(artifacts.path())?;
    assert!(
        bins.client.is_file(),
        "missing upstream juicity-client at {}",
        bins.client.display()
    );

    let cert = write_self_signed_cert_fixture(artifacts.path(), "server.local")?;
    let echo = UdpEchoServer::start().await?;
    let reserved_forward = reserve_udp_socket()?;
    let forward_addr = reserved_forward.local_addr()?;
    drop(reserved_forward);
    let (proxy_addr, mut requests, proxy_task) = start_socks5_udp_associate_proxy().await?;

    let uuid = "00000000-0000-0000-0000-000000000105";
    let password = "upstream client rust udp dialer link password";
    let server_config = validate_server(load_json_str(&format!(
        r#"{{"listen":"127.0.0.1:0","dialer_link":"socks5://{proxy_addr}","users":{{"{uuid}":"{password}"}}}}"#
    ))?)?;
    let runtime = ServerRuntime::new(ServerRuntimeConfig::from_config(server_config));
    let cert_pem = fs::read(&cert.cert_path)?;
    let key_pem = fs::read(&cert.key_path)?;
    let bound = runtime.bind_with_pem(([127, 0, 0, 1], 0).into(), &cert_pem, &key_pem)?;
    let server_addr = bound.local_addr()?;
    let server_task = tokio::spawn(async move {
        bound
            .accept_one_udp_over_stream_with_idle_timeout(INTEROP_TIMEOUT)
            .await
    });

    let client_config_path = artifacts.path().join("upstream-client.json");
    fs::write(
        &client_config_path,
        format!(
            r#"{{"server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"{}","allow_insecure":true,"log_level":"debug","forward":{{"{forward_addr}/udp":"{}"}}}}"#,
            cert.common_name,
            echo.local_addr()
        ),
    )?;

    let client_log_path = artifacts.path().join("upstream-client.log");
    let mut upstream = ManagedProcessBuilder::new(bins.client.to_string_lossy().into_owned())
        .arg("run")
        .arg("-c")
        .arg(client_config_path.to_string_lossy().into_owned())
        .log_path(&client_log_path)
        .start()?;
    fs::write(
        artifacts.path().join("upstream-client.pid"),
        upstream.pid().to_string(),
    )?;
    sleep(Duration::from_millis(150)).await;
    assert!(upstream.is_running()?, "upstream client exited early");

    let evidence = format!(
        "artifact_dir={}\nrust_server={server_addr}\nupstream_forwarder={forward_addr}\nsocks5_proxy={proxy_addr}\necho={}\nupstream_client_log={}\nbuild_log={}\npid_file={}\n",
        artifacts.path().display(),
        echo.local_addr(),
        client_log_path.display(),
        artifacts.path().join("upstream-client-build.log").display(),
        artifacts.path().join("upstream-client.pid").display()
    );
    fs::write(artifacts.path().join("addresses.txt"), &evidence)?;
    fs::create_dir_all("/tmp/zuicity-workspace/egress")?;
    fs::write(
        "/tmp/zuicity-workspace/egress/upstream-client-rust-server-udp-dialer-link-artifacts.txt",
        evidence,
    )?;

    let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let payload = b"upstream client rust server udp dialer link";
    let deadline = Instant::now() + INTEROP_TIMEOUT;
    let mut buf = [0_u8; 1024];
    loop {
        socket.send_to(payload, forward_addr).await?;
        match timeout(Duration::from_millis(250), socket.recv_from(&mut buf)).await {
            Ok(Ok((received, from))) => {
                assert_eq!(from, forward_addr);
                assert_eq!(&buf[..received], payload);
                break;
            }
            Ok(Err(error)) => return Err(error.into()),
            Err(_) if Instant::now() < deadline => {}
            Err(_) => {
                return Err("timed out waiting for upstream client UDP dialer_link echo".into());
            }
        }
    }

    let request = timeout(INTEROP_TIMEOUT, requests.recv())
        .await?
        .ok_or("SOCKS5 proxy request channel closed")?;
    assert_eq!(request.target, echo.local_addr());

    let exit = upstream.terminate(PROCESS_EXIT_TIMEOUT)?;
    fs::write(
        artifacts.path().join("upstream-client-teardown.txt"),
        format!("{exit:?}\n"),
    )?;

    let report = timeout(INTEROP_TIMEOUT, server_task).await???;
    assert_eq!(report.target, echo.local_addr());
    assert!(report.bytes_from_client >= payload.len() as u64);
    assert!(report.bytes_from_target >= payload.len() as u64);
    proxy_task.await??;
    echo.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn upstream_client_forwarder_reaches_rust_server_udp_echo_through_socks5_shadowsocks_dialer_chain()
-> Result<(), Box<dyn std::error::Error>> {
    let _interop_guard = interop_test_lock().await;
    retry_on_addr_in_use(|| async {
    let artifacts =
        artifact_dir("upstream client rust server udp socks5 shadowsocks chain").create()?;
    let bins = upstream_binaries(artifacts.path())?;
    assert!(
        bins.client.is_file(),
        "missing upstream juicity-client at {}",
        bins.client.display()
    );

    let cert = write_self_signed_cert_fixture(artifacts.path(), "server.local")?;
    let echo = UdpEchoServer::start().await?;
    let reserved_forward = reserve_udp_socket()?;
    let forward_addr = reserved_forward.local_addr()?;
    drop(reserved_forward);
    let (socks_proxy_addr, mut socks_requests, socks_proxy_task) =
        start_socks5_udp_associate_proxy().await?;
    let shadowsocks_password = "upstream client rust socks5 shadowsocks udp chain proxy password";
    let (
        shadowsocks_proxy_addr,
        mut shadowsocks_tcp_requests,
        mut shadowsocks_udp_requests,
        shadowsocks_proxy_task,
    ) = start_shadowsocks_tcp_udp_proxy(
        shadowsocks_password,
        shadowsocks::crypto::CipherKind::AES_128_GCM,
    )
    .await?;
    let userinfo =
        general_purpose::URL_SAFE_NO_PAD.encode(format!("aes-128-gcm:{shadowsocks_password}"));

    let uuid = "00000000-0000-0000-0000-000000000107";
    let password = "upstream client rust udp socks5 shadowsocks chain password";
    let server_config = validate_server(load_json_str(&format!(
        r#"{{"listen":"127.0.0.1:0","dialer_link":"socks5://{socks_proxy_addr} -> ss://{userinfo}@{shadowsocks_proxy_addr}","users":{{"{uuid}":"{password}"}}}}"#
    ))?)?;
    let runtime = ServerRuntime::new(ServerRuntimeConfig::from_config(server_config));
    let cert_pem = fs::read(&cert.cert_path)?;
    let key_pem = fs::read(&cert.key_path)?;
    let bound = runtime.bind_with_pem(([127, 0, 0, 1], 0).into(), &cert_pem, &key_pem)?;
    let server_addr = bound.local_addr()?;
    let server_task = tokio::spawn(async move {
        bound
            .accept_one_udp_over_stream_with_idle_timeout(INTEROP_TIMEOUT)
            .await
    });

    let client_config_path = artifacts.path().join("upstream-client.json");
    fs::write(
        &client_config_path,
        format!(
            r#"{{"server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"{}","allow_insecure":true,"log_level":"debug","forward":{{"{forward_addr}/udp":"{}"}}}}"#,
            cert.common_name,
            echo.local_addr()
        ),
    )?;

    let client_log_path = artifacts.path().join("upstream-client.log");
    let mut upstream = ManagedProcessBuilder::new(bins.client.to_string_lossy().into_owned())
        .arg("run")
        .arg("-c")
        .arg(client_config_path.to_string_lossy().into_owned())
        .log_path(&client_log_path)
        .start()?;
    fs::write(
        artifacts.path().join("upstream-client.pid"),
        upstream.pid().to_string(),
    )?;
    sleep(Duration::from_millis(150)).await;
    assert!(upstream.is_running()?, "upstream client exited early");

    let evidence = format!(
        "artifact_dir={}\nrust_server={server_addr}\nupstream_forwarder={forward_addr}\nsocks5_proxy={socks_proxy_addr}\nshadowsocks_proxy={shadowsocks_proxy_addr}\necho={}\nupstream_client_log={}\nbuild_log={}\npid_file={}\n",
        artifacts.path().display(),
        echo.local_addr(),
        client_log_path.display(),
        artifacts.path().join("upstream-client-build.log").display(),
        artifacts.path().join("upstream-client.pid").display()
    );
    fs::write(artifacts.path().join("addresses.txt"), &evidence)?;
    fs::create_dir_all("/tmp/zuicity-workspace/egress")?;
    fs::write(
        "/tmp/zuicity-workspace/egress/upstream-client-rust-server-udp-socks5-shadowsocks-chain-artifacts.txt",
        evidence,
    )?;

    let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let payload = b"upstream client rust server udp socks5 shadowsocks chain";
    let deadline = Instant::now() + INTEROP_TIMEOUT;
    let mut buf = [0_u8; 1024];
    loop {
        socket.send_to(payload, forward_addr).await?;
        match timeout(Duration::from_millis(250), socket.recv_from(&mut buf)).await {
            Ok(Ok((received, from))) => {
                assert_eq!(from, forward_addr);
                assert_eq!(&buf[..received], payload);
                break;
            }
            Ok(Err(error)) => return Err(error.into()),
            Err(_) if Instant::now() < deadline => {}
            Err(_) => {
                return Err(
                    "timed out waiting for upstream client UDP socks5 shadowsocks chain echo"
                        .into(),
                );
            }
        }
    }

    let shadowsocks_tcp_request = timeout(INTEROP_TIMEOUT, shadowsocks_tcp_requests.recv())
        .await?
        .ok_or("Shadowsocks TCP request channel closed")?;
    assert_eq!(shadowsocks_tcp_request.target, socks_proxy_addr);
    let shadowsocks_udp_request = timeout(INTEROP_TIMEOUT, shadowsocks_udp_requests.recv())
        .await?
        .ok_or("Shadowsocks UDP request channel closed")?;
    assert_eq!(shadowsocks_udp_request.target.ip(), socks_proxy_addr.ip());
    let socks_request = timeout(INTEROP_TIMEOUT, socks_requests.recv())
        .await?
        .ok_or("SOCKS5 proxy request channel closed")?;
    assert_eq!(socks_request.target, echo.local_addr());

    let exit = upstream.terminate(PROCESS_EXIT_TIMEOUT)?;
    fs::write(
        artifacts.path().join("upstream-client-teardown.txt"),
        format!("{exit:?}\n"),
    )?;

    let report = timeout(INTEROP_TIMEOUT, server_task).await???;
    assert_eq!(report.target, echo.local_addr());
    assert!(report.bytes_from_client >= payload.len() as u64);
    assert!(report.bytes_from_target >= payload.len() as u64);
    socks_proxy_task.await??;
    shadowsocks_proxy_task.await??;
    echo.shutdown().await?;
    Ok(())
    })
    .await
}

#[tokio::test]
async fn upstream_client_forwarder_reaches_rust_server_udp_echo_through_shadowsocks_socks5_dialer_chain()
-> Result<(), Box<dyn std::error::Error>> {
    let _interop_guard = interop_test_lock().await;
    retry_on_addr_in_use(|| async {
    let artifacts =
        artifact_dir("upstream client rust server udp shadowsocks socks5 chain").create()?;
    let bins = upstream_binaries(artifacts.path())?;
    assert!(
        bins.client.is_file(),
        "missing upstream juicity-client at {}",
        bins.client.display()
    );

    let cert = write_self_signed_cert_fixture(artifacts.path(), "server.local")?;
    let echo = UdpEchoServer::start().await?;
    let reserved_forward = reserve_udp_socket()?;
    let forward_addr = reserved_forward.local_addr()?;
    drop(reserved_forward);
    let (socks_proxy_addr, mut socks_requests, socks_proxy_task) =
        start_socks5_udp_associate_proxy().await?;
    let shadowsocks_password = "upstream client rust shadowsocks socks5 udp chain proxy password";
    let (shadowsocks_proxy_addr, mut shadowsocks_requests, shadowsocks_proxy_task) =
        start_shadowsocks_udp_proxy(
            shadowsocks_password,
            shadowsocks::crypto::CipherKind::AES_128_GCM,
        )
        .await?;
    let userinfo =
        general_purpose::URL_SAFE_NO_PAD.encode(format!("aes-128-gcm:{shadowsocks_password}"));

    let uuid = "00000000-0000-0000-0000-000000000108";
    let password = "upstream client rust udp shadowsocks socks5 chain password";
    let server_config = validate_server(load_json_str(&format!(
        r#"{{"listen":"127.0.0.1:0","dialer_link":"ss://{userinfo}@{shadowsocks_proxy_addr} -> socks5://{socks_proxy_addr}","users":{{"{uuid}":"{password}"}}}}"#
    ))?)?;
    let runtime = ServerRuntime::new(ServerRuntimeConfig::from_config(server_config));
    let cert_pem = fs::read(&cert.cert_path)?;
    let key_pem = fs::read(&cert.key_path)?;
    let bound = runtime.bind_with_pem(([127, 0, 0, 1], 0).into(), &cert_pem, &key_pem)?;
    let server_addr = bound.local_addr()?;
    let server_task = tokio::spawn(async move {
        bound
            .accept_one_udp_over_stream_with_idle_timeout(INTEROP_TIMEOUT)
            .await
    });

    let client_config_path = artifacts.path().join("upstream-client.json");
    fs::write(
        &client_config_path,
        format!(
            r#"{{"server":"{server_addr}","uuid":"{uuid}","password":"{password}","sni":"{}","allow_insecure":true,"log_level":"debug","forward":{{"{forward_addr}/udp":"{}"}}}}"#,
            cert.common_name,
            echo.local_addr()
        ),
    )?;

    let client_log_path = artifacts.path().join("upstream-client.log");
    let mut upstream = ManagedProcessBuilder::new(bins.client.to_string_lossy().into_owned())
        .arg("run")
        .arg("-c")
        .arg(client_config_path.to_string_lossy().into_owned())
        .log_path(&client_log_path)
        .start()?;
    fs::write(
        artifacts.path().join("upstream-client.pid"),
        upstream.pid().to_string(),
    )?;
    sleep(Duration::from_millis(150)).await;
    assert!(upstream.is_running()?, "upstream client exited early");

    let evidence = format!(
        "artifact_dir={}\nrust_server={server_addr}\nupstream_forwarder={forward_addr}\nshadowsocks_proxy={shadowsocks_proxy_addr}\nsocks5_proxy={socks_proxy_addr}\necho={}\nupstream_client_log={}\nbuild_log={}\npid_file={}\n",
        artifacts.path().display(),
        echo.local_addr(),
        client_log_path.display(),
        artifacts.path().join("upstream-client-build.log").display(),
        artifacts.path().join("upstream-client.pid").display()
    );
    fs::write(artifacts.path().join("addresses.txt"), &evidence)?;
    fs::create_dir_all("/tmp/zuicity-workspace/egress")?;
    fs::write(
        "/tmp/zuicity-workspace/egress/upstream-client-rust-server-udp-shadowsocks-socks5-chain-artifacts.txt",
        evidence,
    )?;

    let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let payload = b"upstream client rust server udp shadowsocks socks5 chain";
    let deadline = Instant::now() + INTEROP_TIMEOUT;
    let mut buf = [0_u8; 1024];
    loop {
        socket.send_to(payload, forward_addr).await?;
        match timeout(Duration::from_millis(250), socket.recv_from(&mut buf)).await {
            Ok(Ok((received, from))) => {
                assert_eq!(from, forward_addr);
                assert_eq!(&buf[..received], payload);
                break;
            }
            Ok(Err(error)) => return Err(error.into()),
            Err(_) if Instant::now() < deadline => {}
            Err(_) => {
                return Err(
                    "timed out waiting for upstream client UDP shadowsocks socks5 chain echo"
                        .into(),
                );
            }
        }
    }

    let socks_request = timeout(INTEROP_TIMEOUT, socks_requests.recv())
        .await?
        .ok_or("SOCKS5 proxy request channel closed")?;
    assert_eq!(socks_request.target, shadowsocks_proxy_addr);
    let shadowsocks_request = timeout(INTEROP_TIMEOUT, shadowsocks_requests.recv())
        .await?
        .ok_or("Shadowsocks UDP request channel closed")?;
    assert_eq!(shadowsocks_request.target, echo.local_addr());

    let exit = upstream.terminate(PROCESS_EXIT_TIMEOUT)?;
    fs::write(
        artifacts.path().join("upstream-client-teardown.txt"),
        format!("{exit:?}\n"),
    )?;

    let report = timeout(INTEROP_TIMEOUT, server_task).await???;
    assert_eq!(report.target, echo.local_addr());
    assert!(report.bytes_from_client >= payload.len() as u64);
    assert!(report.bytes_from_target >= payload.len() as u64);
    socks_proxy_task.await??;
    shadowsocks_proxy_task.await??;
    echo.shutdown().await?;
    Ok(())
    })
    .await
}

#[tokio::test]
async fn upstream_client_wrong_password_is_rejected_by_rust_server_before_tcp_target()
-> Result<(), Box<dyn std::error::Error>> {
    let _interop_guard = interop_test_lock().await;
    let artifacts = artifact_dir("upstream client rust server auth failure interop").create()?;
    let bins = upstream_binaries(artifacts.path())?;
    assert!(
        bins.client.is_file(),
        "missing upstream juicity-client at {}",
        bins.client.display()
    );

    let cert = write_self_signed_cert_fixture(artifacts.path(), "server.local")?;
    let target_listener =
        tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let target_addr = target_listener.local_addr()?;
    let reserved_forward = reserve_tcp_listener()?;
    let forward_addr = reserved_forward.local_addr()?;
    drop(reserved_forward);

    let uuid = "00000000-0000-0000-0000-000000000103";
    let correct_password = "upstream client rust correct password";
    let wrong_password = "upstream client rust wrong password";
    let server_config = validate_server(load_json_str(&format!(
        r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{correct_password}"}}}}"#
    ))?)?;
    let runtime = ServerRuntime::new(ServerRuntimeConfig::from_config(server_config));
    let cert_pem = fs::read(&cert.cert_path)?;
    let key_pem = fs::read(&cert.key_path)?;
    let bound = runtime.bind_with_pem(([127, 0, 0, 1], 0).into(), &cert_pem, &key_pem)?;
    let server_addr = bound.local_addr()?;
    let mut server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });

    let client_config_path = artifacts.path().join("upstream-client.json");
    fs::write(
        &client_config_path,
        format!(
            r#"{{"server":"{server_addr}","uuid":"{uuid}","password":"{wrong_password}","sni":"{}","allow_insecure":true,"log_level":"debug","forward":{{"{forward_addr}/tcp":"{target_addr}"}}}}"#,
            cert.common_name
        ),
    )?;

    let client_log_path = artifacts.path().join("upstream-client.log");
    let mut upstream = ManagedProcessBuilder::new(bins.client.to_string_lossy().into_owned())
        .arg("run")
        .arg("-c")
        .arg(client_config_path.to_string_lossy().into_owned())
        .log_path(&client_log_path)
        .start()?;
    fs::write(
        artifacts.path().join("upstream-client.pid"),
        upstream.pid().to_string(),
    )?;
    sleep(Duration::from_millis(150)).await;
    assert!(upstream.is_running()?, "upstream client exited early");

    let evidence = format!(
        "artifact_dir={}\nrust_server={server_addr}\nupstream_forwarder={forward_addr}\ntarget={target_addr}\nupstream_client_log={}\nbuild_log={}\npid_file={}\n",
        artifacts.path().display(),
        client_log_path.display(),
        artifacts.path().join("upstream-client-build.log").display(),
        artifacts.path().join("upstream-client.pid").display()
    );
    fs::write(artifacts.path().join("addresses.txt"), &evidence)?;
    fs::create_dir_all("/tmp/zuicity-workspace")?;
    fs::write(
        "/tmp/zuicity-workspace/upstream-client-rust-server-auth-failure-artifacts.txt",
        evidence,
    )?;

    let mut stream = connect_with_retry(forward_addr, INTEROP_TIMEOUT).await?;
    stream
        .write_all(b"upstream client rust server wrong password")
        .await?;
    stream.shutdown().await?;

    let mut buf = [0_u8; 1];
    match timeout(Duration::from_millis(750), stream.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {}
        Ok(Ok(n)) => return Err(format!("unexpected {n} bytes echoed through bad auth").into()),
    }

    let server_result = match timeout(INTEROP_TIMEOUT, &mut server_task).await {
        Ok(joined) => joined?,
        Err(error) => {
            server_task.abort();
            return Err(format!("Rust server did not reject bad auth in time: {error}").into());
        }
    };
    assert!(
        server_result.is_err(),
        "wrong-password auth unexpectedly relayed TCP: {server_result:?}"
    );

    assert!(
        timeout(Duration::from_millis(500), target_listener.accept())
            .await
            .is_err(),
        "wrong-password auth reached TCP target listener"
    );

    let exit = upstream.terminate(PROCESS_EXIT_TIMEOUT)?;
    fs::write(
        artifacts.path().join("upstream-client-teardown.txt"),
        format!("{exit:?}\n"),
    )?;
    Ok(())
}
