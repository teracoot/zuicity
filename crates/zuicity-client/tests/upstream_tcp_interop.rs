//! Upstream Juicity interoperability tests for the Rust client runtime.

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use zuicity_client::{ClientRuntime, ClientRuntimeConfig};
use zuicity_config::{load_json_str, validate_client};
use zuicity_testkit::{
    ManagedProcessBuilder, TcpEchoServer, UdpEchoServer, UpstreamBinaries, artifact_dir,
    reserve_udp_socket, write_self_signed_cert_fixture,
};
use zuicity_transport::{StreamPolicy, TlsPolicy};

const INTEROP_TIMEOUT: Duration = Duration::from_secs(5);

fn upstream_binaries(dir: &Path) -> Result<UpstreamBinaries, Box<dyn std::error::Error>> {
    if let Some(prebuilt_dir) = std::env::var_os("UPSTREAM_JUICITY_BIN_DIR").map(PathBuf::from) {
        return Ok(UpstreamBinaries::from_dir(prebuilt_dir));
    }
    let upstream_root = std::env::var_os("UPSTREAM_JUICITY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root/projects/juicity/juicity"));
    let bin_dir = dir.join("upstream-bin");
    fs::create_dir_all(&bin_dir)?;
    let server = bin_dir.join("juicity-server");
    let build_log = dir.join("upstream-server-build.log");
    let output = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&server)
        .arg("./cmd/server")
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
            "upstream juicity-server build failed; see {}",
            build_log.display()
        )
        .into());
    }
    Ok(UpstreamBinaries {
        client: bin_dir.join("juicity-client"),
        server,
    })
}

#[tokio::test]
async fn rust_client_forwarder_reaches_upstream_server_tcp_echo_with_real_auth()
-> Result<(), Box<dyn std::error::Error>> {
    let artifacts = artifact_dir("rust client upstream tcp interop").create()?;
    let bins = upstream_binaries(artifacts.path())?;
    assert!(
        bins.server.is_file(),
        "missing upstream juicity-server at {}",
        bins.server.display()
    );

    let cert = write_self_signed_cert_fixture(artifacts.path(), "server.local")?;
    let echo = TcpEchoServer::start().await?;
    let reserved_listen = reserve_udp_socket()?;
    let upstream_addr = reserved_listen.local_addr()?;
    drop(reserved_listen);

    let uuid = "00000000-0000-0000-0000-000000000001";
    let password = "upstream tcp interop password";
    let server_config_path = artifacts.path().join("upstream-server.json");
    fs::write(
        &server_config_path,
        format!(
            r#"{{"listen":"{upstream_addr}","users":{{"{uuid}":"{password}"}},"certificate":"{}","private_key":"{}"}}"#,
            cert.cert_path.display(),
            cert.key_path.display()
        ),
    )?;

    let server_log_path = artifacts.path().join("upstream-server.log");
    let mut upstream = ManagedProcessBuilder::new(bins.server.to_string_lossy().into_owned())
        .arg("run")
        .arg("-c")
        .arg(server_config_path.to_string_lossy().into_owned())
        .log_path(&server_log_path)
        .start()?;
    fs::write(
        artifacts.path().join("upstream-server.pid"),
        upstream.pid().to_string(),
    )?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(upstream.is_running()?, "upstream server exited early");

    let client_config = validate_client(load_json_str(&format!(
        r#"{{"server":"{upstream_addr}","uuid":"{uuid}","password":"{password}","sni":"{}","forward":{{"127.0.0.1:0/tcp":"{}"}}}}"#,
        cert.common_name,
        echo.local_addr()
    ))?)?;
    let runtime = ClientRuntime::new(ClientRuntimeConfig {
        config: client_config,
        tls: TlsPolicy::upstream(),
        streams: StreamPolicy::upstream(),
    });
    let root_pem = fs::read(&cert.cert_path)?;
    let mut forwarders = runtime
        .bind_configured_tcp_forwarders_with_roots(&root_pem)
        .await?;
    assert_eq!(forwarders.len(), 1);
    let forwarder = forwarders.remove(0);
    let forward_addr: SocketAddr = forwarder.local_addr()?;
    let evidence = format!(
        "artifact_dir={}\nupstream={upstream_addr}\nforwarder={forward_addr}\necho={}\nupstream_log={}\nbuild_log={}\npid_file={}\n",
        artifacts.path().display(),
        echo.local_addr(),
        server_log_path.display(),
        artifacts.path().join("upstream-server-build.log").display(),
        artifacts.path().join("upstream-server.pid").display()
    );
    fs::write(artifacts.path().join("addresses.txt"), &evidence)?;
    fs::create_dir_all("/tmp/zuicity-workspace")?;
    fs::write(
        "/tmp/zuicity-workspace/upstream-tcp-interop-artifacts.txt",
        evidence,
    )?;

    let forward_task = tokio::spawn(async move { forwarder.accept_one().await });
    let mut stream = timeout(
        INTEROP_TIMEOUT,
        tokio::net::TcpStream::connect(forward_addr),
    )
    .await??;
    stream
        .write_all(b"rust client upstream tcp interop")
        .await?;
    stream.shutdown().await?;

    let mut echoed = Vec::new();
    timeout(INTEROP_TIMEOUT, stream.read_to_end(&mut echoed)).await??;
    assert_eq!(echoed, b"rust client upstream tcp interop");

    let report = timeout(INTEROP_TIMEOUT, forward_task).await???;
    assert_eq!(
        report.bytes_from_client,
        b"rust client upstream tcp interop".len() as u64
    );
    assert_eq!(
        report.bytes_from_target,
        b"rust client upstream tcp interop".len() as u64
    );

    echo.shutdown().await?;
    let exit = upstream.terminate(Duration::from_secs(2))?;
    fs::write(
        artifacts.path().join("upstream-server-teardown.txt"),
        format!("{exit:?}\n"),
    )?;
    Ok(())
}

#[tokio::test]
async fn rust_client_udp_forwarder_reaches_upstream_server_udp_echo_with_real_auth()
-> Result<(), Box<dyn std::error::Error>> {
    let artifacts = artifact_dir("rust client upstream udp interop").create()?;
    let bins = upstream_binaries(artifacts.path())?;
    assert!(
        bins.server.is_file(),
        "missing upstream juicity-server at {}",
        bins.server.display()
    );

    let cert = write_self_signed_cert_fixture(artifacts.path(), "server.local")?;
    let echo = UdpEchoServer::start().await?;
    let reserved_listen = reserve_udp_socket()?;
    let upstream_addr = reserved_listen.local_addr()?;
    drop(reserved_listen);

    let uuid = "00000000-0000-0000-0000-000000000002";
    let password = "upstream udp interop password";
    let server_config_path = artifacts.path().join("upstream-server.json");
    fs::write(
        &server_config_path,
        format!(
            r#"{{"listen":"{upstream_addr}","users":{{"{uuid}":"{password}"}},"certificate":"{}","private_key":"{}"}}"#,
            cert.cert_path.display(),
            cert.key_path.display()
        ),
    )?;

    let server_log_path = artifacts.path().join("upstream-server.log");
    let mut upstream = ManagedProcessBuilder::new(bins.server.to_string_lossy().into_owned())
        .arg("run")
        .arg("-c")
        .arg(server_config_path.to_string_lossy().into_owned())
        .log_path(&server_log_path)
        .start()?;
    fs::write(
        artifacts.path().join("upstream-server.pid"),
        upstream.pid().to_string(),
    )?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(upstream.is_running()?, "upstream server exited early");

    let client_config = validate_client(load_json_str(&format!(
        r#"{{"server":"{upstream_addr}","uuid":"{uuid}","password":"{password}","sni":"{}","forward":{{"127.0.0.1:0/udp":"{}"}}}}"#,
        cert.common_name,
        echo.local_addr()
    ))?)?;
    let runtime = ClientRuntime::new(ClientRuntimeConfig {
        config: client_config,
        tls: TlsPolicy::upstream(),
        streams: StreamPolicy::upstream(),
    });
    let root_pem = fs::read(&cert.cert_path)?;
    let mut forwarders = runtime
        .bind_configured_udp_forwarders_with_roots(&root_pem)
        .await?;
    assert_eq!(forwarders.len(), 1);
    let forwarder = forwarders.remove(0);
    let forward_addr: SocketAddr = forwarder.local_addr()?;
    let evidence = format!(
        "artifact_dir={}\nupstream={upstream_addr}\nforwarder={forward_addr}\necho={}\nupstream_log={}\nbuild_log={}\npid_file={}\n",
        artifacts.path().display(),
        echo.local_addr(),
        server_log_path.display(),
        artifacts.path().join("upstream-server-build.log").display(),
        artifacts.path().join("upstream-server.pid").display()
    );
    fs::write(artifacts.path().join("addresses.txt"), &evidence)?;
    fs::create_dir_all("/tmp/zuicity-workspace")?;
    fs::write(
        "/tmp/zuicity-workspace/upstream-udp-interop-artifacts.txt",
        evidence,
    )?;

    let forward_task = tokio::spawn(async move { forwarder.forward_one_datagram().await });
    let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    socket
        .send_to(b"rust client upstream udp interop", forward_addr)
        .await?;
    let mut buf = [0_u8; 1024];
    let (received, from) = timeout(INTEROP_TIMEOUT, socket.recv_from(&mut buf)).await??;
    assert_eq!(from, forward_addr);
    assert_eq!(&buf[..received], b"rust client upstream udp interop");

    let report = timeout(INTEROP_TIMEOUT, forward_task).await???;
    assert_eq!(report.local_peer, socket.local_addr()?);
    assert_eq!(report.remote_target, echo.local_addr());
    assert_eq!(
        report.bytes_from_client,
        b"rust client upstream udp interop".len() as u64
    );
    assert_eq!(
        report.bytes_from_target,
        b"rust client upstream udp interop".len() as u64
    );

    echo.shutdown().await?;
    let exit = upstream.terminate(Duration::from_secs(2))?;
    fs::write(
        artifacts.path().join("upstream-server-teardown.txt"),
        format!("{exit:?}\n"),
    )?;
    Ok(())
}
