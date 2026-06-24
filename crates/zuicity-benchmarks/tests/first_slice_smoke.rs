//! Smoke tests for the first-slice Juicity benchmark fixtures.

use std::time::Duration;

use anyhow::Context;
#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
use zuicity_benchmarks::probe_socket_fwmark_support;
use zuicity_benchmarks::{
    LiveServerFixture, MixedTcpBenchmarkMode, ServerEgressTcpBenchmarkMode,
    ServerEgressUdpBenchmarkMode, THROUGHPUT_MATRIX_CONCURRENCY, THROUGHPUT_MATRIX_PAYLOAD_SIZES,
    connect_client, current_process_memory_snapshot, parse_client_fixture, parse_server_fixture,
    parse_soak_duration, run_client_forward_tcp_echo, run_client_forward_udp_echo,
    run_concurrent_socks5_udp_associations, run_dae_connector_tcp_echo, run_dae_connector_udp_echo,
    run_mixed_tcp_echo, run_relay_soak, run_server_egress_tcp_echo, run_server_egress_udp_echo,
    run_server_lifecycle_churn, run_tcp_throughput_cell, soak_duration_from_env,
    validated_client_fixture, validated_server_fixture,
};

#[test]
fn config_fixtures_parse_and_validate() -> anyhow::Result<()> {
    parse_client_fixture()?;
    parse_server_fixture()?;
    let client = validated_client_fixture()?;
    let server = validated_server_fixture()?;
    assert_eq!(
        client.uuid,
        server.users.keys().next().copied().expect("server user")
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn current_process_memory_snapshot_reports_nonzero_rss() -> anyhow::Result<()> {
    let snapshot = current_process_memory_snapshot()?;
    eprintln!("current_process_memory_snapshot={snapshot:?}");
    assert!(
        snapshot.resident_set_kib > 0,
        "current process RSS should be non-zero: {snapshot:?}"
    );
    Ok(())
}

#[tokio::test]
async fn server_runtime_starts_and_stops_on_loopback() -> anyhow::Result<()> {
    let fixture = LiveServerFixture::start()?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        fixture
            .bound
            .run_proxy_loop_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });
    shutdown_tx.send(()).expect("send shutdown");
    let report = tokio::time::timeout(Duration::from_secs(3), task).await???;
    assert_eq!(report.accepted_connections, 0);
    Ok(())
}

#[tokio::test]
async fn rust_rust_handshake_succeeds() -> anyhow::Result<()> {
    let fixture = LiveServerFixture::start()?;
    let client_fixture = fixture.client.clone();
    let bound = fixture.bound;
    let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });
    let connection = connect_client(&client_fixture).await?;
    assert_eq!(connection.remote_address(), client_fixture.server_addr);
    drop(connection);
    server_task.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_relay_echoes_payload() -> anyhow::Result<()> {
    let echo = zuicity_testkit::TcpEchoServer::start().await?;
    let fixture = LiveServerFixture::start()?;
    let client_fixture = fixture.client.clone();
    let bound = fixture.bound;
    let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });
    let connection = connect_client(&client_fixture).await?;
    let echo_addr = echo.local_addr();
    let mut stream = connection
        .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
        .await?;
    stream.write_all(b"benchmark tcp smoke").await?;
    stream.finish()?;
    let echoed = stream.read_to_end(1024).await?;
    assert_eq!(echoed, b"benchmark tcp smoke");
    let relay = server_task.await??;
    assert_eq!(relay.target, echo_addr);
    echo.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn concurrent_tcp_clients_echo_payloads() -> anyhow::Result<()> {
    let fixture = LiveServerFixture::start()?;
    let summary = zuicity_benchmarks::run_concurrent_tcp_clients(fixture, 4, 2).await?;
    assert_eq!(summary.clients, 4);
    assert_eq!(summary.requests_per_client, 2);
    assert_eq!(
        summary.clients * summary.requests_per_client,
        summary.completed_requests
    );
    assert!(summary.bytes_echoed > 0);
    Ok(())
}

#[tokio::test]
async fn concurrent_socks5_udp_associations_echo_payloads() -> anyhow::Result<()> {
    let fixture = LiveServerFixture::start()?;
    let summary = run_concurrent_socks5_udp_associations(fixture, 2, 2).await?;
    assert_eq!(summary.associations, 2);
    assert_eq!(summary.datagrams_per_association, 2);
    assert_eq!(
        summary.associations * summary.datagrams_per_association,
        summary.completed_datagrams
    );
    assert_eq!(summary.listener_accepted_connections, 2);
    assert_eq!(summary.listener_completed_udp_associations, 2);
    assert_eq!(summary.server_accepted_connections, 2);
    assert_eq!(summary.server_completed_udp_relays, 2);
    assert!(summary.bytes_echoed > 0);
    Ok(())
}

#[tokio::test]
async fn server_lifecycle_churn_relays_tcp_and_udp_clients() -> anyhow::Result<()> {
    let fixture = LiveServerFixture::start()?;
    let summary = run_server_lifecycle_churn(fixture, 4, 4).await?;
    assert_eq!(summary.tcp_clients, 4);
    assert_eq!(summary.udp_clients, 4);
    assert_eq!(summary.completed_tcp_relays, 4);
    assert_eq!(summary.completed_udp_relays, 4);
    assert_eq!(summary.server_accepted_connections, 8);
    assert_eq!(summary.server_completed_tcp_relays, 4);
    assert_eq!(summary.server_completed_udp_relays, 4);
    assert_eq!(
        summary.server_bytes_from_client,
        summary.bytes_echoed as u64
    );
    assert_eq!(
        summary.server_bytes_from_target,
        summary.bytes_echoed as u64
    );
    assert!(summary.bytes_echoed > 0);
    Ok(())
}

#[test]
fn soak_duration_parses_units() -> anyhow::Result<()> {
    assert_eq!(parse_soak_duration("10s")?, Duration::from_secs(10));
    assert_eq!(parse_soak_duration("90s")?, Duration::from_secs(90));
    assert_eq!(parse_soak_duration("2m")?, Duration::from_secs(120));
    assert_eq!(parse_soak_duration("30m")?, Duration::from_secs(1800));
    assert_eq!(parse_soak_duration("250ms")?, Duration::from_millis(250));
    assert!(parse_soak_duration("").is_err());
    assert!(parse_soak_duration("-1s").is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_soak_sustains_tcp_udp_without_leaks() -> anyhow::Result<()> {
    let duration = soak_duration_from_env()?;
    let summary = run_relay_soak(duration).await?;
    eprintln!("relay_soak_summary={summary:?}");
    eprintln!(
        "relay_soak rss_growth_ratio={:.4} fd_growth={}",
        summary.rss_growth_ratio(),
        summary.fd_growth()
    );
    assert!(summary.waves > summary.warmup_waves);
    assert!(summary.completed_tcp_relays > 0);
    assert!(summary.completed_udp_relays > 0);
    assert!(summary.bytes_echoed > 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn tcp_throughput_matrix_completes_all_cells() -> anyhow::Result<()> {
    for payload_size in THROUGHPUT_MATRIX_PAYLOAD_SIZES {
        for concurrency in THROUGHPUT_MATRIX_CONCURRENCY {
            let fixture = LiveServerFixture::start()?;
            let cell = run_tcp_throughput_cell(fixture, payload_size, concurrency).await?;
            eprintln!(
                "throughput cell payload={} concurrency={} relays={} bytes={} mib_per_s={:.2}",
                cell.payload_size,
                cell.concurrency,
                cell.completed_relays,
                cell.bytes_echoed,
                cell.mib_per_second()
            );
            assert_eq!(cell.completed_relays, concurrency);
            assert_eq!(cell.bytes_echoed, payload_size * concurrency);
        }
    }
    Ok(())
}

#[tokio::test]
async fn mixed_tcp_frontends_echo_payloads() -> anyhow::Result<()> {
    for mode in [
        MixedTcpBenchmarkMode::HttpConnect,
        MixedTcpBenchmarkMode::Socks5Connect,
    ] {
        let summary = run_mixed_tcp_echo(mode).await?;
        assert_eq!(summary.mode, mode);
        assert_eq!(summary.payload_bytes, summary.echoed_bytes);
        assert_eq!(summary.listener_accepted_connections, 1);
        assert_eq!(summary.listener_completed_tcp_relays, 1);
        assert_eq!(summary.server_accepted_connections, 1);
        assert_eq!(summary.server_completed_tcp_relays, 1);
    }
    Ok(())
}

#[tokio::test]
async fn client_forward_tcp_and_udp_echo_payloads() -> anyhow::Result<()> {
    let tcp = run_client_forward_tcp_echo(LiveServerFixture::start()?).await?;
    assert_eq!(tcp.payload_bytes, tcp.echoed_bytes);
    assert_eq!(tcp.forwarder_bytes_from_client, tcp.payload_bytes as u64);
    assert_eq!(tcp.forwarder_bytes_from_target, tcp.payload_bytes as u64);
    assert_eq!(tcp.server_accepted_connections, 1);
    assert_eq!(tcp.server_completed_tcp_relays, 1);

    let udp = run_client_forward_udp_echo(LiveServerFixture::start()?).await?;
    assert_eq!(udp.payload_bytes, udp.echoed_bytes);
    assert_eq!(udp.forwarder_bytes_from_client, udp.payload_bytes as u64);
    assert_eq!(udp.forwarder_bytes_from_target, udp.payload_bytes as u64);
    assert_eq!(udp.server_accepted_connections, 1);
    assert_eq!(udp.server_completed_udp_relays, 1);
    Ok(())
}

#[tokio::test]
async fn dae_connector_tcp_and_udp_echo_payloads() -> anyhow::Result<()> {
    let tcp = run_dae_connector_tcp_echo(LiveServerFixture::start()?).await?;
    assert_eq!(tcp.payload_bytes, tcp.echoed_bytes);
    assert_eq!(tcp.server_completed_tcp_relays, 1);
    assert_eq!(tcp.server_completed_udp_relays, 0);
    assert_eq!(tcp.metrics.opened_connections, 1);
    assert_eq!(tcp.metrics.closed_connections, 1);
    assert_eq!(tcp.metrics.failed_connections, 0);
    assert_eq!(tcp.metrics.open_connections, 0);
    assert_eq!(tcp.metrics.bytes_sent, tcp.payload_bytes as u64);
    assert_eq!(tcp.metrics.bytes_received, tcp.echoed_bytes as u64);

    let udp = run_dae_connector_udp_echo(LiveServerFixture::start()?).await?;
    assert_eq!(udp.payload_bytes, udp.echoed_bytes);
    assert_eq!(udp.server_completed_tcp_relays, 0);
    assert_eq!(udp.server_completed_udp_relays, 1);
    assert_eq!(udp.metrics.opened_connections, 1);
    assert_eq!(udp.metrics.closed_connections, 1);
    assert_eq!(udp.metrics.failed_connections, 0);
    assert_eq!(udp.metrics.open_connections, 0);
    assert_eq!(udp.metrics.bytes_sent, udp.payload_bytes as u64);
    assert_eq!(udp.metrics.bytes_received, udp.echoed_bytes as u64);
    Ok(())
}

#[tokio::test]
async fn udp_relay_echoes_datagram() -> anyhow::Result<()> {
    let echo = zuicity_testkit::UdpEchoServer::start().await?;
    let fixture = LiveServerFixture::start()?;
    let client_fixture = fixture.client.clone();
    let bound = fixture.bound;
    let server_task = tokio::spawn(async move { bound.accept_one_udp_over_stream().await });
    let connection = connect_client(&client_fixture).await?;
    let echo_addr = echo.local_addr();
    let mut stream = connection
        .open_udp_over_stream(echo_addr.ip(), echo_addr.port())
        .await?;
    stream.send_datagram(b"benchmark udp smoke").await?;
    let echoed = stream.recv_datagram(1024).await?;
    assert_eq!(echoed.target, echo_addr);
    assert_eq!(echoed.payload, b"benchmark udp smoke");
    stream.finish()?;
    let relay = server_task.await??;
    assert_eq!(relay.target, echo_addr);
    echo.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn server_egress_tcp_modes_echo_payloads() -> anyhow::Result<()> {
    for mode in [
        ServerEgressTcpBenchmarkMode::Direct,
        ServerEgressTcpBenchmarkMode::SendThrough,
        ServerEgressTcpBenchmarkMode::Socks5DialerLink,
        ServerEgressTcpBenchmarkMode::HttpConnectDialerLink,
    ] {
        assert_server_egress_tcp_mode_echoes(mode).await?;
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    match probe_socket_fwmark_support() {
        Ok(()) => {
            assert_server_egress_tcp_mode_echoes(ServerEgressTcpBenchmarkMode::Fwmark).await?
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "skipping fwmark server egress benchmark smoke because the host denied SO_MARK: {error}"
            );
        }
        Err(error) => {
            return Err(error).context("probe SO_MARK support for fwmark benchmark smoke");
        }
    }

    Ok(())
}

async fn assert_server_egress_tcp_mode_echoes(
    mode: ServerEgressTcpBenchmarkMode,
) -> anyhow::Result<()> {
    let summary = tokio::time::timeout(Duration::from_secs(10), run_server_egress_tcp_echo(mode))
        .await
        .map_err(|_| anyhow::anyhow!("server egress benchmark mode {mode:?} timed out"))?
        .with_context(|| format!("server egress benchmark mode {mode:?} failed"))?;
    assert_eq!(summary.mode, mode);
    assert_eq!(summary.payload_bytes, summary.echoed_bytes);
    assert_eq!(summary.server_accepted_connections, 1);
    assert_eq!(summary.server_completed_tcp_relays, 1);
    let expected_socks5 = u64::from(mode == ServerEgressTcpBenchmarkMode::Socks5DialerLink);
    let expected_http = u64::from(mode == ServerEgressTcpBenchmarkMode::HttpConnectDialerLink);
    assert_eq!(summary.socks5_connect_requests, expected_socks5);
    assert_eq!(summary.http_connect_requests, expected_http);
    Ok(())
}

#[tokio::test]
async fn server_egress_udp_modes_echo_payloads() -> anyhow::Result<()> {
    for mode in [
        ServerEgressUdpBenchmarkMode::Direct,
        ServerEgressUdpBenchmarkMode::SendThrough,
        ServerEgressUdpBenchmarkMode::Socks5DialerLink,
    ] {
        assert_server_egress_udp_mode_echoes(mode).await?;
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    match probe_socket_fwmark_support() {
        Ok(()) => {
            assert_server_egress_udp_mode_echoes(ServerEgressUdpBenchmarkMode::Fwmark).await?
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "skipping fwmark UDP server egress benchmark smoke because the host denied SO_MARK: {error}"
            );
        }
        Err(error) => {
            return Err(error).context("probe SO_MARK support for UDP fwmark benchmark smoke");
        }
    }

    Ok(())
}

async fn assert_server_egress_udp_mode_echoes(
    mode: ServerEgressUdpBenchmarkMode,
) -> anyhow::Result<()> {
    let summary = tokio::time::timeout(Duration::from_secs(10), run_server_egress_udp_echo(mode))
        .await
        .map_err(|_| anyhow::anyhow!("server UDP egress benchmark mode {mode:?} timed out"))?
        .with_context(|| format!("server UDP egress benchmark mode {mode:?} failed"))?;
    assert_eq!(summary.mode, mode);
    assert_eq!(summary.payload_bytes, summary.echoed_bytes);
    assert_eq!(summary.server_accepted_connections, 1);
    assert_eq!(summary.server_completed_udp_relays, 1);
    let expected_socks5 = u64::from(mode == ServerEgressUdpBenchmarkMode::Socks5DialerLink);
    assert_eq!(summary.socks5_udp_requests, expected_socks5);
    Ok(())
}
