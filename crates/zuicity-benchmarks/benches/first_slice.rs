//! First-slice Criterion benchmarks for Juicity Rust runtime paths.
#![allow(missing_docs)]

use std::time::Duration;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
use zuicity_benchmarks::probe_socket_fwmark_support;
use zuicity_benchmarks::{
    LiveServerFixture, MixedTcpBenchmarkMode, ServerEgressTcpBenchmarkMode,
    ServerEgressUdpBenchmarkMode, THROUGHPUT_MATRIX_CONCURRENCY, THROUGHPUT_MATRIX_PAYLOAD_SIZES,
    client_json_fixture, connect_client, parse_client_fixture, parse_server_fixture,
    run_client_forward_tcp_echo, run_client_forward_udp_echo,
    run_concurrent_socks5_udp_associations, run_concurrent_tcp_clients, run_dae_connector_tcp_echo,
    run_dae_connector_udp_echo, run_mixed_tcp_echo, run_server_egress_tcp_echo,
    run_server_egress_udp_echo, run_server_lifecycle_churn, run_tcp_throughput_cell,
    server_json_fixture,
};

fn config_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("config");
    group.bench_function("load_client_json_str", |b| {
        b.iter(|| zuicity_config::load_json_str(criterion::black_box(client_json_fixture())))
    });
    group.bench_function("load_server_json_str", |b| {
        b.iter(|| zuicity_config::load_json_str(criterion::black_box(server_json_fixture())))
    });
    group.bench_function("validate_client", |b| {
        b.iter_batched(
            || parse_client_fixture().expect("parse client fixture"),
            |raw| zuicity_config::validate_client(criterion::black_box(raw)),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("validate_server", |b| {
        b.iter_batched(
            || parse_server_fixture().expect("parse server fixture"),
            |raw| zuicity_config::validate_server(criterion::black_box(raw)),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn live_benches(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build benchmark runtime");
    let mut group = c.benchmark_group("live");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(3));
    group.bench_function("server_runtime_startup_shutdown", |b| {
        b.to_async(&runtime).iter(|| async {
            let fixture = LiveServerFixture::start().expect("start server fixture");
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
            let _report = task.await.expect("join server task").expect("server loop");
        })
    });
    group.bench_function("rust_rust_handshake", |b| {
        b.to_async(&runtime).iter(|| async {
            let fixture = LiveServerFixture::start().expect("start server fixture");
            let client_fixture = fixture.client.clone();
            let bound = fixture.bound;
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
            let server_task = tokio::spawn(async move {
                bound
                    .run_proxy_loop_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });
            let connection = connect_client(&client_fixture)
                .await
                .expect("connect client");
            criterion::black_box(connection.remote_address());
            drop(connection);
            shutdown_tx.send(()).expect("send shutdown");
            let _report = server_task
                .await
                .expect("join server task")
                .expect("server loop");
        })
    });
    group.bench_function("tcp_relay_echo_1k", |b| {
        b.to_async(&runtime).iter(|| async {
            let echo = zuicity_testkit::TcpEchoServer::start()
                .await
                .expect("start TCP echo");
            let fixture = LiveServerFixture::start().expect("start server fixture");
            let client_fixture = fixture.client.clone();
            let bound = fixture.bound;
            let server_task = tokio::spawn(async move { bound.accept_one_tcp_proxy().await });
            let connection = connect_client(&client_fixture)
                .await
                .expect("connect client");
            let payload = vec![0x5a; 1024];
            let echo_addr = echo.local_addr();
            let mut stream = connection
                .open_tcp_proxy_stream(echo_addr.ip(), echo_addr.port())
                .await
                .expect("open TCP stream");
            stream.write_all(&payload).await.expect("write TCP payload");
            stream.finish().expect("finish TCP stream");
            let echoed = stream.read_to_end(2048).await.expect("read TCP echo");
            criterion::black_box(echoed);
            let _relay = server_task
                .await
                .expect("join TCP task")
                .expect("TCP relay");
            echo.shutdown().await.expect("shutdown TCP echo");
        })
    });
    group.bench_function("udp_relay_echo_256b", |b| {
        b.to_async(&runtime).iter(|| async {
            let echo = zuicity_testkit::UdpEchoServer::start()
                .await
                .expect("start UDP echo");
            let fixture = LiveServerFixture::start().expect("start server fixture");
            let client_fixture = fixture.client.clone();
            let bound = fixture.bound;
            let server_task = tokio::spawn(async move { bound.accept_one_udp_over_stream().await });
            let connection = connect_client(&client_fixture)
                .await
                .expect("connect client");
            let payload = vec![0xa5; 256];
            let echo_addr = echo.local_addr();
            let mut stream = connection
                .open_udp_over_stream(echo_addr.ip(), echo_addr.port())
                .await
                .expect("open UDP stream");
            stream
                .send_datagram(&payload)
                .await
                .expect("send UDP payload");
            let echoed = stream.recv_datagram(512).await.expect("read UDP echo");
            criterion::black_box(echoed);
            stream.finish().expect("finish UDP stream");
            let _relay = server_task
                .await
                .expect("join UDP task")
                .expect("UDP relay");
            echo.shutdown().await.expect("shutdown UDP echo");
        })
    });
    group.bench_function("concurrent_tcp_clients_rust_rust", |b| {
        b.to_async(&runtime).iter(|| async {
            let fixture = LiveServerFixture::start().expect("start server fixture");
            let summary = run_concurrent_tcp_clients(fixture, 4, 2)
                .await
                .expect("run concurrent TCP clients");
            criterion::black_box(summary);
        })
    });
    group.bench_function("concurrent_socks5_udp_associations_rust_rust", |b| {
        b.to_async(&runtime).iter(|| async {
            let fixture = LiveServerFixture::start().expect("start server fixture");
            let summary = run_concurrent_socks5_udp_associations(fixture, 2, 2)
                .await
                .expect("run concurrent SOCKS5 UDP associations");
            criterion::black_box(summary);
        })
    });
    group.bench_function("server_lifecycle_tcp_udp_churn_rust_rust", |b| {
        b.to_async(&runtime).iter(|| async {
            let fixture = LiveServerFixture::start().expect("start server fixture");
            let summary = run_server_lifecycle_churn(fixture, 4, 4)
                .await
                .expect("run server lifecycle TCP/UDP churn");
            criterion::black_box(summary);
        })
    });
    group.bench_function("mixed_http_connect_tcp_echo", |b| {
        b.to_async(&runtime).iter(|| async {
            let summary = run_mixed_tcp_echo(MixedTcpBenchmarkMode::HttpConnect)
                .await
                .expect("run mixed HTTP CONNECT TCP echo");
            criterion::black_box(summary);
        })
    });
    group.bench_function("mixed_socks5_connect_tcp_echo", |b| {
        b.to_async(&runtime).iter(|| async {
            let summary = run_mixed_tcp_echo(MixedTcpBenchmarkMode::Socks5Connect)
                .await
                .expect("run mixed SOCKS5 CONNECT TCP echo");
            criterion::black_box(summary);
        })
    });
    group.bench_function("client_forward_tcp_echo", |b| {
        b.to_async(&runtime).iter(|| async {
            let fixture = LiveServerFixture::start().expect("start server fixture");
            let summary = run_client_forward_tcp_echo(fixture)
                .await
                .expect("run client TCP forward echo");
            criterion::black_box(summary);
        })
    });
    group.bench_function("client_forward_udp_echo", |b| {
        b.to_async(&runtime).iter(|| async {
            let fixture = LiveServerFixture::start().expect("start server fixture");
            let summary = run_client_forward_udp_echo(fixture)
                .await
                .expect("run client UDP forward echo");
            criterion::black_box(summary);
        })
    });
    group.bench_function("server_egress_tcp_direct", |b| {
        b.to_async(&runtime).iter(|| async {
            let summary = run_server_egress_tcp_echo(ServerEgressTcpBenchmarkMode::Direct)
                .await
                .expect("run direct server egress TCP echo");
            criterion::black_box(summary);
        })
    });
    group.bench_function("server_egress_tcp_send_through", |b| {
        b.to_async(&runtime).iter(|| async {
            let summary = run_server_egress_tcp_echo(ServerEgressTcpBenchmarkMode::SendThrough)
                .await
                .expect("run send_through server egress TCP echo");
            criterion::black_box(summary);
        })
    });
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    match probe_socket_fwmark_support() {
        Ok(()) => {
            group.bench_function("server_egress_tcp_fwmark", |b| {
                b.to_async(&runtime).iter(|| async {
                    let summary = run_server_egress_tcp_echo(ServerEgressTcpBenchmarkMode::Fwmark)
                        .await
                        .expect("run fwmark server egress TCP echo");
                    criterion::black_box(summary);
                })
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping server_egress_tcp_fwmark because the host denied SO_MARK: {error}");
        }
        Err(error) => panic!("probe SO_MARK support for fwmark benchmark failed: {error}"),
    }
    group.bench_function("server_egress_tcp_socks5_dialer_link", |b| {
        b.to_async(&runtime).iter(|| async {
            let summary =
                run_server_egress_tcp_echo(ServerEgressTcpBenchmarkMode::Socks5DialerLink)
                    .await
                    .expect("run SOCKS5 dialer_link server egress TCP echo");
            criterion::black_box(summary);
        })
    });
    group.bench_function("server_egress_tcp_http_connect_dialer_link", |b| {
        b.to_async(&runtime).iter(|| async {
            let summary =
                run_server_egress_tcp_echo(ServerEgressTcpBenchmarkMode::HttpConnectDialerLink)
                    .await
                    .expect("run HTTP CONNECT dialer_link server egress TCP echo");
            criterion::black_box(summary);
        })
    });
    group.bench_function("server_egress_udp_direct", |b| {
        b.to_async(&runtime).iter(|| async {
            let summary = run_server_egress_udp_echo(ServerEgressUdpBenchmarkMode::Direct)
                .await
                .expect("run direct server egress UDP echo");
            criterion::black_box(summary);
        })
    });
    group.bench_function("server_egress_udp_send_through", |b| {
        b.to_async(&runtime).iter(|| async {
            let summary = run_server_egress_udp_echo(ServerEgressUdpBenchmarkMode::SendThrough)
                .await
                .expect("run send_through server egress UDP echo");
            criterion::black_box(summary);
        })
    });
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    match probe_socket_fwmark_support() {
        Ok(()) => {
            group.bench_function("server_egress_udp_fwmark", |b| {
                b.to_async(&runtime).iter(|| async {
                    let summary = run_server_egress_udp_echo(ServerEgressUdpBenchmarkMode::Fwmark)
                        .await
                        .expect("run fwmark server egress UDP echo");
                    criterion::black_box(summary);
                })
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping server_egress_udp_fwmark because the host denied SO_MARK: {error}");
        }
        Err(error) => panic!("probe SO_MARK support for UDP fwmark benchmark failed: {error}"),
    }
    group.bench_function("server_egress_udp_socks5_dialer_link", |b| {
        b.to_async(&runtime).iter(|| async {
            let summary =
                run_server_egress_udp_echo(ServerEgressUdpBenchmarkMode::Socks5DialerLink)
                    .await
                    .expect("run SOCKS5 dialer_link server egress UDP echo");
            criterion::black_box(summary);
        })
    });
    group.bench_function("dae_connector_tcp_echo", |b| {
        b.to_async(&runtime).iter(|| async {
            let fixture = LiveServerFixture::start().expect("start server fixture");
            let summary = run_dae_connector_tcp_echo(fixture)
                .await
                .expect("run dae TCP connector echo");
            criterion::black_box(summary);
        })
    });
    group.bench_function("dae_connector_udp_echo", |b| {
        b.to_async(&runtime).iter(|| async {
            let fixture = LiveServerFixture::start().expect("start server fixture");
            let summary = run_dae_connector_udp_echo(fixture)
                .await
                .expect("run dae UDP connector echo");
            criterion::black_box(summary);
        })
    });
    for payload_size in THROUGHPUT_MATRIX_PAYLOAD_SIZES {
        for concurrency in THROUGHPUT_MATRIX_CONCURRENCY {
            let id = format!("tcp_throughput_payload_{payload_size}_concurrency_{concurrency}");
            group.bench_function(id, |b| {
                b.to_async(&runtime).iter(|| async {
                    let fixture = LiveServerFixture::start().expect("start server fixture");
                    let cell = run_tcp_throughput_cell(fixture, payload_size, concurrency)
                        .await
                        .expect("run TCP throughput matrix cell");
                    criterion::black_box(cell);
                })
            });
        }
    }
    group.finish();
}

criterion_group!(benches, config_benches, live_benches);
criterion_main!(benches);
