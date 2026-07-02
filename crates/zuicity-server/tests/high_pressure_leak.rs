//! High-pressure leak reproduction: many connections whose egress write wedges
//! on a black-hole target, then all clients vanish. The server's
//! active_connections gauge must return to zero (relays force-drained on close)
//! instead of climbing and staying pinned forever - the production OOM the bug
//! reporter hit.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use zuicity_config::{load_json_str, validate_server};
use zuicity_server::{ServerMetrics, ServerRuntime, ServerRuntimeConfig, ServerRuntimeHooks};

// Black-hole TCP target: accepts connections and holds them open forever without
// ever reading. The relay's client->target write fills the socket buffers and
// then blocks indefinitely - exactly the stuck egress write that pins a relay
// past its idle timeout.
async fn start_black_hole() -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)>
{
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            match listener.accept().await {
                Ok((stream, _)) => held.push(stream),
                Err(_) => break,
            }
        }
    });
    Ok((addr, handle))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn high_pressure_wedged_relays_do_not_leak_connections() {
    const CONNECTIONS: usize = 40;
    const STREAMS_PER_CONN: usize = 4;
    const WEDGE_PAYLOAD: usize = 4 * 1024 * 1024;

    let uuid = uuid::Uuid::new_v4();
    let password = "high pressure leak password";
    let cert = rcgen::generate_simple_self_signed(vec!["server.local".to_owned()])
        .expect("generate fixture cert");

    let (target, _black_hole) = start_black_hole().await.expect("start black hole target");

    let server_config = validate_server(
        load_json_str(&format!(
            r#"{{"listen":"127.0.0.1:0","users":{{"{uuid}":"{password}"}}}}"#
        ))
        .expect("parse server config"),
    )
    .expect("validate server config");
    let mut runtime_config = ServerRuntimeConfig::from_config(server_config);
    runtime_config.quic.max_idle_timeout_millis = Some(2_000);
    let runtime = ServerRuntime::new(runtime_config);
    let bound = runtime
        .bind_with_pem(
            ([127, 0, 0, 1], 0).into(),
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )
        .expect("bind server");
    let server_addr = bound.local_addr().expect("server addr");

    let metrics = ServerMetrics::default();
    let hooks = ServerRuntimeHooks::new(metrics.clone());
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        bound
            .run_proxy_loop_until_with_hooks(
                async {
                    let _ = shutdown_rx.await;
                },
                hooks,
            )
            .await
    });

    let cert_pem = Arc::new(cert.cert.pem());
    let mut client_tasks = Vec::new();
    for _ in 0..CONNECTIONS {
        let cert_pem = Arc::clone(&cert_pem);
        client_tasks.push(tokio::spawn(async move {
            let client =
                zuicity_transport::JuicityQuicClient::bind(([127, 0, 0, 1], 0).into()).unwrap();
            let connection = match tokio::time::timeout(
                Duration::from_secs(10),
                client.connect_with_roots(
                    server_addr,
                    "server.local",
                    cert_pem.as_bytes(),
                    false,
                    uuid,
                    password.as_bytes(),
                ),
            )
            .await
            {
                Ok(Ok(connection)) => connection,
                _ => return,
            };

            let blob = vec![0x5a_u8; WEDGE_PAYLOAD];
            for _ in 0..STREAMS_PER_CONN {
                if let Ok(mut stream) = connection
                    .open_tcp_proxy_stream(target.ip(), target.port())
                    .await
                {
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), stream.write_all(&blob)).await;
                }
            }
            drop(connection);
        }));
    }

    for task in client_tasks {
        let _ = task.await;
    }

    // After every client vanishes the server must reap each connection. The fix
    // bounds the normal-close drain, so active_connections returns to zero. On
    // the buggy code the connection tasks hang on wedged relays and this never
    // reaches zero (the leak), so the test times out instead of asserting.
    let drain_started = Instant::now();
    let deadline = drain_started + Duration::from_secs(40);
    let mut last;
    loop {
        last = metrics.snapshot().active_connections;
        if last == 0 {
            eprintln!(
                "active_connections drained to 0 in {:?}",
                drain_started.elapsed()
            );
            break;
        }
        if Instant::now() >= deadline {
            eprintln!(
                "DEADLINE: active_connections still {last} after {:?}",
                drain_started.elapsed()
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let _ = shutdown_tx.send(());
    let _ = server_task.await;

    assert_eq!(
        last, 0,
        "active_connections must drain to zero after clients vanish; a non-zero \
         value means wedged relays pinned their connections (the leak)"
    );
}
