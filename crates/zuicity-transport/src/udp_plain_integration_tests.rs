use std::{io, net::SocketAddr, sync::Arc, sync::atomic::Ordering};

use super::*;

struct TestEndpointConfig {
    address: SocketAddr,
    server_config: Option<quinn::ServerConfig>,
}

struct BulkTransferResult {
    client_socket: Arc<PlainUdpSocket>,
    server_socket: Arc<PlainUdpSocket>,
    transferred: usize,
}

fn build_off_endpoint(
    config: TestEndpointConfig,
) -> Result<(quinn::Endpoint, Arc<PlainUdpSocket>), TransportError> {
    let std_socket = std::net::UdpSocket::bind(config.address)?;
    let socket = Arc::new(PlainUdpSocket::with_test_config(
        std_socket,
        PlainUdpTestConfig::new(GsoMode::Off, GroMode::Off),
    )?);
    let runtime =
        quinn::default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        config.server_config,
        Arc::clone(&socket) as Arc<dyn quinn::AsyncUdpSocket>,
        runtime,
    )?;
    Ok((endpoint, socket))
}

#[tokio::test]
async fn given_long_header_batch_when_gso_is_off_then_ordinary_datagrams_preserve_payloads()
-> io::Result<()> {
    let receiver = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let destination = receiver.local_addr()?;
    let sender = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let socket = PlainUdpSocket::with_test_config(
        sender,
        PlainUdpTestConfig::new(GsoMode::Off, GroMode::Off),
    )?;
    let contents = [0x80, 1, 2, 3, 0x40, 4, 5, 6, 0x40, 7];
    let transmit = quinn::udp::Transmit {
        destination,
        ecn: Some(quinn::udp::EcnCodepoint::Ect0),
        contents: &contents,
        segment_size: Some(4),
        src_ip: Some(std::net::Ipv4Addr::LOCALHOST.into()),
    };

    quinn::AsyncUdpSocket::try_send(&socket, &transmit)?;
    let mut payloads = Vec::new();
    for _ in 0..3 {
        let mut buffer = [0_u8; 16];
        let (length, _) = receiver.recv_from(&mut buffer).await?;
        payloads.push(buffer[..length].to_vec());
    }

    assert_eq!(
        payloads,
        [&contents[..4], &contents[4..8], &contents[8..]].map(<[u8]>::to_vec)
    );
    let plain = socket.plain_counters();
    assert_eq!(plain.sendmmsg_calls.load(Ordering::Relaxed), 1);
    assert_eq!(plain.sendmmsg_datagrams.load(Ordering::Relaxed), 3);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn given_gso_off_quic_when_bulk_echo_runs_then_sendmmsg_preserves_integrity()
-> Result<(), TransportError> {
    let result = run_off_bulk_transfer().await?;
    let client_gso = result.client_socket.counters();
    let server_gso = result.server_socket.counters();
    let client_plain = result.client_socket.plain_counters();
    let server_plain = result.server_socket.plain_counters();
    let client_calls = client_plain.sendmmsg_calls.load(Ordering::Relaxed);
    let client_datagrams = client_plain.sendmmsg_datagrams.load(Ordering::Relaxed);
    let server_calls = server_plain.sendmmsg_calls.load(Ordering::Relaxed);
    let server_datagrams = server_plain.sendmmsg_datagrams.load(Ordering::Relaxed);

    assert_eq!(result.transferred, 2 * 1024 * 1024);
    assert_eq!(client_gso.attempt.load(Ordering::Relaxed), 0);
    assert_eq!(client_gso.success.load(Ordering::Relaxed), 0);
    assert_eq!(server_gso.attempt.load(Ordering::Relaxed), 0);
    assert_eq!(server_gso.success.load(Ordering::Relaxed), 0);
    assert!(client_calls > 0);
    assert!(server_calls > 0);
    assert!(client_datagrams > client_calls);
    assert!(server_datagrams > server_calls);
    Ok(())
}

async fn run_off_bulk_transfer() -> Result<BulkTransferResult, TransportError> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate fixture cert");
    let server_crypto = build_server_crypto_config_from_pem(
        cert.cert.pem().as_bytes(),
        cert.key_pair.serialize_pem().as_bytes(),
    )?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    server_config
        .transport_config(build_transport_config(&QuicRuntimePolicy::upstream_server()).into_arc());
    let (server_endpoint, server_socket) = build_off_endpoint(TestEndpointConfig {
        address: ([127, 0, 0, 1], 0).into(),
        server_config: Some(server_config),
    })?;
    let server_address = server_endpoint.local_addr()?;
    let payload_length = 2 * 1024 * 1024;
    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .ok_or(TransportError::EndpointClosed)?;
        let connection = incoming.accept()?.await?;
        let (mut send, mut receive) = connection.accept_bi().await?;
        let payload = receive.read_to_end(payload_length).await?;
        send.write_all(&payload).await?;
        send.finish()?;
        send.stopped().await?;
        Ok::<_, TransportError>(payload.len())
    });
    let client_crypto = build_client_crypto_config_with_roots(cert.cert.pem().as_bytes(), false)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));
    client_config
        .transport_config(build_transport_config(&QuicRuntimePolicy::upstream_client()).into_arc());
    let (client_endpoint, client_socket) = build_off_endpoint(TestEndpointConfig {
        address: ([127, 0, 0, 1], 0).into(),
        server_config: None,
    })?;
    let connection = client_endpoint
        .connect_with(client_config, server_address, "localhost")?
        .await?;
    let (mut send, mut receive) = connection.open_bi().await?;
    let upload = (0..payload_length)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    send.write_all(&upload).await?;
    send.finish()?;
    let echoed = receive.read_to_end(payload_length).await?;
    assert_eq!(echoed, upload);
    let transferred = server_task.await??;
    Ok(BulkTransferResult {
        client_socket,
        server_socket,
        transferred,
    })
}
