/// Requests a 4 MiB send and receive socket buffer, then logs the kernel-applied sizes.
pub(crate) fn configure_socket_buffers(socket: &std::net::UdpSocket) {
    const TARGET_BYTES: usize = 4 * 1024 * 1024;
    let socket = socket2::SockRef::from(socket);
    if let Err(error) = socket.set_recv_buffer_size(TARGET_BYTES) {
        tracing::debug!(%error, "udp set_recv_buffer_size failed; keeping default");
    }
    if let Err(error) = socket.set_send_buffer_size(TARGET_BYTES) {
        tracing::debug!(%error, "udp set_send_buffer_size failed; keeping default");
    }
    let applied_recv = socket.recv_buffer_size().unwrap_or(0);
    let applied_send = socket.send_buffer_size().unwrap_or(0);
    tracing::debug!(
        requested = TARGET_BYTES,
        applied_recv,
        applied_send,
        "udp socket buffers sized; kernel clamps to net.core rmem_max/wmem_max"
    );
}
