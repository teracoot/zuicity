use std::{io::IoSliceMut, sync::Arc, sync::atomic::Ordering};

use crate::{GroMode, PlainUdpSocket, udp_state::GroReceiver};

impl PlainUdpSocket {
    /// Builds the GRO receiver for the real socket when GRO is in
    /// [`GroMode::Auto`]. It constructs a [`quinn::udp::UdpSocketState`] on the
    /// socket, which enables `UDP_GRO` and gives a `recv` that parses the GRO
    /// segment-size cmsg correctly (the unsafe `recvmsg`/cmsg work lives inside
    /// quinn-udp, so this crate stays `forbid(unsafe_code)`).
    ///
    /// If `UdpSocketState::new` fails — which is how GRO-hostile paths surface,
    /// since it also probes other receive options — the error is swallowed and
    /// `None` is returned, so [`crate::PlainUdpSocket::poll_recv`] falls back to the historical plain
    /// per-datagram path and the cross-host handshake is never stranded. The ECN
    /// and dst-ip values quinn would parse are discarded in [`Self::recv_gro_batch`],
    /// so this path stays wire- and reliability-equivalent to the plain one.
    #[cfg(target_os = "linux")]
    pub(super) fn build_gro_receiver(
        socket: &std::net::UdpSocket,
        gro_mode: GroMode,
    ) -> GroReceiver {
        if !matches!(gro_mode, GroMode::Auto) {
            return None;
        }
        match quinn::udp::UdpSocketState::new(socket.into()) {
            Ok(state) if state.gro_segments() > 1 => {
                tracing::debug!(
                    gro_segments = state.gro_segments(),
                    "udp gro enabled on receive socket"
                );
                Some(Arc::new(state))
            }
            Ok(_) => {
                tracing::debug!("udp gro reports a single segment; receiving plain datagrams");
                None
            }
            Err(error) => {
                tracing::debug!(%error, "udp gro setup rejected by this path; receiving plain datagrams");
                None
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn build_gro_receiver(
        _socket: &std::net::UdpSocket,
        _gro_mode: GroMode,
    ) -> GroReceiver {
        None
    }

    /// GRO batched receive: delegates to [`quinn::udp::UdpSocketState::recv`],
    /// which performs the `recvmsg`/`recvmmsg` and parses the kernel `UDP_GRO`
    /// control message into each [`quinn::udp::RecvMeta::stride`] (the
    /// per-segment size). quinn-proto then re-splits a coalesced super-buffer
    /// into `ceil(len / stride)` segments, so QUIC decode stays correct — the
    /// reason a coalesced buffer must never be handed over with `stride == len`.
    ///
    /// quinn's parser also fills `ecn` and `dst_ip` from their cmsgs; both are
    /// forced back to `None` here so this receive path stays wire- and
    /// reliability-equivalent to the plain path (no ECN feedback on the wire, no
    /// per-packet destination tracking). The send path is untouched and remains
    /// the adaptive GSO path. Only the GRO segment size is taken from quinn.
    ///
    /// Returns the number of [`quinn::udp::RecvMeta`] slots filled, and tallies
    /// coalescing (`stride < len`) into the GRO counters for test evidence.
    #[cfg(target_os = "linux")]
    pub(super) fn recv_gro_batch(
        &self,
        gro_recv: &quinn::udp::UdpSocketState,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> std::io::Result<usize> {
        let filled = gro_recv.recv((&self.io).into(), bufs, meta)?;
        for slot in meta.iter_mut().take(filled) {
            if slot.stride > 0 && slot.stride < slot.len {
                let segments = slot.len.div_ceil(slot.stride) as u64;
                self.gro_counters
                    .gro_coalesced_recv
                    .fetch_add(1, Ordering::Relaxed);
                self.gro_counters
                    .gro_segments_total
                    .fetch_add(segments, Ordering::Relaxed);
            }
            slot.ecn = None;
            slot.dst_ip = None;
        }
        Ok(filled)
    }

    /// Readiness loop for the GRO receive path. Mirrors the plain path's
    /// structure: await readiness, then run one batched GRO read. A
    /// `WouldBlock` from the batched read means the queue drained between the
    /// readiness signal and the syscall, so it re-arms readiness and loops.
    #[cfg(target_os = "linux")]
    pub(super) fn poll_recv_gro(
        &self,
        cx: &mut std::task::Context,
        gro_recv: &quinn::udp::UdpSocketState,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
        capacity: usize,
    ) -> std::task::Poll<std::io::Result<usize>> {
        loop {
            std::task::ready!(self.io.poll_recv_ready(cx))?;
            match self.io.try_io(tokio::io::Interest::READABLE, || {
                self.recv_gro_batch(gro_recv, &mut bufs[..capacity], &mut meta[..capacity])
            }) {
                Ok(0) => continue,
                Ok(received) => return std::task::Poll::Ready(Ok(received)),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(error) => return std::task::Poll::Ready(Err(error)),
            }
        }
    }
}
