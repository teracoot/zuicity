#[cfg(target_os = "linux")]
use std::{io::IoSliceMut, sync::Arc, sync::atomic::Ordering};

use crate::{GroMode, PlainUdpSocket, udp_state::GroReceiver};

impl PlainUdpSocket {
    /// Builds the GRO receiver for the real socket when GRO is in
    /// [`GroMode::Auto`]. It constructs a receive-only
    /// [`quinn::GroSocketState`] on the socket, which enables `UDP_GRO` and
    /// parses its segment-size cmsg without probing or emitting `UDP_SEGMENT`.
    ///
    /// If GRO setup fails, `None` is returned so
    /// [`crate::PlainUdpSocket::poll_recv`] falls back to the historical plain
    /// per-datagram path.
    #[cfg(target_os = "linux")]
    pub(super) fn build_gro_receiver(
        socket: &std::net::UdpSocket,
        gro_mode: GroMode,
    ) -> (GroReceiver, bool) {
        if !matches!(gro_mode, GroMode::Auto) {
            return (None, true);
        }
        match quinn::GroSocketState::new(socket) {
            Ok(state) => {
                let may_fragment = state.may_fragment();
                tracing::debug!(gro_segments = 64, "udp gro enabled on receive socket");
                (Some(Arc::new(state)), may_fragment)
            }
            Err(error) => {
                tracing::debug!(%error, "udp gro setup rejected by this path; receiving plain datagrams");
                (None, true)
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn build_gro_receiver(
        _socket: &std::net::UdpSocket,
        _gro_mode: GroMode,
    ) -> (GroReceiver, bool) {
        (None, true)
    }

    /// GRO batched receive: delegates to [`quinn::GroSocketState::recv`],
    /// which performs the `recvmsg`/`recvmmsg` and parses the kernel `UDP_GRO`
    /// control message into each [`quinn::udp::RecvMeta::stride`] (the
    /// per-segment size). quinn-proto then re-splits a coalesced super-buffer
    /// into `ceil(len / stride)` segments, so QUIC decode stays correct - the
    /// reason a coalesced buffer must never be handed over with `stride == len`.
    ///
    /// Returns the number of [`quinn::udp::RecvMeta`] slots filled, and tallies
    /// coalescing (`stride < len`) into the GRO counters for test evidence.
    #[cfg(target_os = "linux")]
    pub(super) fn recv_gro_batch(
        &self,
        gro_recv: &quinn::GroSocketState,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> std::io::Result<usize> {
        let filled = gro_recv.recv(self.io.as_ref(), bufs, meta)?;
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
        gro_recv: &quinn::GroSocketState,
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
