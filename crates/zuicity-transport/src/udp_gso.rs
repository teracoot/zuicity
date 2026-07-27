use std::sync::Arc;

#[cfg(all(test, target_os = "linux"))]
use std::sync::atomic::Ordering;

use crate::{GsoMode, PlainUdpSocket};

#[cfg(all(test, target_os = "linux"))]
use crate::udp_state::GsoTestHook;

impl PlainUdpSocket {
    // Build the per-message GSO sender from a throwaway socket so quinn-udp's
    // receive-path socket options (GRO, IP_TOS, IP_MTU_DISCOVER=PROBE,
    // IP_PKTINFO) land on the throwaway, never on the real socket. `try_send`
    // takes the target fd as a separate argument, so the real socket only ever
    // sees the per-message `UDP_SEGMENT` cmsg.
    #[cfg(target_os = "linux")]
    pub(super) fn build_sender_for(mode: GsoMode) -> Option<Arc<quinn::udp::UdpSocketState>> {
        if matches!(mode, GsoMode::Auto) {
            build_gso_sender()
        } else {
            None
        }
    }

    /// Sends `transmit` as plain datagrams, one per segment. Non-Linux targets
    /// retain the historical nonblocking `sendto` loop. Linux routes grouped
    /// transmits through one safe `sendmmsg` and owns any suffix accepted for
    /// recovery after a positive prefix. No plain path emits `UDP_SEGMENT`.
    #[cfg(not(target_os = "linux"))]
    pub(super) fn send_plain_chunks(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        let segment = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        let socket = socket2::SockRef::from(self.io.as_ref());
        let destination = socket2::SockAddr::from(transmit.destination);
        for chunk in transmit.contents.chunks(segment) {
            socket.send_to(chunk, &destination)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn send_plain_chunks(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        if transmit.contents.is_empty() {
            return Ok(());
        }
        let segment = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        if transmit.contents.chunks(segment).len() > 1 {
            return crate::udp_plain_direct::send(
                &self.plain_batch_io,
                self.plain_counters.as_ref(),
                transmit,
            );
        }
        let socket = socket2::SockRef::from(self.plain_batch_io.socket());
        let destination = socket2::SockAddr::from(transmit.destination);
        let sent = socket.send_to(transmit.contents, &destination)?;
        if sent == transmit.contents.len() {
            Ok(())
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::WriteZero))
        }
    }

    /// Returns true if any segment in this transmit is a QUIC long-header
    /// packet (first byte high bit set), i.e. an Initial/Handshake/0-RTT/Retry
    /// packet that must never be segmented.
    pub(super) fn has_long_header(transmit: &quinn::udp::Transmit, segment: usize) -> bool {
        transmit
            .contents
            .chunks(segment)
            .any(|chunk| chunk.first().is_some_and(|byte| byte & 0x80 != 0))
    }

    /// Attempts a single GSO `sendmsg` for an eligible batched short-header
    /// transmit. On `EINVAL`/`EIO` (or a forced test failure) returns the error
    /// for the caller to fall back; on `WouldBlock` returns it for quinn to
    /// retry; on success returns `Ok(())`.
    #[cfg(target_os = "linux")]
    pub(super) fn try_send_gso(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        if let Some(forced) = self.forced_gso_failure() {
            return Err(forced);
        }
        let Some(sender) = self.gso_sender.as_ref() else {
            return Err(std::io::Error::from(rustix::io::Errno::INVAL));
        };
        // `try_send` emits the per-message `UDP_SEGMENT` cmsg on the target fd
        // and returns the raw `sendmsg` error (unlike `send`, which swallows
        // EINVAL/EIO), so we can run our own per-destination fallback.
        sender.try_send((self.io.as_ref()).into(), transmit)
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn try_send_gso(&self, _transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    /// In test builds, consults the failure hook and returns a forced error
    /// when the hook demands it. Production builds always return `None`.
    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn forced_gso_failure(&self) -> Option<std::io::Error> {
        match self.test_hook {
            GsoTestHook::AlwaysEinval => Some(std::io::Error::from(rustix::io::Errno::INVAL)),
            GsoTestHook::FirstEinval => {
                static FIRST_DONE: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                FIRST_DONE
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                    .then(|| std::io::Error::from(rustix::io::Errno::INVAL))
            }
            GsoTestHook::None => None,
        }
    }

    #[cfg(all(not(test), target_os = "linux"))]
    pub(super) fn forced_gso_failure(&self) -> Option<std::io::Error> {
        None
    }
}

/// Returns true if `error` is a GSO-rejection (`EINVAL`/`EIO`) that should
/// disable GSO for the destination and trigger a plain-datagram fallback.
#[cfg(target_os = "linux")]
pub(super) fn is_gso_rejection(error: &std::io::Error) -> bool {
    matches!(
        rustix::io::Errno::from_io_error(error),
        Some(rustix::io::Errno::INVAL | rustix::io::Errno::IO)
    )
}

/// Returns the process-wide per-message GSO sender, building it at most once.
///
/// [`quinn::udp::UdpSocketState::new`] re-runs the kernel GSO/GRO capability
/// probes (binding throwaway sockets and issuing several `setsockopt` calls)
/// on every invocation, which can block for tens to hundreds of milliseconds
/// under socket-table contention. Doing that per connection stalls the async
/// worker on the connect hot path, so the sender is built once and shared by
/// [`Arc`]: it carries no per-socket fd (`try_send` takes the target fd as an
/// argument), so a single instance is correct for every socket. Returns `None`
/// when the kernel/path reports no GSO capability so the socket stays plain.
#[cfg(target_os = "linux")]
fn build_gso_sender() -> Option<Arc<quinn::udp::UdpSocketState>> {
    static CACHED_SENDER: std::sync::OnceLock<Option<Arc<quinn::udp::UdpSocketState>>> =
        std::sync::OnceLock::new();
    CACHED_SENDER
        .get_or_init(|| {
            let probe = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
                .or_else(|_| std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)))
                .ok()?;
            let state = quinn::udp::UdpSocketState::new((&probe).into()).ok()?;
            // If the kernel/probe reports no GSO capability, do not engage GSO at all.
            if state.max_gso_segments() <= 1 {
                return None;
            }
            Some(Arc::new(state))
        })
        .clone()
}
