use crate::PlainUdpSocket;

#[cfg(all(test, target_os = "linux"))]
use crate::udp_state::GsoTestHook;

impl PlainUdpSocket {
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

    pub(super) fn has_long_header(transmit: &quinn::udp::Transmit, segment: usize) -> bool {
        transmit
            .contents
            .chunks(segment)
            .any(|chunk| chunk.first().is_some_and(|byte| byte & 0x80 != 0))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn try_send_gso(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        if let Some(error) = self.forced_gso_failure() {
            return Err(error);
        }
        let send = || quinn::send_udp_gso(self.io.as_ref(), transmit);
        match send() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                self.io.try_io(tokio::io::Interest::WRITABLE, send)
            }
            result => result,
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn try_send_gso(&self, _transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    #[cfg(all(test, target_os = "linux"))]
    fn forced_gso_failure(&self) -> Option<std::io::Error> {
        let errno = match self.test_hook {
            GsoTestHook::None => return None,
            GsoTestHook::AlwaysEinval => rustix::io::Errno::INVAL,
            GsoTestHook::AlwaysEio => rustix::io::Errno::IO,
        };
        Some(std::io::Error::from(errno))
    }

    #[cfg(all(not(test), target_os = "linux"))]
    fn forced_gso_failure(&self) -> Option<std::io::Error> {
        None
    }
}

#[cfg(target_os = "linux")]
pub(super) fn is_gso_rejection(error: &std::io::Error) -> bool {
    matches!(
        rustix::io::Errno::from_io_error(error),
        Some(rustix::io::Errno::INVAL | rustix::io::Errno::IO)
    )
}

#[cfg(not(target_os = "linux"))]
pub(super) fn is_gso_rejection(_error: &std::io::Error) -> bool {
    false
}
