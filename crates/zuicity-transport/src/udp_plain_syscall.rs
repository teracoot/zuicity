use std::{
    io::{self, IoSlice},
    os::fd::AsFd,
    sync::{Arc, atomic::Ordering},
    time::Instant,
};

use arrayvec::ArrayVec;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    net::{MMsgHdr, SendAncillaryBuffer, SendFlags, SocketAddrAny, sendmmsg},
};

use crate::{
    udp_plain_batch::{MAX_PLAIN_BATCH_DATAGRAMS, PlainTransmit},
    udp_state::PlainSendCounters,
};

const MAX_CONSECUTIVE_INTERRUPTS: usize = 8;

pub(super) struct PlainBatchIo {
    socket: Arc<tokio::net::UdpSocket>,
    #[cfg(test)]
    hook: Option<crate::udp_plain_test_support::PlainSendTestHook>,
}

impl PlainBatchIo {
    pub(super) fn new(socket: Arc<tokio::net::UdpSocket>) -> Self {
        Self {
            socket,
            #[cfg(test)]
            hook: None,
        }
    }

    #[cfg(test)]
    pub(super) fn with_hook(
        socket: Arc<tokio::net::UdpSocket>,
        hook: crate::udp_plain_test_support::PlainSendTestHook,
    ) -> Self {
        Self {
            socket,
            hook: Some(hook),
        }
    }

    pub(super) fn socket(&self) -> &tokio::net::UdpSocket {
        self.socket.as_ref()
    }

    pub(super) fn attempt(
        &self,
        counters: &PlainSendCounters,
        transmit: PlainTransmit<'_>,
    ) -> io::Result<ArrayVec<usize, MAX_PLAIN_BATCH_DATAGRAMS>> {
        let mut interrupted = 0;
        let mut clear_cached_readiness = false;
        loop {
            let result = if clear_cached_readiness {
                self.socket.try_io(tokio::io::Interest::WRITABLE, || {
                    self.attempt_once(counters, transmit)
                })
            } else {
                self.attempt_once(counters, transmit)
            };
            match result {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    interrupted += 1;
                    if interrupted == MAX_CONSECUTIVE_INTERRUPTS {
                        return Err(io::Error::from(io::ErrorKind::Interrupted));
                    }
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && !clear_cached_readiness =>
                {
                    clear_cached_readiness = true;
                }
                result => return result,
            }
        }
    }

    fn attempt_once(
        &self,
        counters: &PlainSendCounters,
        transmit: PlainTransmit<'_>,
    ) -> io::Result<ArrayVec<usize, MAX_PLAIN_BATCH_DATAGRAMS>> {
        counters.sendmmsg_calls.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        if let Some(hook) = &self.hook {
            return hook.attempt(transmit);
        }
        sendmmsg_once(self.socket.as_ref(), transmit)
    }

    pub(super) fn wait_writable(&self, deadline: Instant) -> io::Result<()> {
        #[cfg(test)]
        if let Some(hook) = &self.hook {
            return hook.poll_writable();
        }
        wait_socket_writable(self.socket.as_ref(), deadline)
    }
}

fn wait_socket_writable(socket: &tokio::net::UdpSocket, deadline: Instant) -> io::Result<()> {
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        };
        if remaining.is_zero() {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        let timeout = Timespec::try_from(remaining)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut descriptor = PollFd::from_borrowed_fd(socket.as_fd(), PollFlags::OUT);
        match poll(std::slice::from_mut(&mut descriptor), Some(&timeout)) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::TimedOut)),
            Ok(_) => {
                let events = descriptor.revents();
                let errors = events & (PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL);
                if !errors.is_empty() {
                    return poll_error(socket, errors);
                }
                if events.contains(PollFlags::OUT) {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) => return Err(io::Error::from(error)),
        }
    }
}

fn poll_error(socket: &tokio::net::UdpSocket, events: PollFlags) -> io::Result<()> {
    if events.contains(PollFlags::ERR)
        && let Some(error) = socket.take_error()?
    {
        return Err(error);
    }
    if events.contains(PollFlags::NVAL) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    if events.contains(PollFlags::HUP) {
        return Err(io::Error::from(io::ErrorKind::BrokenPipe));
    }
    Err(io::Error::other("UDP socket poll reported an error"))
}

fn sendmmsg_once(
    socket: &tokio::net::UdpSocket,
    transmit: PlainTransmit<'_>,
) -> io::Result<ArrayVec<usize, MAX_PLAIN_BATCH_DATAGRAMS>> {
    let _metadata_ignored_by_plain_path = (transmit.ecn, transmit.src_ip);
    let address = SocketAddrAny::from(transmit.destination);
    let datagram_count = transmit.datagram_count();
    let mut iovecs = ArrayVec::<_, MAX_PLAIN_BATCH_DATAGRAMS>::new();
    for datagram in transmit.datagrams() {
        iovecs
            .try_push([IoSlice::new(datagram)])
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    }
    let mut controls = ArrayVec::<_, MAX_PLAIN_BATCH_DATAGRAMS>::new();
    for _ in 0..datagram_count {
        controls
            .try_push(SendAncillaryBuffer::default())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    }
    let mut messages = ArrayVec::<_, MAX_PLAIN_BATCH_DATAGRAMS>::new();
    for (iov, control) in iovecs.iter().zip(controls.iter_mut()) {
        messages
            .try_push(MMsgHdr::new_with_addr(&address, iov, control))
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    }
    let count = sendmmsg(socket, &mut messages, SendFlags::DONTWAIT).map_err(io::Error::from)?;
    if count > messages.len() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut sent_lengths = ArrayVec::<_, MAX_PLAIN_BATCH_DATAGRAMS>::new();
    for message in messages.iter().take(count) {
        sent_lengths
            .try_push(message.bytes_sent())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    }
    Ok(sent_lengths)
}
