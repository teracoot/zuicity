//! Stateless Linux UDP GSO sends for custom Quinn sockets.

use std::{io, mem, os::fd::AsRawFd, ptr};

use crate::udp::Transmit;

const MAX_CONSECUTIVE_INTERRUPTS: usize = 8;
const CONTROL_LEN: usize = unsafe { libc::CMSG_SPACE(mem::size_of::<u16>() as libc::c_uint) } as usize;

#[repr(align(16))]
struct AlignedControl([u8; CONTROL_LEN]);

/// Sends one grouped transmit with a per-message Linux `UDP_SEGMENT` cmsg.
///
/// This function does not probe GSO support or set persistent socket options.
/// Callers learn support from the real send result and may fall back on
/// `EINVAL` or `EIO`.
pub fn send_udp_gso<S: AsRawFd>(socket: &S, transmit: &Transmit<'_>) -> io::Result<()> {
    let segment_size = transmit.segment_size.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "UDP GSO requires a segment size")
    })?;
    if segment_size == 0
        || segment_size >= transmit.contents.len()
        || segment_size > usize::from(u16::MAX)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid UDP GSO segment size",
        ));
    }

    let destination = socket2::SockAddr::from(transmit.destination);
    let mut iovec = libc::iovec {
        iov_base: transmit.contents.as_ptr().cast_mut().cast(),
        iov_len: transmit.contents.len(),
    };
    let mut control = AlignedControl([0; CONTROL_LEN]);
    let mut header: libc::msghdr = unsafe { mem::zeroed() };
    header.msg_name = destination.as_ptr().cast_mut().cast();
    header.msg_namelen = destination.len();
    header.msg_iov = ptr::from_mut(&mut iovec);
    header.msg_iovlen = 1;
    header.msg_control = control.0.as_mut_ptr().cast();
    header.msg_controllen = CONTROL_LEN as _;

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&header) };
    if cmsg.is_null() {
        return Err(io::Error::other("failed to allocate UDP GSO control message"));
    }
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_UDP;
        (*cmsg).cmsg_type = libc::UDP_SEGMENT;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<u16>() as libc::c_uint) as _;
        ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<u16>(), segment_size as u16);
    }
    let mut interrupted = 0;
    loop {
        let result = unsafe {
            libc::sendmsg(
                socket.as_raw_fd(),
                &header,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if result >= 0 {
            return if result as usize == transmit.contents.len() {
                Ok(())
            } else {
                Err(io::Error::from(io::ErrorKind::WriteZero))
            };
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
        interrupted += 1;
        if interrupted == MAX_CONSECUTIVE_INTERRUPTS {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_segment_sizes_without_a_syscall() {
        let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let destination = socket.local_addr().unwrap();
        let payload = [0_u8; 4];

        for segment_size in [None, Some(0), Some(payload.len()), Some(payload.len() + 1)] {
            let transmit = Transmit {
                destination,
                ecn: None,
                contents: &payload,
                segment_size,
                src_ip: None,
            };
            assert_eq!(
                send_udp_gso(&socket, &transmit).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
