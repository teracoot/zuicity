//! Linux receive-only UDP GRO support for custom Quinn sockets.

use std::{
    io::{self, IoSliceMut},
    mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::AsRawFd,
    ptr,
};

use crate::udp::RecvMeta;

const CONTROL_LEN: usize = 64;
const OPTION_ON: libc::c_int = 1;

#[repr(align(16))]
struct AlignedControl([u8; CONTROL_LEN]);

/// Socket-independent state for receiving Linux UDP GRO super-buffers.
///
/// Unlike [`crate::udp::UdpSocketState`], construction configures only receive
/// GRO and fragmentation behavior. It never probes or emits `UDP_SEGMENT`.
#[derive(Debug)]
pub struct GroSocketState {
    may_fragment: bool,
}

impl GroSocketState {
    /// Enables `UDP_GRO` on `socket` without probing UDP GSO support.
    pub fn new(socket: &std::net::UdpSocket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        let is_ipv4 = socket.local_addr()?.is_ipv4();

        // No fallible operation follows this call, so an enabled socket always
        // retains a receiver capable of decoding UDP_GRO control messages.
        set_socket_option(socket, libc::SOL_UDP, libc::UDP_GRO, OPTION_ON)?;

        let mut may_fragment = set_socket_option(
            socket,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_PROBE,
        )
        .is_err();
        if !is_ipv4 {
            may_fragment |= set_socket_option(
                socket,
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                libc::IPV6_PMTUDISC_PROBE,
            )
            .is_err();
            may_fragment |= set_socket_option(
                socket,
                libc::IPPROTO_IPV6,
                libc::IPV6_DONTFRAG,
                OPTION_ON,
            )
            .is_err();
        }

        Ok(Self { may_fragment })
    }

    /// Receives up to Quinn's platform batch size and decodes each `UDP_GRO`
    /// stride into the corresponding [`RecvMeta`].
    pub fn recv<S: AsRawFd>(
        &self,
        socket: &S,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        let capacity = bufs.len().min(meta.len()).min(crate::udp::BATCH_SIZE);
        if capacity == 0 {
            return Ok(0);
        }

        let mut names: [libc::sockaddr_storage; crate::udp::BATCH_SIZE] =
            std::array::from_fn(|_| unsafe { mem::zeroed() });
        let mut controls: [AlignedControl; crate::udp::BATCH_SIZE] =
            std::array::from_fn(|_| AlignedControl([0; CONTROL_LEN]));
        let mut iovecs: [libc::iovec; crate::udp::BATCH_SIZE] =
            std::array::from_fn(|_| libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            });
        let mut headers: [libc::mmsghdr; crate::udp::BATCH_SIZE] =
            std::array::from_fn(|_| unsafe { mem::zeroed() });

        for index in 0..capacity {
            iovecs[index] = libc::iovec {
                iov_base: bufs[index].as_mut_ptr().cast(),
                iov_len: bufs[index].len(),
            };
            let header = &mut headers[index].msg_hdr;
            *header = unsafe { mem::zeroed() };
            header.msg_name = ptr::from_mut(&mut names[index]).cast();
            header.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            header.msg_iov = &mut iovecs[index];
            header.msg_iovlen = 1;
            header.msg_control = controls[index].0.as_mut_ptr().cast();
            header.msg_controllen = CONTROL_LEN as _;
        }

        let received = loop {
            let result = unsafe {
                libc::recvmmsg(
                    socket.as_raw_fd(),
                    headers.as_mut_ptr(),
                    capacity as libc::c_uint,
                    0,
                    ptr::null_mut(),
                )
            };
            if result >= 0 {
                break result as usize;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        };

        for index in 0..received {
            meta[index] = decode_meta(
                &names[index],
                &headers[index].msg_hdr,
                headers[index].msg_len as usize,
            )?;
        }
        Ok(received)
    }

    /// Whether the configured socket may fragment transmitted datagrams.
    #[must_use]
    pub const fn may_fragment(&self) -> bool {
        self.may_fragment
    }
}

fn decode_meta(
    name: &libc::sockaddr_storage,
    header: &libc::msghdr,
    len: usize,
) -> io::Result<RecvMeta> {
    if header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated UDP GRO message",
        ));
    }
    let addr = decode_addr(name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid UDP source address"))?;
    let stride = decode_stride(header, len).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid UDP GRO segment size")
    })?;
    Ok(RecvMeta {
        addr,
        len,
        stride,
        ecn: None,
        dst_ip: None,
    })
}

fn decode_stride(header: &libc::msghdr, len: usize) -> Option<usize> {
    let mut gro_stride = None;
    let mut control = unsafe { libc::CMSG_FIRSTHDR(header) };
    while !control.is_null() {
        let control_ref = unsafe { &*control };
        if control_ref.cmsg_level == libc::SOL_UDP && control_ref.cmsg_type == libc::UDP_GRO {
            let minimum = unsafe {
                libc::CMSG_LEN(mem::size_of::<libc::c_int>() as libc::c_uint) as usize
            };
            if (control_ref.cmsg_len as usize) < minimum {
                return None;
            }
            gro_stride = Some(unsafe {
                ptr::read_unaligned(libc::CMSG_DATA(control).cast::<libc::c_int>())
            });
        }
        control = unsafe { libc::CMSG_NXTHDR(header, control) };
    }
    normalize_stride(len, gro_stride)
}

fn normalize_stride(len: usize, gro_stride: Option<libc::c_int>) -> Option<usize> {
    if len == 0 {
        return Some(0);
    }
    let stride = match gro_stride {
        Some(stride) if stride > 0 => stride as usize,
        Some(_) => return None,
        None => len,
    };
    (stride <= len).then_some(stride)
}

fn decode_addr(name: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match libc::c_int::from(name.ss_family) {
        libc::AF_INET => {
            let addr = unsafe { &*(ptr::from_ref(name).cast::<libc::sockaddr_in>()) };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(addr.sin_port),
            )))
        }
        libc::AF_INET6 => {
            let addr = unsafe { &*(ptr::from_ref(name).cast::<libc::sockaddr_in6>()) };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(addr.sin6_addr.s6_addr),
                u16::from_be(addr.sin6_port),
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

fn set_socket_option(
    socket: &impl AsRawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            ptr::from_ref(&value).cast(),
            mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_stride;

    #[test]
    fn gro_stride_accepts_a_short_final_datagram() {
        assert_eq!(normalize_stride(2500, Some(1200)), Some(1200));
    }

    #[test]
    fn gro_stride_rejects_invalid_metadata() {
        assert_eq!(normalize_stride(1200, Some(0)), None);
        assert_eq!(normalize_stride(1200, Some(-1)), None);
        assert_eq!(normalize_stride(1200, Some(1201)), None);
    }
}
