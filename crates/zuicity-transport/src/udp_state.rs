use std::sync::Arc;

use zuicity_protocol::AtomicCounter64;

/// Per-destination GSO capability learned at runtime. One hostile egress path
/// must not disable GSO for unrelated peers, so this is tracked per
/// destination [`SocketAddr`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GsoDestState {
    /// No GSO send has been attempted to this destination yet.
    Unknown,
    /// A GSO send to this destination has succeeded.
    Working,
    /// A GSO send to this destination failed with `EINVAL`/`EIO`; fall back to
    /// plain datagrams for this destination from now on.
    Disabled,
}

/// Counters for the adaptive GSO send path. Exposed as atomics so tests can
/// assert on engagement and fallback behaviour without scraping logs.
#[derive(Debug, Default)]
pub(crate) struct GsoCounters {
    /// GSO `sendmsg` attempts (eligible batched short-header transmits).
    pub(crate) attempt: AtomicCounter64,
    /// GSO `sendmsg` attempts that succeeded.
    pub(crate) success: AtomicCounter64,
    /// GSO `sendmsg` attempts that failed with `EINVAL`/`EIO`.
    pub(crate) fallback: AtomicCounter64,
    /// Plain chunked sends performed after a GSO fallback for a destination.
    pub(crate) plain_after_fallback: AtomicCounter64,
    /// GSO attempts that involved a long-header packet. Must always stay zero:
    /// the long-header guard routes Initial/Handshake packets to the plain path
    /// before any GSO attempt, so this is a tripwire for that invariant.
    pub(crate) long_header_gso_attempt: AtomicCounter64,
}

#[derive(Debug, Default)]
pub(crate) struct PlainSendCounters {
    pub(crate) sendmmsg_calls: AtomicCounter64,
    pub(crate) sendmmsg_datagrams: AtomicCounter64,
    pub(crate) partial_prefixes: AtomicCounter64,
}

/// Counters for the GRO receive path. Exposed as atomics so tests can assert
/// that coalescing actually engaged without scraping logs.
#[derive(Debug, Default)]
pub(crate) struct GroCounters {
    /// `recvmsg` calls that returned a coalesced super-buffer (the kernel
    /// `UDP_GRO` cmsg reported a stride smaller than the received length, i.e.
    /// more than one datagram in a single read).
    pub(crate) gro_coalesced_recv: AtomicCounter64,
    /// Total datagrams delivered across all coalesced reads (sum of segment
    /// counts), so a test can confirm GRO carried real volume.
    pub(crate) gro_segments_total: AtomicCounter64,
}

/// Shared GRO receiver. `Some` only when GRO is enabled and the kernel/path
/// supports it; the `recv` it exposes parses the `UDP_GRO` segment-size cmsg.
/// `None` means the receive path is the plain per-datagram one.
pub(crate) type GroReceiver = Option<Arc<quinn::udp::UdpSocketState>>;

/// Test hook to force GSO `sendmsg` failures deterministically. Only present
/// in test builds; production has no hook and always attempts a real send.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GsoTestHook {
    /// No forced failures; behave normally.
    None,
    /// Force the first GSO attempt to any destination to fail with `EINVAL`.
    FirstEinval,
    /// Force every GSO attempt to fail with `EINVAL`.
    AlwaysEinval,
}
