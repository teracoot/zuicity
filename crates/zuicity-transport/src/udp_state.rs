use std::sync::Arc;

use zuicity_protocol::AtomicCounter64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GsoDestState {
    Unknown,
    Working,
    Disabled,
}

#[derive(Debug, Default)]
pub(crate) struct GsoCounters {
    pub(crate) attempt: AtomicCounter64,
    pub(crate) success: AtomicCounter64,
    pub(crate) fallback: AtomicCounter64,
    pub(crate) plain_after_fallback: AtomicCounter64,
}

#[cfg(all(test, target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GsoTestHook {
    None,
    AlwaysEinval,
    AlwaysEio,
}

#[derive(Debug, Default)]
#[cfg(target_os = "linux")]
pub(crate) struct PlainSendCounters {
    pub(crate) sendmmsg_calls: AtomicCounter64,
    pub(crate) sendmmsg_datagrams: AtomicCounter64,
    pub(crate) partial_prefixes: AtomicCounter64,
}

/// Counters for the GRO receive path. Exposed as atomics so tests can assert
/// that coalescing actually engaged without scraping logs.
#[derive(Debug, Default)]
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
pub(crate) type GroReceiver = Option<Arc<quinn::GroSocketState>>;

#[cfg(not(target_os = "linux"))]
pub(crate) type GroReceiver = Option<Arc<()>>;
