/// Zuicity's UDP send policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GsoMode {
    /// Never issue `UDP_SEGMENT`; grouped transmits use ordinary datagrams.
    Off,
    /// Attempt GSO on eligible grouped short-header transmits, with adaptive
    /// per-destination fallback to ordinary datagrams.
    Auto,
}

impl GsoMode {
    /// Maximum safe segment count for one UDP GSO super-message at normal QUIC MTUs.
    const MAX_GSO_SEGMENTS: usize = 44;

    /// Resolves the production GSO mode. GSO is off unless explicitly enabled
    /// with `ZUICITY_ENABLE_GSO=1` or `true`. `ZUICITY_DISABLE_GSO` takes
    /// precedence, and non-Linux targets are always off.
    #[must_use]
    pub fn from_env() -> Self {
        let enable = std::env::var("ZUICITY_ENABLE_GSO").ok();
        let disable = std::env::var("ZUICITY_DISABLE_GSO").ok();
        Self::from_env_values(enable.as_deref(), disable.as_deref())
    }

    pub(crate) fn from_env_values(enable: Option<&str>, disable: Option<&str>) -> Self {
        if !cfg!(target_os = "linux") || env_flag_is_set(disable) {
            return Self::Off;
        }
        if env_flag_is_set(enable) {
            Self::Auto
        } else {
            Self::Off
        }
    }

    pub(crate) const fn max_transmit_segments(self, plain_batch_segments: usize) -> usize {
        match self {
            Self::Off => plain_batch_segments,
            Self::Auto => {
                if plain_batch_segments > Self::MAX_GSO_SEGMENTS {
                    Self::MAX_GSO_SEGMENTS
                } else {
                    plain_batch_segments
                }
            }
        }
    }
}

fn env_flag_is_set(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        let value = value.trim();
        value == "1" || value.eq_ignore_ascii_case("true")
    })
}

pub(crate) fn plain_batch_segments_from_env(default_segments: usize) -> usize {
    let value = std::env::var("ZUICITY_PLAIN_BATCH_SEGMENTS").ok();
    plain_batch_segments_from_value(value.as_deref(), default_segments)
}

#[cfg(target_os = "linux")]
pub(crate) fn plain_batch_segments_from_value(
    value: Option<&str>,
    default_segments: usize,
) -> usize {
    match value.map(str::trim) {
        Some("20") => 20,
        Some("32") => 32,
        Some("64") => 64,
        Some("80") => 80,
        Some("88") => 88,
        Some("96") => 96,
        Some("104") => 104,
        Some("112") => 112,
        Some("128") => 128,
        Some(_) | None => default_segments,
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn plain_batch_segments_from_value(
    _value: Option<&str>,
    _default_segments: usize,
) -> usize {
    1
}

/// Selects whether the adaptive UDP socket enables Linux UDP GRO
/// (`UDP_GRO`) on the receive path, coalescing several same-sized datagrams
/// into one `recvmsg` and splitting the super-buffer back into segments via the
/// kernel-reported `gso_size`, or always receives one datagram per `recvmsg`
/// (the historical safe behaviour).
///
/// GRO is wire-invisible: it changes only how the *local* kernel batches
/// already-received datagrams up to userspace. It enables exactly one extra
/// receive-side socket option (`UDP_GRO`); it never touches ECN
/// (`IP_RECVTOS`/`IP_TOS`), PMTUDISC (`IP_MTU_DISCOVER`), or `IP_PKTINFO`, so
/// the cross-host reliability profile of the plain receive path is preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroMode {
    /// Never enable GRO; receive one datagram per `recvmsg`. Always safe.
    Off,
    /// Enable `UDP_GRO` on the receive socket and split coalesced super-buffers
    /// by the kernel-reported segment size. Default in production on Linux.
    Auto,
}

impl GroMode {
    /// Linux caps GRO coalescing at `UDP_GRO_CNT_MAX = 64` segments per
    /// `recvmsg`. The receive buffer quinn allocates per slot is sized as
    /// `max_udp_payload_size * max_receive_segments()`, so this also bounds the
    /// per-slot buffer growth.
    const MAX_GRO_SEGMENTS: usize = 64;

    /// Resolves the production GRO mode from the environment.
    /// `ZUICITY_DISABLE_GRO=1` (or `true`) forces
    /// [`GroMode::Off`]; anything else (including unset) is [`GroMode::Auto`].
    /// On non-Linux targets GRO is always [`GroMode::Off`].
    #[must_use]
    pub fn from_env() -> Self {
        if !cfg!(target_os = "linux") {
            return Self::Off;
        }
        match std::env::var("ZUICITY_DISABLE_GRO") {
            Ok(value) => {
                let value = value.trim();
                if value == "1" || value.eq_ignore_ascii_case("true") {
                    Self::Off
                } else {
                    Self::Auto
                }
            }
            Err(_) => Self::Auto,
        }
    }

    /// Maximum number of datagrams a single [`quinn::udp::RecvMeta`] may
    /// describe. quinn uses this to size each receive buffer slot
    /// (`max_udp_payload_size * max_receive_segments`); it must be `> 1` for GRO
    /// coalescing to have room to land, and `1` keeps the historical per-slot
    /// buffer size when GRO is off.
    pub(crate) const fn max_receive_segments(self) -> usize {
        match self {
            Self::Off => 1,
            Self::Auto => Self::MAX_GRO_SEGMENTS,
        }
    }
}
