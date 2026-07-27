/// Selects whether the adaptive UDP socket may attempt Linux UDP GSO
/// (`UDP_SEGMENT`) on eligible egress, or always falls back to one datagram per
/// segment (the historical safe behaviour).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GsoMode {
    /// Never attempt GSO; send one datagram per segment. Always safe.
    Off,
    /// Attempt GSO on eligible short-header batched transmits, with per-message
    /// `UDP_SEGMENT` cmsg and same-call fallback to plain datagrams on the first
    /// `EINVAL`/`EIO` from a destination. Enabled only by explicit opt-in on
    /// Linux.
    Auto,
}

impl GsoMode {
    /// Resolves the production GSO mode from the environment. GSO is opt-in:
    /// `ZUICITY_ENABLE_GSO=1` (or `true`) enables [`GsoMode::Auto`], while
    /// unset, invalid, or `ZUICITY_DISABLE_GSO=1` keeps [`GsoMode::Off`]. On
    /// non-Linux targets GSO is always [`GsoMode::Off`].
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

    /// Maximum number of datagrams quinn may pack into one [`quinn::udp::Transmit`].
    #[cfg(target_os = "linux")]
    pub(crate) const fn max_transmit_segments(self) -> usize {
        match self {
            Self::Off | Self::Auto => crate::udp_plain_batch::MAX_PLAIN_BATCH_DATAGRAMS,
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) const fn max_transmit_segments(self) -> usize {
        match self {
            Self::Off | Self::Auto => 1,
        }
    }
}

fn env_flag_is_set(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        let value = value.trim();
        value == "1" || value.eq_ignore_ascii_case("true")
    })
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

    /// Resolves the production GRO mode from the environment, mirroring
    /// [`GsoMode::from_env`]. `ZUICITY_DISABLE_GRO=1` (or `true`) forces
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
