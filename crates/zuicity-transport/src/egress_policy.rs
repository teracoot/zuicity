use std::net::IpAddr;

use crate::ProxyDialerLink;

/// Target-side egress policy for server proxy relays.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProxyEgressPolicy {
    /// Optional source IP used when dialing proxied targets.
    pub send_through: Option<IpAddr>,
    /// Optional packet mark applied to outbound target sockets.
    pub fwmark: Option<u32>,
    /// Optional upstream-compatible outbound proxy link for target dials.
    pub dialer_link: Option<ProxyDialerLink>,
}

impl ProxyEgressPolicy {
    /// Returns the default direct egress policy.
    #[must_use]
    pub const fn direct() -> Self {
        Self {
            send_through: None,
            fwmark: None,
            dialer_link: None,
        }
    }

    /// Builds an egress policy with an optional source IP.
    #[must_use]
    pub const fn with_send_through(send_through: Option<IpAddr>) -> Self {
        Self {
            send_through,
            fwmark: None,
            dialer_link: None,
        }
    }

    /// Builds an egress policy with optional source IP and packet mark.
    #[must_use]
    pub const fn with_send_through_and_fwmark(
        send_through: Option<IpAddr>,
        fwmark: Option<u32>,
    ) -> Self {
        Self {
            send_through,
            fwmark,
            dialer_link: None,
        }
    }

    /// Builds an egress policy with optional source IP, packet mark, and outbound link.
    #[must_use]
    pub const fn with_send_through_fwmark_and_dialer_link(
        send_through: Option<IpAddr>,
        fwmark: Option<u32>,
        dialer_link: Option<ProxyDialerLink>,
    ) -> Self {
        Self {
            send_through,
            fwmark,
            dialer_link,
        }
    }
}
