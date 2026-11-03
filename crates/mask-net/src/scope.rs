//! Network scope: which IP addresses MORP components may use.
//!
//! v0.6 lets MORP leave the single machine, but **only onto networks you
//! control**. Every bind address, advertised address, `EXTEND` target,
//! authority address, and accepted peer is checked against a scope:
//!
//! - [`NetworkScope::Loopback`] (default): 127.0.0.0/8 and ::1 only, the
//!   v0.5 behaviour.
//! - [`NetworkScope::Private`]: loopback plus private ranges: RFC 1918
//!   (10/8, 172.16/12, 192.168/16), CGNAT 100.64/10 (Tailscale-style VPNs),
//!   and IPv6 unique-local fc00::/7.
//!
//! **Public addresses are always refused.** So are unspecified addresses
//! (`0.0.0.0`, `::`), which would bind every interface including public ones,
//! and link-local, multicast, and broadcast addresses.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::NetError;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkScope {
    /// One machine only (127.0.0.0/8, ::1).
    #[default]
    Loopback,
    /// Loopback plus private LAN / VPN ranges. Never public addresses.
    Private,
}

/// What kind of address an IP is, for scope decisions and error messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressClass {
    Loopback,
    Private,
    /// 0.0.0.0 or `::`: "every interface".
    Unspecified,
    /// Link-local, multicast, broadcast, documentation, reserved.
    Special,
    Public,
}

/// Classify an IP address. IPv4-mapped IPv6 addresses are classified as IPv4.
pub fn classify(ip: IpAddr) -> AddressClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => classify_v4(v4),
            None => classify_v6(v6),
        },
    }
}

fn classify_v4(ip: Ipv4Addr) -> AddressClass {
    let [a, b, ..] = ip.octets();
    if ip.is_loopback() {
        AddressClass::Loopback
    } else if ip.is_unspecified() {
        AddressClass::Unspecified
    } else if ip.is_private() || (a == 100 && (64..128).contains(&b)) {
        // RFC 1918, or RFC 6598 shared address space (100.64.0.0/10).
        AddressClass::Private
    } else if ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0
        || a >= 240
    {
        AddressClass::Special
    } else {
        AddressClass::Public
    }
}

fn classify_v6(ip: Ipv6Addr) -> AddressClass {
    let first = ip.segments()[0];
    if ip.is_loopback() {
        AddressClass::Loopback
    } else if ip.is_unspecified() {
        AddressClass::Unspecified
    } else if first & 0xfe00 == 0xfc00 {
        AddressClass::Private // fc00::/7 unique local
    } else if first & 0xffc0 == 0xfe80
        || ip.is_multicast()
        || first == 0x2001 && ip.segments()[1] == 0x0db8
    {
        AddressClass::Special // link-local, multicast, documentation
    } else {
        AddressClass::Public
    }
}

impl NetworkScope {
    /// Is `ip` usable in this scope?
    pub fn allows_ip(self, ip: IpAddr) -> bool {
        matches!(
            (self, classify(ip)),
            (_, AddressClass::Loopback) | (NetworkScope::Private, AddressClass::Private)
        )
    }

    pub fn allows(self, addr: SocketAddr) -> bool {
        self.allows_ip(addr.ip())
    }

    /// `Ok` if `addr` is usable; otherwise an error naming the problem.
    pub fn check(self, addr: SocketAddr) -> Result<(), NetError> {
        if self.allows(addr) {
            Ok(())
        } else {
            Err(NetError::OutOfScope { addr, scope: self })
        }
    }

    /// Like [`check`](Self::check), but also refuses port 0 (for addresses
    /// that others will connect to).
    pub fn check_reachable(self, addr: SocketAddr) -> Result<(), NetError> {
        self.check(addr)?;
        if addr.port() == 0 {
            return Err(NetError::InvalidConfig(format!("{addr} has no port")));
        }
        Ok(())
    }

    pub fn describe(self) -> &'static str {
        match self {
            NetworkScope::Loopback => "loopback only (127.0.0.0/8, ::1)",
            NetworkScope::Private => {
                "loopback and private networks (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7)"
            }
        }
    }
}

impl fmt::Display for NetworkScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NetworkScope::Loopback => "loopback",
            NetworkScope::Private => "private",
        })
    }
}

impl FromStr for NetworkScope {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "loopback" => Ok(Self::Loopback),
            "private" => Ok(Self::Private),
            other => Err(format!(
                "unknown network scope \"{other}\" (expected loopback or private; public is not supported)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn classification_table() {
        let table = [
            ("127.0.0.1", AddressClass::Loopback),
            ("127.5.6.7", AddressClass::Loopback),
            ("::1", AddressClass::Loopback),
            ("10.0.0.1", AddressClass::Private),
            ("172.16.0.1", AddressClass::Private),
            ("172.31.255.254", AddressClass::Private),
            ("192.168.1.251", AddressClass::Private),
            ("100.64.0.1", AddressClass::Private),
            ("100.127.255.254", AddressClass::Private),
            ("fd12:3456::1", AddressClass::Private),
            ("::ffff:192.168.1.5", AddressClass::Private),
            ("0.0.0.0", AddressClass::Unspecified),
            ("::", AddressClass::Unspecified),
            ("169.254.1.1", AddressClass::Special),
            ("fe80::1", AddressClass::Special),
            ("224.0.0.1", AddressClass::Special),
            ("255.255.255.255", AddressClass::Special),
            ("8.8.8.8", AddressClass::Public),
            ("172.32.0.1", AddressClass::Public),
            ("100.128.0.1", AddressClass::Public),
            ("192.169.0.1", AddressClass::Public),
            ("2606:4700::1111", AddressClass::Public),
            ("::ffff:8.8.8.8", AddressClass::Public),
        ];
        for (addr, class) in table {
            assert_eq!(classify(ip(addr)), class, "{addr}");
        }
    }

    #[test]
    fn public_addresses_are_refused_in_every_scope() {
        for scope in [NetworkScope::Loopback, NetworkScope::Private] {
            for addr in [
                "8.8.8.8:7101",
                "[2606:4700::1111]:7101",
                "0.0.0.0:7101",
                "[::]:7101",
                "169.254.0.1:7101",
            ] {
                let addr: SocketAddr = addr.parse().unwrap();
                assert!(
                    matches!(scope.check(addr), Err(NetError::OutOfScope { .. })),
                    "{scope} {addr}"
                );
            }
        }
    }

    #[test]
    fn loopback_scope_refuses_lan_and_private_scope_accepts_it() {
        let lan: SocketAddr = "192.168.1.20:7101".parse().unwrap();
        assert!(NetworkScope::Loopback.check(lan).is_err());
        assert!(NetworkScope::Private.check(lan).is_ok());
        let local: SocketAddr = "127.0.0.1:7101".parse().unwrap();
        assert!(NetworkScope::Loopback.check(local).is_ok());
        assert!(NetworkScope::Private.check(local).is_ok());
    }

    #[test]
    fn reachable_addresses_need_a_port() {
        let addr: SocketAddr = "10.0.0.2:0".parse().unwrap();
        assert!(NetworkScope::Private.check_reachable(addr).is_err());
    }

    #[test]
    fn scope_parses_and_public_is_unknown() {
        assert_eq!("Private".parse::<NetworkScope>(), Ok(NetworkScope::Private));
        assert!("public".parse::<NetworkScope>().is_err());
    }
}
