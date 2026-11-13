//! Which addresses the worker may connect to.
//!
//! The worker fetches pages of sites that are hostile by nature. A domain can resolve to
//! a private address (on purpose, DNS rebinding) to make the worker reach the router, a
//! NAS or a cloud metadata service. Every address a name resolves to must pass
//! [`is_public`] before any connection, redirects included.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// True when `ip` is a globally routable unicast address.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0                                   // 0.0.0.0/8 "this network"
        || (a == 100 && (64..128).contains(&b))     // 100.64.0.0/10 CGNAT
        || (a == 192 && b == 0 && c == 0)           // 192.0.0.0/24 IETF protocol assignments
        || (a == 198 && (b == 18 || b == 19))       // 198.18.0.0/15 benchmarking
        || a >= 240) // 240.0.0.0/4 reserved
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    // IPv4-mapped and IPv4-compatible forms are judged as the IPv4 address they carry
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let s = ip.segments();
    if s[..6] == [0, 0, 0, 0, 0, 0] && !ip.is_loopback() && !ip.is_unspecified() {
        return is_public_v4(Ipv4Addr::new(
            (s[6] >> 8) as u8,
            s[6] as u8,
            (s[7] >> 8) as u8,
            s[7] as u8,
        ));
    }
    // NAT64 well-known prefix 64:ff9b::/96
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return is_public_v4(Ipv4Addr::new(
            (s[6] >> 8) as u8,
            s[6] as u8,
            (s[7] >> 8) as u8,
            s[7] as u8,
        ));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00                // fc00::/7 unique local (ULA)
        || (s[0] & 0xffc0) == 0xfe80                // fe80::/10 link-local
        || (s[0] & 0xffc0) == 0xfec0                // fec0::/10 site-local (deprecated)
        || (s[0] == 0x2001 && s[1] == 0x0db8)       // 2001:db8::/32 documentation
        || s[0] == 0x0100 && s[1..4] == [0, 0, 0]   // 100::/64 discard
        || (s[0] == 0x2001 && s[1] < 0x0200)        // 2001::/23 IETF protocol assignments
        || (s[0] & 0xe000) != 0x2000) // only 2000::/3 is global unicast today
}

#[cfg(test)]
mod tests {
    use super::is_public;

    fn ok(s: &str) -> bool {
        is_public(s.parse().unwrap())
    }

    #[test]
    fn public_addresses() {
        for a in [
            "23.227.38.65",
            "9.9.9.9",
            "2a00:1450:4007:80e::200e",
            "2606:4700::6810:84e5",
            "::ffff:23.227.38.65",
            "64:ff9b::1717:2641",
        ] {
            assert!(ok(a), "{a}");
        }
    }

    #[test]
    fn private_and_special_addresses() {
        for a in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "192.0.2.10",
            "198.18.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "fd00::1",
            "fdab:cdef::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:192.168.1.1",
            "::ffff:127.0.0.1",
            "::192.168.1.1",
            "64:ff9b::a00:1",
            "100::1",
        ] {
            assert!(!ok(a), "{a}");
        }
    }
}
