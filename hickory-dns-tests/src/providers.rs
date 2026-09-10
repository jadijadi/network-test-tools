use std::net::IpAddr;
use std::sync::Arc;

use hickory_resolver::config::NameServerConfig;

/// A DNS resolver we probe against: plain DNS, DoT and DoH all use the same IP.
#[derive(Clone, Copy, Debug)]
pub struct Provider {
    pub name: &'static str,
    pub ip: IpAddr,
    /// TLS server name / certificate name used for DoT and DoH.
    pub tls_name: &'static str,
    /// DoH query path (almost always "/dns-query").
    pub doh_path: &'static str,
}

pub const PROVIDERS: &[Provider] = &[
    Provider {
        name: "cloudflare",
        ip: IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
        tls_name: "cloudflare-dns.com",
        doh_path: "/dns-query",
    },
    Provider {
        name: "google",
        ip: IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
        tls_name: "dns.google",
        doh_path: "/dns-query",
    },
    Provider {
        name: "quad9",
        ip: IpAddr::V4(std::net::Ipv4Addr::new(9, 9, 9, 9)),
        tls_name: "dns.quad9.net",
        doh_path: "/dns-query",
    },
];

impl Provider {
    /// Every transport this provider answers on, ordered so the two an on-path filter can
    /// read and rewrite come first and the two it cannot come last. Checks that ask the
    /// same question over all four treat the encrypted answers as ground truth for the
    /// plain ones.
    pub fn transports(&self) -> [(&'static str, NameServerConfig); 4] {
        [
            ("udp", NameServerConfig::udp(self.ip)),
            ("tcp", NameServerConfig::tcp(self.ip)),
            (
                "dot",
                NameServerConfig::tls(self.ip, Arc::from(self.tls_name)),
            ),
            (
                "doh",
                NameServerConfig::https(
                    self.ip,
                    Arc::from(self.tls_name),
                    Some(Arc::from(self.doh_path)),
                ),
            ),
        ]
    }
}
