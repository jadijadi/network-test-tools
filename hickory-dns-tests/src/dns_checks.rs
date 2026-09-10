use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;

fn opts(timeout: Duration) -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    opts.timeout = timeout;
    opts.attempts = 1;
    opts
}

fn summarize(answers: &[hickory_resolver::proto::rr::Record]) -> String {
    if answers.is_empty() {
        return "0 answers".to_string();
    }
    let rdata: Vec<String> = answers.iter().map(|r| r.data.to_string()).collect();
    format!("{} answer(s): {}", rdata.len(), rdata.join(" | "))
}

async fn lookup_with(
    ns: NameServerConfig,
    name: &str,
    rtype: RecordType,
    timeout: Duration,
) -> anyhow::Result<String> {
    let config = ResolverConfig::from_name_servers(vec![ns]);
    let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts(timeout))
        .build()?;
    let lookup = resolver.lookup(name, rtype).await?;
    Ok(summarize(lookup.answers()))
}

/// Plain DNS over UDP.
pub async fn udp(
    ip: IpAddr,
    name: &str,
    rtype: RecordType,
    timeout: Duration,
) -> anyhow::Result<String> {
    lookup_with(NameServerConfig::udp(ip), name, rtype, timeout).await
}

/// Plain DNS over TCP.
pub async fn tcp(
    ip: IpAddr,
    name: &str,
    rtype: RecordType,
    timeout: Duration,
) -> anyhow::Result<String> {
    lookup_with(NameServerConfig::tcp(ip), name, rtype, timeout).await
}

/// DNS-over-TLS (DoT): also proves the TLS handshake to the resolver succeeds.
pub async fn dot(
    ip: IpAddr,
    tls_name: &str,
    name: &str,
    rtype: RecordType,
    timeout: Duration,
) -> anyhow::Result<String> {
    lookup_with(
        NameServerConfig::tls(ip, Arc::from(tls_name)),
        name,
        rtype,
        timeout,
    )
    .await
}

/// DNS-over-HTTPS (DoH) record lookup; used both to prove DoH resolution works and, with
/// `RecordType::HTTPS`, to fetch SVCB/HTTPS records (which may carry an ECH config).
pub async fn doh(
    ip: IpAddr,
    tls_name: &str,
    doh_path: &str,
    name: &str,
    rtype: RecordType,
    timeout: Duration,
) -> anyhow::Result<String> {
    lookup_with(
        NameServerConfig::https(ip, Arc::from(tls_name), Some(Arc::from(doh_path))),
        name,
        rtype,
        timeout,
    )
    .await
}

/// Build a resolver that talks DoH to `ip`/`tls_name`, for use by callers (e.g. the ECH lookup
/// and IP-resolution-before-connect steps) that need the resolver itself rather than a one-shot
/// summary string.
pub fn doh_resolver(
    ip: IpAddr,
    tls_name: &str,
    doh_path: &str,
    timeout: Duration,
) -> anyhow::Result<hickory_resolver::TokioResolver> {
    let ns = NameServerConfig::https(ip, Arc::from(tls_name), Some(Arc::from(doh_path)));
    let config = ResolverConfig::from_name_servers(vec![ns]);
    let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts(timeout))
        .build()?;
    Ok(resolver)
}
