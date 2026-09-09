mod dns_checks;
mod ech;
mod providers;
mod report;
mod tls_probe;

use std::net::{IpAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use hickory_resolver::proto::rr::RecordType;

use providers::PROVIDERS;
use report::Report;
use tls_probe::{EchRequest, ProbeParams};

/// DNS / DoT / DoH / ECH network status probe (Hickory DNS + rustls port of
/// `test_dns_doh_ech.sh`).
#[derive(Parser)]
struct Args {
    /// Plain HTTPS/DoH target.
    #[arg(long, default_value = "cloudflare.com")]
    doh_target: String,

    /// Cloudflare's public ECH test domain; its /cdn-cgi/trace reports
    /// sni=encrypted|plaintext server-side.
    #[arg(long, default_value = "cloudflare-ech.com")]
    ech_target: String,

    /// Large page on a shared Cloudflare ECH config, used for the ECH-on vs ECH-off stall
    /// comparison.
    #[arg(long, default_value = "research.cloudflare.com")]
    stall_target: String,

    /// Which built-in provider (cloudflare/google/quad9) to use for the DoH lookups that fetch
    /// ECH configs.
    #[arg(long, default_value = "quad9")]
    ech_doh_provider: String,

    /// Hard per-test timeout, in seconds.
    #[arg(long, default_value_t = 8)]
    timeout: u64,

    /// Timeout for the stall-comparison requests, in seconds.
    #[arg(long, default_value_t = 12)]
    stall_timeout: u64,

    /// Trials per arm for the ECH-on vs ECH-off stall comparison.
    #[arg(long, default_value_t = 3)]
    repeat: u32,

    /// Log file path. Defaults to hichory-dns-tests-<timestamp>.log in the current directory.
    #[arg(long)]
    log: Option<PathBuf>,
}

/// Prefer an IPv4 address: many networks (including this tool's own test sandbox) have no
/// IPv6 route, which would otherwise make every connect hang until the timeout.
fn prefer_v4(ips: impl Iterator<Item = IpAddr>) -> Option<IpAddr> {
    let ips: Vec<IpAddr> = ips.collect();
    ips.iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| ips.first())
        .copied()
}

fn default_log_path() -> PathBuf {
    let now = time::OffsetDateTime::now_utc();
    PathBuf::from(format!(
        "hichory-dns-tests-{:04}{:02}{:02}-{:02}{:02}{:02}.log",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    ))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let timeout = Duration::from_secs(args.timeout);
    let stall_timeout = Duration::from_secs(args.stall_timeout);

    let log_path = args.log.clone().unwrap_or_else(default_log_path);
    let mut report = Report::new(log_path)?;
    report.line(&format!("Log: {}", report.path.display()));

    let ech_doh_provider = PROVIDERS
        .iter()
        .find(|p| p.name == args.ech_doh_provider)
        .ok_or_else(|| anyhow::anyhow!("unknown provider '{}'", args.ech_doh_provider))?;

    // ---- 1. Plain DNS baseline: UDP + TCP, multiple resolvers ----
    report.line("\n=== 1. Plain DNS baseline (UDP/TCP) ===");
    for p in PROVIDERS {
        report
            .run(
                &format!("dns-udp-A-{}", p.name),
                timeout,
                dns_checks::udp(p.ip, &args.doh_target, RecordType::A, timeout),
            )
            .await;
        report
            .run(
                &format!("dns-udp-AAAA-{}", p.name),
                timeout,
                dns_checks::udp(p.ip, &args.doh_target, RecordType::AAAA, timeout),
            )
            .await;
        report
            .run(
                &format!("dns-tcp-A-{}", p.name),
                timeout,
                dns_checks::tcp(p.ip, &args.doh_target, RecordType::A, timeout),
            )
            .await;
    }

    // ---- 2. HTTPS/SVCB record lookup - shows whether an ECH config is even published ----
    report.line("\n=== 2. HTTPS/SVCB record lookup (ECH config publication) ===");
    for p in PROVIDERS {
        report
            .run(
                &format!("dns-https-record-{}", p.name),
                timeout,
                dns_checks::udp(p.ip, &args.ech_target, RecordType::HTTPS, timeout),
            )
            .await;
    }

    // ---- 3. DoT reachability ----
    report.line("\n=== 3. DNS-over-TLS (DoT) reachability ===");
    for p in PROVIDERS {
        report
            .run(
                &format!("dot-query-{}", p.name),
                timeout,
                dns_checks::dot(p.ip, p.tls_name, &args.doh_target, RecordType::A, timeout),
            )
            .await;
    }

    // ---- 4. DoH resolution + fetch, per provider ----
    report.line("\n=== 4. DNS-over-HTTPS (DoH) resolution + fetch ===");
    for p in PROVIDERS {
        report
            .run(
                &format!("doh-record-{}", p.name),
                timeout,
                dns_checks::doh(
                    p.ip,
                    p.tls_name,
                    p.doh_path,
                    &args.doh_target,
                    RecordType::A,
                    timeout,
                ),
            )
            .await;

        let doh_resolver = dns_checks::doh_resolver(p.ip, p.tls_name, p.doh_path, timeout)?;
        let doh_target = args.doh_target.clone();
        report
            .run(
                &format!("doh-fetch-{}", p.name),
                timeout,
                async {
                    let ips = doh_resolver.lookup_ip(doh_target.as_str()).await?;
                    let ip = prefer_v4(ips.iter())
                        .ok_or_else(|| anyhow::anyhow!("no addresses returned"))?;
                    tls_probe::probe(ProbeParams {
                        connect_ip: ip,
                        port: 443,
                        sni: doh_target.clone(),
                        http_host: doh_target.clone(),
                        path: String::new(),
                        timeout,
                        ech: None,
                    })
                    .await
                },
            )
            .await;
    }

    // ---- 5. Baseline HTTPS, no DoH/no ECH, system resolver only ----
    report.line("\n=== 5. Baseline HTTPS via system resolver ===");
    {
        let doh_target = args.doh_target.clone();
        report
            .run("https-baseline", timeout, async {
                let host_for_lookup = doh_target.clone();
                let ip = tokio::task::spawn_blocking(move || {
                    let addrs = format!("{host_for_lookup}:443")
                        .to_socket_addrs()
                        .map(|it| it.map(|addr| addr.ip()))
                        .map_err(|e| anyhow::anyhow!("system resolver: {e}"))?;
                    prefer_v4(addrs)
                        .ok_or_else(|| anyhow::anyhow!("system resolver returned no address"))
                })
                .await??;
                tls_probe::probe(ProbeParams {
                    connect_ip: ip,
                    port: 443,
                    sni: doh_target.clone(),
                    http_host: doh_target.clone(),
                    path: String::new(),
                    timeout,
                    ech: None,
                })
                .await
            })
            .await;
    }

    // ---- 6. ECH ground truth via cloudflare-ech.com trace endpoint ----
    report.line("\n=== 6. ECH ground truth (cdn-cgi/trace) ===");
    let ech_doh_resolver = dns_checks::doh_resolver(
        ech_doh_provider.ip,
        ech_doh_provider.tls_name,
        ech_doh_provider.doh_path,
        timeout,
    )?;
    let ech_config_lists = report
        .run(
            "ech-config-lookup",
            timeout,
            ech::lookup_ech_configs(&ech_doh_resolver, &args.ech_target),
        )
        .await
        .unwrap_or_default();
    report.line(&format!(
        "  found {} ECH config list(s) for {}",
        ech_config_lists.len(),
        args.ech_target
    ));

    let ech_target_ip = report
        .run("ech-target-resolve", timeout, async {
            let ips = ech_doh_resolver.lookup_ip(args.ech_target.as_str()).await?;
            prefer_v4(ips.iter()).ok_or_else(|| anyhow::anyhow!("no addresses returned"))
        })
        .await;

    if let Some(ip) = ech_target_ip {
        let target = args.ech_target.clone();
        report
            .run(
                "ech-true-groundtruth",
                timeout,
                tls_probe::probe(ProbeParams {
                    connect_ip: ip,
                    port: 443,
                    sni: target.clone(),
                    http_host: target.clone(),
                    path: "cdn-cgi/trace".to_string(),
                    timeout,
                    ech: Some(EchRequest {
                        config_lists: ech_config_lists.clone(),
                        grease_if_missing: true,
                    }),
                }),
            )
            .await;

        report
            .run(
                "ech-false-groundtruth",
                timeout,
                tls_probe::probe(ProbeParams {
                    connect_ip: ip,
                    port: 443,
                    sni: target.clone(),
                    http_host: target.clone(),
                    path: "cdn-cgi/trace".to_string(),
                    timeout,
                    ech: None,
                }),
            )
            .await;
    } else {
        report.line("  skipping ECH ground truth probes: could not resolve ECH target");
    }

    // ---- 7. ECH-on vs ECH-off against the target that previously stalled mid-transfer ----
    report.line("\n=== 7. ECH-on vs ECH-off stall comparison ===");
    let stall_ech_configs = report
        .run(
            "stall-ech-config-lookup",
            timeout,
            ech::lookup_ech_configs(&ech_doh_resolver, &args.stall_target),
        )
        .await
        .unwrap_or_default();
    let stall_ip = report
        .run("stall-target-resolve", timeout, async {
            let ips = ech_doh_resolver
                .lookup_ip(args.stall_target.as_str())
                .await?;
            prefer_v4(ips.iter()).ok_or_else(|| anyhow::anyhow!("no addresses returned"))
        })
        .await;

    if let Some(ip) = stall_ip {
        for i in 1..=args.repeat {
            let target = args.stall_target.clone();
            report
                .run(
                    &format!("ech-true-stall-{i}"),
                    stall_timeout,
                    tls_probe::probe(ProbeParams {
                        connect_ip: ip,
                        port: 443,
                        sni: target.clone(),
                        http_host: target.clone(),
                        path: String::new(),
                        timeout: stall_timeout,
                        ech: Some(EchRequest {
                            config_lists: stall_ech_configs.clone(),
                            grease_if_missing: true,
                        }),
                    }),
                )
                .await;

            let target = args.stall_target.clone();
            report
                .run(
                    &format!("ech-false-stall-{i}"),
                    stall_timeout,
                    tls_probe::probe(ProbeParams {
                        connect_ip: ip,
                        port: 443,
                        sni: target.clone(),
                        http_host: target.clone(),
                        path: String::new(),
                        timeout: stall_timeout,
                        ech: None,
                    }),
                )
                .await;
        }
    } else {
        report.line("  skipping stall comparison: could not resolve stall target");
    }

    report.mark("All tests complete");
    report.line(&format!("Log: {}", report.path.display()));
    Ok(())
}
