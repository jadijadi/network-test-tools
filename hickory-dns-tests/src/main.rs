mod dns_checks;
mod ech;
mod providers;
mod report;
mod tls_probe;
mod txt_checks;

use std::net::{IpAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use hickory_resolver::config::NameServerConfig;
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

    /// Names with well-known, stable TXT records, checked over every transport. Repeat the
    /// flag or comma-separate to add your own.
    #[arg(
        long,
        value_delimiter = ',',
        default_values_t = [String::from("google.com"), String::from("cloudflare.com")]
    )]
    txt_target: Vec<String>,

    /// Name publishing an unusually large TXT set, used to check whether an answer too big
    /// for UDP survives truncation and the retry over TCP.
    #[arg(long, default_value = "microsoft.com")]
    txt_large_target: String,

    /// Base domain for the tunnel-shaped probe: a long random label is queried under it, so
    /// every answer should be a clean negative (NXDOMAIN, or NODATA if the zone answers for
    /// names under it).
    #[arg(long, default_value = "example.com")]
    txt_random_base: String,

    /// Log file path. Defaults to hickory-dns-tests-<timestamp>.log in the current directory.
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
        "hickory-dns-tests-{:04}{:02}{:02}-{:02}{:02}{:02}.log",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    ))
}

/// Asks every provider for one name's TXT records over all four transports, with an
/// A-record control for the same name, and logs a verdict per plain transport. Comparing a
/// provider against *itself* over an encrypted transport - rather than against another
/// provider - keeps the finding about the network path and not about the resolver.
async fn txt_across_transports(report: &mut Report, name: &str, timeout: Duration) {
    for p in PROVIDERS {
        let mut answers: Vec<(&'static str, Option<txt_checks::Answer>)> = Vec::new();
        for (transport, ns) in p.transports() {
            let answer = report
                .run(
                    &format!("txt-{transport}-{}-{name}", p.name),
                    timeout,
                    txt_checks::query(ns, name, RecordType::TXT, timeout),
                )
                .await;
            answers.push((transport, answer));
        }

        let a_control = report
            .run(
                &format!("txt-control-a-udp-{}-{name}", p.name),
                timeout,
                txt_checks::query(NameServerConfig::udp(p.ip), name, RecordType::A, timeout),
            )
            .await;

        let answer = |want: &str| {
            answers
                .iter()
                .find(|(transport, _)| *transport == want)
                .and_then(|(_, answer)| answer.as_ref())
        };
        // DoH is the ground truth; DoT is the fallback for when DoH itself is blocked.
        let control = answer("doh").or_else(|| answer("dot"));
        for plain in ["udp", "tcp"] {
            report.line(&format!(
                "  {name} via {}/{plain}: {}",
                p.name,
                txt_checks::verdict(answer(plain), control)
            ));
        }
        if let Some(finding) = txt_checks::txt_specific(a_control.as_ref(), answer("udp")) {
            report.line(&format!("  {name} via {}: {finding}", p.name));
        }
    }
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

    // ---- 8. TXT records: dropped, emptied or rewritten on the plain-DNS path? ----
    report.line("\n=== 8. TXT record filtering ===");
    report.line(
        "  TXT carries free-form text and is what DNS tunnels ride on, so filters single it\n\
        \x20 out. Each name is asked over plain UDP/TCP and over the same resolver's DoT/DoH,\n\
        \x20 which the network cannot read; the encrypted answer is the ground truth.",
    );
    for name in &args.txt_target {
        report.line(&format!("\n-- {name} --"));
        txt_across_transports(&mut report, name, timeout).await;
    }

    report.line("\n=== 8b. Large TXT answers (truncation and TCP fallback) ===");
    report.line(&format!(
        "  {} publishes an unusually large TXT set, so the UDP answer is expected to come\n\
        \x20 back truncated: the tcp line is the real test, because the retry over TCP is a\n\
        \x20 step some middleboxes drop on its own.",
        args.txt_large_target
    ));
    txt_across_transports(&mut report, &args.txt_large_target, timeout).await;

    report.line("\n=== 8c. Tunnel-shaped TXT queries ===");
    report.line(&format!(
        "  A long random label under {}, asked as TXT: the shape DPI fingerprints to spot DNS\n\
        \x20 tunnelling. Every answer should be a clean negative, and the same name asked as A\n\
        \x20 is the control.",
        args.txt_random_base
    ));
    for p in PROVIDERS {
        // A fresh label per provider, so no probe can be answered from a negative cache
        // entry left behind by the previous one.
        let name = format!("{}.{}", txt_checks::random_label(), args.txt_random_base);
        let txt_plain = report
            .run(
                &format!("txt-tunnel-udp-{}", p.name),
                timeout,
                txt_checks::query(NameServerConfig::udp(p.ip), &name, RecordType::TXT, timeout),
            )
            .await;
        let a_plain = report
            .run(
                &format!("txt-tunnel-control-a-udp-{}", p.name),
                timeout,
                txt_checks::query(NameServerConfig::udp(p.ip), &name, RecordType::A, timeout),
            )
            .await;
        let txt_control = report
            .run(
                &format!("txt-tunnel-doh-{}", p.name),
                timeout,
                txt_checks::query(
                    NameServerConfig::https(
                        p.ip,
                        Arc::from(p.tls_name),
                        Some(Arc::from(p.doh_path)),
                    ),
                    &name,
                    RecordType::TXT,
                    timeout,
                ),
            )
            .await;
        report.line(&format!(
            "  {}: {}",
            p.name,
            txt_checks::tunnel_verdict(txt_plain.as_ref(), a_plain.as_ref(), txt_control.as_ref())
        ));
    }

    report.mark("All tests complete");
    report.line(&format!("Log: {}", report.path.display()));
    Ok(())
}
