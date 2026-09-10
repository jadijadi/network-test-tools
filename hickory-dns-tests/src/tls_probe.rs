//! Raw TLS(+ECH) + HTTP/1.1 probe, modeled on rustls's `ech-client.rs` example but adapted to
//! report timing and an HTTP status/trace line instead of dumping the whole response.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use rustls::client::{EchConfig, EchGreaseConfig, EchMode};
use rustls::crypto::aws_lc_rs;
use rustls::crypto::aws_lc_rs::hpke::{ALL_SUPPORTED_SUITES, DH_KEM_X25519_HKDF_SHA256_AES_128};
use rustls::crypto::hpke::Hpke;
use rustls::pki_types::{EchConfigListBytes, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// What to connect to and (optionally) which ECH configuration to use.
pub struct ProbeParams {
    /// IP the TCP connection is opened to.
    pub connect_ip: IpAddr,
    pub port: u16,
    /// The (inner, real) hostname: used as the rustls `ServerName` and, with ECH enabled,
    /// encrypted inside the outer ClientHello. Without ECH this is sent in the clear as SNI.
    pub sni: String,
    /// `Host:` header for the HTTP request.
    pub http_host: String,
    /// Request path, without a leading '/'.
    pub path: String,
    pub timeout: Duration,
    /// `None` = plain TLS, no ECH. `Some` = attempt ECH with these configs (falling back to
    /// GREASE if the list is empty and `grease_if_missing` is set).
    pub ech: Option<EchRequest>,
}

pub struct EchRequest {
    pub config_lists: Vec<EchConfigListBytes<'static>>,
    pub grease_if_missing: bool,
}

#[derive(Debug)]
#[allow(dead_code)] // every field is surfaced via the Debug print in Report::run
pub struct ProbeResult {
    pub connect_ms: f64,
    /// TLS handshake plus the HTTP request/response round trip.
    pub handshake_ms: f64,
    pub total_ms: f64,
    pub ech_status: Option<String>,
    pub http_status: Option<u16>,
    /// The `sni=...` line from a Cloudflare `/cdn-cgi/trace` body, if the response looked like
    /// one.
    pub trace_sni: Option<String>,
    pub body_len: usize,
}

fn root_store() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    }
}

fn build_client_config(ech: Option<&EchRequest>) -> anyhow::Result<Arc<ClientConfig>> {
    let config = match ech {
        None => ClientConfig::builder()
            .with_root_certificates(root_store())
            .with_no_client_auth(),
        Some(req) => {
            let ech_mode = match req
                .config_lists
                .iter()
                .find_map(|list| EchConfig::new(list.clone(), ALL_SUPPORTED_SUITES).ok())
            {
                Some(cfg) => EchMode::from(cfg),
                None if req.grease_if_missing => {
                    let (public_key, _) =
                        DH_KEM_X25519_HKDF_SHA256_AES_128.generate_key_pair()?;
                    EchMode::from(EchGreaseConfig::new(
                        DH_KEM_X25519_HKDF_SHA256_AES_128,
                        public_key,
                    ))
                }
                None => return Err(anyhow!("no supported ECH config in the HTTPS record(s)")),
            };
            ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_ech(ech_mode)
                .map_err(|e| anyhow!("building ECH client config: {e}"))?
                .with_root_certificates(root_store())
                .with_no_client_auth()
        }
    };
    Ok(Arc::new(config))
}

fn probe_sync(params: ProbeParams) -> anyhow::Result<ProbeResult> {
    let overall_start = Instant::now();
    let config = build_client_config(params.ech.as_ref())?;

    let server_name: ServerName<'static> = params
        .sni
        .clone()
        .try_into()
        .context("invalid SNI hostname")?;

    let connect_start = Instant::now();
    let addr = SocketAddr::new(params.connect_ip, params.port);
    let mut sock = TcpStream::connect_timeout(&addr, params.timeout)
        .with_context(|| format!("TCP connect to {addr}"))?;
    sock.set_read_timeout(Some(params.timeout))?;
    sock.set_write_timeout(Some(params.timeout))?;
    let connect_ms = connect_start.elapsed().as_secs_f64() * 1000.0;

    let handshake_start = Instant::now();
    let conn = ClientConnection::new(config, server_name)
        .context("constructing TLS ClientConnection")?;
    let mut tls = StreamOwned::new(conn, &mut sock);

    let request = format!(
        "GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept-Encoding: identity\r\nUser-Agent: hickory-dns-tests/0.1\r\n\r\n",
        path = params.path.trim_start_matches('/'),
        host = params.http_host,
    );
    tls.write_all(request.as_bytes())
        .context("writing HTTP request over TLS")?;

    let mut response = Vec::new();
    // A read error after the handshake is common with `Connection: close` servers once the
    // peer shuts the connection down; treat it as "end of body" rather than a hard failure.
    let _ = tls.read_to_end(&mut response);
    // Includes the TLS handshake plus the HTTP request/response round trip.
    let handshake_ms = handshake_start.elapsed().as_secs_f64() * 1000.0;

    let ech_status = Some(format!("{:?}", tls.conn.ech_status()));

    let text = String::from_utf8_lossy(&response);
    let http_status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok());
    let trace_sni = text
        .lines()
        .find(|line| line.starts_with("sni="))
        .map(|line| line.to_string());
    let body_len = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.len())
        .unwrap_or(0);

    Ok(ProbeResult {
        connect_ms,
        handshake_ms,
        total_ms: overall_start.elapsed().as_secs_f64() * 1000.0,
        ech_status,
        http_status,
        trace_sni,
        body_len,
    })
}

pub async fn probe(params: ProbeParams) -> anyhow::Result<ProbeResult> {
    tokio::task::spawn_blocking(move || probe_sync(params))
        .await
        .context("probe task panicked")?
}
