//! Looks up a server's ECH ("Encrypted Client Hello") config via the HTTPS/SVCB DNS record,
//! following the pattern from rustls's own `ech-client.rs` example: the lookup should go over
//! DoH so the inner (real) hostname is never sent in cleartext ahead of the TLS handshake.

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
use hickory_resolver::proto::rr::{RData, RecordType};
use rustls::pki_types::EchConfigListBytes;

pub async fn lookup_ech_configs(
    resolver: &TokioResolver,
    domain: &str,
) -> anyhow::Result<Vec<EchConfigListBytes<'static>>> {
    let lookup = resolver.lookup(domain, RecordType::HTTPS).await?;

    let mut ech_config_lists = Vec::new();
    for r in lookup.answers() {
        let RData::HTTPS(svcb) = &r.data else {
            continue;
        };
        ech_config_lists.extend(svcb.svc_params.iter().find_map(|(k, v)| match (k, v) {
            (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(e)) => {
                Some(EchConfigListBytes::from(e.0.clone()))
            }
            _ => None,
        }));
    }
    Ok(ech_config_lists)
}
