//! TXT-record reachability and integrity checks.
//!
//! TXT gets singled out by national filters more than any other record type: it is the
//! record DNS tunnels ride on, and it is free-form text, so middleboxes drop it, empty it
//! out or rewrite it while leaving A/AAAA answers alone. A single TXT lookup therefore
//! proves nothing on its own. Every check here is a comparison instead - the same question
//! asked over a path the network can read (plain UDP/TCP) and over one it cannot (DoT/DoH),
//! plus an A-record control for the same name - so the *difference* between the answers is
//! the finding.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_resolver::config::NameServerConfig;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::rr::{RData, RecordType};

use crate::dns_checks;

/// What a resolver said, classified so that "the server answered, and the answer was no"
/// is distinguishable from "nothing came back at all". Censorship shows up in that gap:
/// a dropped query times out, while a filtered one usually gets a prompt, well-formed
/// NXDOMAIN, SERVFAIL or empty NOERROR.
#[derive(Clone, PartialEq, Eq)]
pub enum Answer {
    /// Records came back. For TXT, each entry is one record with its character-strings
    /// concatenated (how SPF and friends are meant to be read); the set is sorted so two
    /// resolvers that answer the same thing in a different order still compare equal.
    Records { rdata: Vec<String>, bytes: usize },
    /// The server answered that there is nothing here.
    NoRecords { rcode: String },
    /// The server answered with a failure code - which is also what a resolver that has
    /// been told not to answer this question returns.
    Rcode { rcode: String },
    /// The answer did not fit in a UDP packet and came back with the truncation bit set.
    /// This is normal for a large TXT set and is not itself a sign of interference: what
    /// matters is whether the retry over TCP - probed separately - gets through.
    Truncated,
}

impl Answer {
    /// The records, if any came back. `None` covers every shape of "no data", which is
    /// what the comparisons below key on.
    pub fn records(&self) -> Option<&[String]> {
        match self {
            Self::Records { rdata, .. } => Some(rdata),
            _ => None,
        }
    }
}

impl fmt::Debug for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Records { rdata, bytes } => write!(
                f,
                "{} record(s), {bytes} byte(s): {}",
                rdata.len(),
                rdata.join(" | ")
            ),
            Self::NoRecords { rcode } => write!(f, "no records ({rcode})"),
            Self::Rcode { rcode } => write!(f, "error response ({rcode})"),
            Self::Truncated => write!(f, "truncated, too big for UDP"),
        }
    }
}

/// Ask `ns` for `name`/`rtype` and classify the reply. Unlike [`dns_checks`], a negative
/// answer is `Ok`, not `Err`: for these checks "the resolver said NXDOMAIN" is a result
/// worth comparing, and only a timeout or transport failure is an error.
pub async fn query(
    ns: NameServerConfig,
    name: &str,
    rtype: RecordType,
    timeout: Duration,
) -> anyhow::Result<Answer> {
    let resolver = dns_checks::resolver(ns, timeout)?;
    let lookup = match resolver.lookup(name, rtype).await {
        Ok(lookup) => lookup,
        Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => {
            return Ok(Answer::NoRecords {
                rcode: no_records.response_code.to_string(),
            });
        }
        Err(NetError::Dns(DnsError::ResponseCode(rcode))) => {
            return Ok(Answer::Rcode {
                rcode: rcode.to_string(),
            });
        }
        // Only reachable because each probe pins one transport, so there is no TCP
        // connection for this resolver to promote the query to.
        Err(NetError::Truncated) => return Ok(Answer::Truncated),
        Err(err) => return Err(err.into()),
    };

    let mut rdata = Vec::new();
    let mut bytes = 0;
    for record in lookup.answers() {
        match &record.data {
            // Join the character-strings: a long TXT value is split into 255-byte chunks
            // on the wire, and only the joined form is comparable between resolvers.
            RData::TXT(txt) => {
                let mut joined = String::new();
                for chunk in txt.txt_data.iter() {
                    bytes += chunk.len();
                    joined.push_str(&String::from_utf8_lossy(chunk));
                }
                rdata.push(joined);
            }
            other if other.record_type() == rtype => {
                let rendered = other.to_string();
                bytes += rendered.len();
                rdata.push(rendered);
            }
            // CNAMEs and other chain records: not the answer we asked about.
            _ => {}
        }
    }
    rdata.sort();

    if rdata.is_empty() {
        // A NOERROR that carries no matching record is one of the shapes TXT filtering
        // takes, so it is reported rather than treated as an error.
        return Ok(Answer::NoRecords {
            rcode: "NOERROR, 0 answers".to_string(),
        });
    }
    Ok(Answer::Records { rdata, bytes })
}

/// Compare what the network could read (`plain`) against what it could not (`control`),
/// for the same name and record type. `None` means the probe got nothing back at all.
pub fn verdict(plain: Option<&Answer>, control: Option<&Answer>) -> String {
    let Some(control) = control else {
        return "INCONCLUSIVE: the encrypted control failed too, so there is nothing to \
                compare against"
            .to_string();
    };
    if let Some(Answer::Truncated) = plain {
        return "TRUNCATED: too big for a UDP packet, which is normal for a large TXT set - \
                the tcp line for this name is what says whether the retry survives the network"
            .to_string();
    }
    match (plain, control.records()) {
        (None, Some(_)) => "BLOCKED: no answer at all over the plain path, while the encrypted \
                            control returned records"
            .to_string(),
        (None, None) => "inconclusive: the plain path got no answer, but the encrypted control \
                         found no records either"
            .to_string(),
        (Some(plain), Some(expected)) => match plain.records() {
            Some(got) if got == expected => {
                "OK: the plain path returned exactly the records the encrypted control did"
                    .to_string()
            }
            Some(_) => format!(
                "TAMPERED: the plain path returned different records than the encrypted \
                 control - plain said {plain:?}"
            ),
            None => format!(
                "BLOCKED: the encrypted control returned {} record(s), the plain path said \
                 {plain:?}",
                expected.len()
            ),
        },
        (Some(plain), None) => match plain.records() {
            Some(_) => "unexpected: the plain path returned records the encrypted control did \
                        not - the name may have just changed, or this resolver is answering \
                        from a stale cache"
                .to_string(),
            None => "consistent: neither path found records for this name".to_string(),
        },
    }
}

/// The sharpest signal available: A records for a name arrive over the plain path but TXT
/// records for that same name do not. Nothing about a broken route or an unreachable
/// resolver explains that - only a filter that treats TXT differently. Returns `None` when
/// the finding does not hold.
pub fn txt_specific(a_plain: Option<&Answer>, txt_plain: Option<&Answer>) -> Option<String> {
    a_plain?.records()?;
    let txt = match txt_plain {
        Some(txt) if txt.records().is_some() => return None,
        // An answer too big for UDP is a size problem, not a filter, so it is judged on the
        // TCP line instead of raised here.
        Some(Answer::Truncated) => return None,
        Some(txt) => format!("{txt:?}"),
        None => "no answer at all".to_string(),
    };
    Some(format!(
        "TXT-SPECIFIC: A records come back over plain UDP but TXT does not (TXT: {txt})"
    ))
}

/// Verdict for the tunnel-shaped probe, where every answer should be a clean negative -
/// NXDOMAIN, or NODATA if the base domain answers for names under it. The question here is
/// not which records came back but whether the query was answered at all, so it needs its
/// own reading of the three results.
pub fn tunnel_verdict(
    txt_plain: Option<&Answer>,
    a_plain: Option<&Answer>,
    txt_control: Option<&Answer>,
) -> String {
    if txt_control.is_none() {
        return "INCONCLUSIVE: the encrypted control got no answer either, so this says nothing \
                about TXT"
            .to_string();
    }
    match (txt_plain, a_plain) {
        (Some(answer), _) => format!(
            "OK: the tunnel-shaped TXT query was answered normally over plain UDP ({answer:?})"
        ),
        (None, Some(_)) => "DROPPED: the tunnel-shaped TXT query got no answer over plain UDP, \
                            while the identical name queried as A did - long high-entropy \
                            labels are being filtered for TXT specifically"
            .to_string(),
        (None, None) => "inconclusive: neither TXT nor A was answered for the random name, so \
                         the plain path to this resolver is down rather than TXT being singled \
                         out"
        .to_string(),
    }
}

/// A long, high-entropy label - the shape a DNS tunnel's queries take, and the shape DPI
/// fingerprints to spot one. Seeded from the clock plus a counter so repeat probes never
/// reuse a name a resolver has already cached a negative answer for.
pub fn random_label() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    const GOLDEN: u64 = 0x9e37_79b9_7f4a_7c15;

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut state = nanos ^ COUNTER.fetch_add(GOLDEN, Ordering::Relaxed);

    // splitmix64, so consecutive seeds an instant apart still produce unrelated labels.
    let mut label = String::with_capacity(32);
    while label.len() < 32 {
        state = state.wrapping_add(GOLDEN);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        label.push_str(&format!("{z:016x}"));
    }
    label.truncate(32);
    label
}
