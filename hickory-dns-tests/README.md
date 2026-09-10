# hickory-dns-tests

A little command-line tool that checks how healthy DNS is on the network
it's run from: plain DNS, DNS-over-TLS, DNS-over-HTTPS, and Encrypted
Client Hello (ECH). It's a Rust rewrite of the `test_dns_doh_ech.sh` bash
script one directory up, built on [Hickory DNS](https://hickory-dns.org/)
and [rustls](https://github.com/rustls/rustls) instead of `dig`/`kdig`/`curl`.

The point is to answer questions like: *can this network resolve DNS at
all? Does it block DNS-over-HTTPS? Does ECH actually get negotiated, or is
something stripping it?* That's useful when you suspect a network is doing
DNS-based blocking or SNI-based filtering and you want evidence rather than
a guess.

## What it actually does

It runs through the same seven checks as the bash version, plus a set of
TXT-record checks the bash version doesn't have, against three public
resolvers (Cloudflare, Google, Quad9) by default:

1. **Plain DNS** — UDP and TCP queries against each resolver, so you can
   see if UDP/53 is being dropped while TCP/53 still works (a classic sign
   of DNS tampering).
2. **HTTPS/SVCB record lookup** — checks whether the target domain even
   publishes an ECH config in DNS, before we try to use it.
3. **DNS-over-TLS (DoT)** — proves the TLS handshake to port 853 succeeds
   and a query goes through.
4. **DNS-over-HTTPS (DoH)** — resolves a name via DoH, then actually opens
   an HTTPS connection to the IP it got back.
5. **Plain HTTPS baseline** — same fetch, but using whatever your OS's
   normal resolver returns, as a point of comparison.
6. **ECH ground truth** — connects to `cloudflare-ech.com` twice, once with
   ECH turned on and once off, and reads back its `/cdn-cgi/trace`
   endpoint, which tells you server-side whether it saw an encrypted or
   plaintext SNI. This is the "does ECH actually work here" test.
7. **ECH-on vs ECH-off stall comparison** — repeats a fetch against a
   larger page (`research.cloudflare.com`) several times with ECH on and
   off, interleaved. This one exists because a previous run of the bash
   script stalled for minutes on that page specifically — this checks
   whether hiding the SNI with ECH makes the stall go away (which would
   point at SNI-based DPI) or not (which would point at something else,
   like IP or volume-based blocking).
8. **TXT record filtering** — TXT is the record type that gets singled out
   most: it carries free-form text and it's what DNS tunnels ride on, so
   filters that leave A/AAAA alone will happily drop, empty out or rewrite
   TXT. A single TXT lookup proves nothing on its own, though, so every
   check here is a *comparison* — the same name asked over plain UDP/TCP
   and over that same resolver's DoT/DoH, which the network can't read.
   The encrypted answer is the ground truth; a difference between the two
   is the finding. It comes in three parts:
   - **8** — well-known, stable TXT records (`google.com`,
     `cloudflare.com` by default), each with an A-record control for the
     same name. If A comes back over plain UDP and TXT doesn't, that's
     flagged as `TXT-SPECIFIC` — nothing about a broken route or an
     unreachable resolver explains that, only a filter that treats TXT
     differently.
   - **8b** — a name with an unusually large TXT set (`microsoft.com`).
     The answer doesn't fit in a UDP packet, so it comes back truncated
     and has to be retried over TCP — a step some middleboxes drop on its
     own. The `udp` line is expected to say `TRUNCATED` here; the `tcp`
     line is the real test.
   - **8c** — a long random label queried as TXT, which is the shape DPI
     uses to fingerprint DNS tunnelling. Every answer should be a clean
     negative; the same name asked as A is the control. If the TXT query
     gets nothing while the A query is answered, long high-entropy labels
     are being filtered for TXT specifically.

Every check runs under a hard timeout, so one hung connection can't eat
the whole run — the original bash script actually lost ~300 seconds to
exactly that, which is why this port keeps the same guardrail.

Everything is printed to the terminal as it happens and also written to a
log file, so you have something to hand to whoever you're debugging the
network issue with.

## Building it

You need a Rust toolchain — [rustup](https://rustup.rs/) is the easiest
way to get one if you don't have it already.

### Static build (recommended for deploying to a server)

A normal `cargo build --release` dynamically links against the glibc on
your build machine. Copy that binary to a server running an older glibc
and it'll fail to even start:

```
./hickory-dns-tests: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found
```

To avoid any runtime dependency on the target machine's glibc version,
build a fully static binary against musl instead:

```sh
rustup target add x86_64-unknown-linux-musl
sudo apt-get install -y musl-tools   # provides musl-gcc, needed to build aws-lc-rs
cd hickory-dns-tests
cargo build --release --target x86_64-unknown-linux-musl
```

The binary ends up at
`target/x86_64-unknown-linux-musl/release/hickory-dns-tests`. Verify it
has no dynamic dependencies with `ldd` (it should print `statically
linked` or `not a dynamic executable`) — that binary can be copied to
any x86_64 Linux server and run as-is, regardless of its glibc version.

### Regular build

```sh
cd hickory-dns-tests
cargo build --release
```

The binary ends up at `target/release/hickory-dns-tests`, dynamically
linked against your build machine's glibc — fine for local use, but only
copy it to another machine if that machine's glibc is the same version
or newer.

## Running it

Just run it with no arguments to use the defaults:

```sh
./target/x86_64-unknown-linux-musl/release/hickory-dns-tests
```

or during development, straight through cargo:

```sh
cargo run
```

You'll see output like this as it works through each section:

```
=== 1. Plain DNS baseline (UDP/TCP) ===
MARKER[...]: START dns-udp-A-cloudflare
  OK   dns-udp-A-cloudflare (0.019s): "2 answer(s): 104.16.133.229 | 104.16.132.229"
...
=== 6. ECH ground truth (cdn-cgi/trace) ===
  OK   ech-true-groundtruth (0.146s): ... ech_status: Some("Accepted") ... trace_sni: Some("sni=encrypted")
  OK   ech-false-groundtruth (0.075s): ... ech_status: Some("NotOffered") ... trace_sni: Some("sni=plaintext")
...
=== 8. TXT record filtering ===
-- google.com --
  OK   txt-udp-cloudflare-google.com (0.013s): 17 record(s), 927 byte(s): MS=E4A68B9A... | v=spf1 include:_spf.google.com ~all | ...
  google.com via cloudflare/udp: OK: the plain path returned exactly the records the encrypted control did
  google.com via cloudflare/tcp: OK: the plain path returned exactly the records the encrypted control did
```

On a network that *is* filtering TXT, the same lines would instead read
`BLOCKED`, `TAMPERED`, or — the clearest of them —
`TXT-SPECIFIC: A records come back over plain UDP but TXT does not`.

That `Accepted` / `sni=encrypted` pairing on the "true" run and
`NotOffered` / `sni=plaintext` on the "false" run is what a working,
unblocked ECH path looks like. If ECH is being stripped or blocked
somewhere on the path, you'd expect the "true" run to fail to negotiate
ECH, time out, or otherwise not match that pattern.

A log file is also written next to wherever you run the tool, named
`hickory-dns-tests-<timestamp>.log`.

### Options

```
hickory-dns-tests [OPTIONS]

      --doh-target <DOH_TARGET>              Plain HTTPS/DoH target [default: cloudflare.com]
      --ech-target <ECH_TARGET>              ECH test domain (must publish an ECH config and
                                              serve /cdn-cgi/trace) [default: cloudflare-ech.com]
      --stall-target <STALL_TARGET>          Target for the ECH-on/off stall comparison
                                              [default: research.cloudflare.com]
      --ech-doh-provider <ECH_DOH_PROVIDER>  Which resolver (cloudflare/google/quad9) to use
                                              for the DoH lookups that fetch ECH configs
                                              [default: quad9]
      --timeout <TIMEOUT>                    Hard per-test timeout, in seconds [default: 8]
      --stall-timeout <STALL_TIMEOUT>        Timeout for the stall-comparison requests, in
                                              seconds [default: 12]
      --repeat <REPEAT>                      Trials per arm for the ECH-on/off stall comparison
                                              [default: 3]
      --txt-target <TXT_TARGET>              Names with well-known, stable TXT records, checked
                                              over every transport; repeat the flag or
                                              comma-separate to add your own
                                              [default: google.com cloudflare.com]
      --txt-large-target <TXT_LARGE_TARGET>  Name publishing an unusually large TXT set, to check
                                              whether truncation and the TCP retry survive
                                              [default: microsoft.com]
      --txt-random-base <TXT_RANDOM_BASE>    Base domain for the tunnel-shaped probe; a long
                                              random label is queried under it
                                              [default: example.com]
      --log <LOG>                            Log file path [default: hickory-dns-tests-<timestamp>.log]
  -h, --help                                 Print help
```

For example, to point it at a different site and run more stall trials:

```sh
./target/release/hickory-dns-tests --doh-target example.com --repeat 5
```

Or to check TXT filtering against domains you care about:

```sh
./target/release/hickory-dns-tests --txt-target example.org,_dmarc.example.org
```

The three resolvers it tests against (1.1.1.1, 8.8.8.8, 9.9.9.9) are
hardcoded in `src/providers.rs` for now, not exposed as flags — if you
need different resolvers, that's the file to edit.

## A couple of things worth knowing

- **IPv4 is preferred over IPv6.** If a lookup returns both, this tool
  connects over IPv4. That's a deliberate choice: on networks without a
  working IPv6 route, picking an IPv6 address first just means every
  connection hangs until the timeout instead of actually testing anything.
- **A "TIMEOUT" doesn't kill the underlying connection attempt.** Unlike
  the bash script, which could `SIGKILL` a hung `curl` subprocess, this
  tool can only stop *waiting* on a hung TCP/TLS operation — the socket
  itself still has its own read/write timeout, so it'll clean itself up
  shortly after, but you may see a "TIMEOUT" logged slightly before the
  underlying attempt has fully given up.
- **A `TRUNCATED` verdict is not a finding.** Each TXT probe pins one
  transport on purpose, so a UDP probe has no TCP connection to promote a
  truncated answer to. Any TXT set larger than a UDP packet will say
  `TRUNCATED` on the `udp` line even on a completely unfiltered network —
  read the `tcp` line for that name instead.
- There's no packet capture (`tcpdump`) built in, unlike the bash version.
  If you need a pcap alongside a run, capture it separately.
