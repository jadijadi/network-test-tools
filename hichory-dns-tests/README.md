# hichory-dns-tests

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

It runs through the same seven checks as the bash version, against three
public resolvers (Cloudflare, Google, Quad9) by default:

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

Every check runs under a hard timeout, so one hung connection can't eat
the whole run — the original bash script actually lost ~300 seconds to
exactly that, which is why this port keeps the same guardrail.

Everything is printed to the terminal as it happens and also written to a
log file, so you have something to hand to whoever you're debugging the
network issue with.

## Building it

You need a Rust toolchain — [rustup](https://rustup.rs/) is the easiest
way to get one if you don't have it already.

```sh
cd hichory-dns-tests
cargo build --release
```

The binary ends up at `target/release/hichory-dns-tests`.

## Running it

Just run it with no arguments to use the defaults:

```sh
./target/release/hichory-dns-tests
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
```

That `Accepted` / `sni=encrypted` pairing on the "true" run and
`NotOffered` / `sni=plaintext` on the "false" run is what a working,
unblocked ECH path looks like. If ECH is being stripped or blocked
somewhere on the path, you'd expect the "true" run to fail to negotiate
ECH, time out, or otherwise not match that pattern.

A log file is also written next to wherever you run the tool, named
`hichory-dns-tests-<timestamp>.log`.

### Options

```
hichory-dns-tests [OPTIONS]

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
      --log <LOG>                            Log file path [default: hichory-dns-tests-<timestamp>.log]
  -h, --help                                 Print help
```

For example, to point it at a different site and run more stall trials:

```sh
./target/release/hichory-dns-tests --doh-target example.com --repeat 5
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
- There's no packet capture (`tcpdump`) built in, unlike the bash version.
  If you need a pcap alongside a run, capture it separately.
