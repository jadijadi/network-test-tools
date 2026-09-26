# network-test-tools

Small command-line tools for checking what a network actually lets through.

| Tool | What it checks |
|------|----------------|
| [`hickory-dns-tests/`](hickory-dns-tests/) | Plain DNS, DoT, DoH and ECH. Rust. |
| [`test_dns_doh_ech.sh`](test_dns_doh_ech.sh) | The original bash version of the DNS checks. |
| [`l2-connectivity/`](l2-connectivity/) | Layer 2 reachability between machines using raw Ethernet frames: RTT, loss and MTU matrix. Go, Linux, needs root. |

## Build

```sh
# DNS tests (Rust)
cd hickory-dns-tests && cargo build --release

# L2 connectivity (Go)
cd l2-connectivity && CGO_ENABLED=0 go build -o l2-connectivity .
```

GitLab CI builds static Linux binaries of both on every push.

## Quick start

```sh
./hickory-dns-tests/target/release/hickory-dns-tests

# on each machine on the same L2 segment:
sudo ./l2-connectivity/l2-connectivity agent -i wlan0
```

See [hickory-dns-tests/README.md](hickory-dns-tests/README.md) and
[l2-connectivity/NOTES.md](l2-connectivity/NOTES.md) for details.

## License

MIT, see [LICENSE](LICENSE).
