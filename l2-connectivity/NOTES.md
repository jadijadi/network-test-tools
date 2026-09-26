# l2-connectivity — working notes

Checks layer 2 reachability between machines using raw Ethernet frames only
(no IP). It's the first building block for an L2 mesh overlay: every node finds
its neighbours and measures RTT, loss and path MTU to each one.

## Status (2026-09-26)

- First draft, written on macOS.
- Unit tests pass (`go test ./...`, runs on any OS). The Linux static build
  compiles (`GOOS=linux CGO_ENABLED=0`).
- **Not yet run on real Linux / real network.** The raw socket code
  (`packet.Listen`, read/write loops) has only been compiled, never executed.
  Start there.

## Build and run

```sh
cd l2-connectivity
go test ./...
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o l2-connectivity .   # static binary

# on every node (root or CAP_NET_RAW):
sudo ./l2-connectivity agent -i wlan0
# one-shot check, prints the final matrix and sets exit status:
sudo ./l2-connectivity agent -i wlan0 -duration 30s
# passive: which MACs' frames reach us
sudo ./l2-connectivity sniff -i wlan0
```

The binary needs Go ≥ 1.26 (because of the `x/sys` / `x/net` versions). With an
older Go, `GOTOOLCHAIN=auto` downloads the right one. CI (`build-l2-connectivity`
in `.gitlab-ci.yml`) builds a static linux/amd64 binary as an artifact.

Instead of root: `sudo setcap cap_net_raw+ep ./l2-connectivity`.

## Testing without real hardware (do this first on Linux)

Two network namespaces joined by a veth pair behave like two machines on a
wire:

```sh
sudo ip netns add a; sudo ip netns add b
sudo ip link add va type veth peer name vb
sudo ip link set va netns a; sudo ip link set vb netns b
sudo ip -n a link set va up; sudo ip -n b link set vb up
# terminal 1 / 2:
sudo ip netns exec a ./l2-connectivity agent -i va -name A
sudo ip netns exec b ./l2-connectivity agent -i vb -name B
```

For more than two nodes, put a bridge in a third namespace and attach veths to
it. Useful knobs to check that the numbers move:

```sh
sudo ip netns exec a tc qdisc add dev va root netem delay 20ms loss 10%   # RTT/loss
sudo ip -n a link set va mtu 1400; sudo ip -n b link set vb mtu 1400        # MTU
```

For a Wi-Fi mesh without radios: `modprobe mac80211_hwsim radios=3`, then set
up 802.11s on the simulated interfaces (`iw dev wlanX set type mp`,
`iw dev wlanX mesh join <id>`).

## Design

### Two modes

- **`agent`** (active, the main tool): every node runs it; there is no separate
  client and server. It broadcasts HELLOs, unicast-probes every peer it knows,
  answers probes from others, and prints a matrix.
- **`sniff`** (passive): opens `ETH_P_ALL` and lists every source MAC seen, with
  counts by destination kind (bcast/mcast/to me/to others), EtherTypes and the
  IPs from ARP. A frame whose source MAC is X proves X is on our segment, since
  a router would have rewritten it. It only proves one direction, and quiet
  hosts are invisible.

### Wire protocol (`proto.go`)

The payload goes straight into an Ethernet frame with EtherType `0x88B5` (IEEE
local experimental; change it with `-ethertype`, and all nodes must match).
Header: magic `L2CT`, version, type, length, seq. The explicit length field
exists because frames under 60 bytes get padded.

| type  | sent to   | purpose |
|-------|-----------|---------|
| HELLO | broadcast | name, interface MTU, and **this node's view of every peer** (RTT, losses, MTU, flags). Sharing views is how each node can draw the full N×N matrix. About 87 entries fit in 1500 bytes. |
| PROBE | unicast   | `ping` kind (small, every `-interval`) → RTT and loss; `mtu` kind (sizes 576…iface MTU, every `-mtu-interval`) → path MTU |
| REPLY | unicast   | echoes the probe's seq plus the size it received, so a truncated big probe doesn't count |

### Where the numbers come from

- **RTT / unicast loss (`u`)**: ping probes, round trip, over the last
  `-window` (100) probes. No reply within `-timeout` counts as lost.
- **Broadcast loss (`b`)**: gaps in the peer's HELLO sequence numbers. On
  Wi-Fi, broadcast goes out at the basic rate with no ACK or retry, so
  `b` > `u` is expected there.
- **Path MTU**: the largest probe size acknowledged in the last ~3 MTU rounds.
  The upper bound is our own interface MTU. It measures A→B only; the small
  reply only confirms the probe arrived.
- **Peer discovery**: HELLOs, incoming probes, `-peer MAC` (static, for when
  broadcast is filtered), and MACs that other nodes report as alive. So if
  C's broadcasts don't reach A but B sees C, A still probes C by unicast.

### Reading the matrix

Row = observer, column = target. Row 0 is measured locally; other rows come
from those nodes' HELLOs (`~` = that report is stale). Cell:
`avgRTT u<unicast loss> b<target's HELLO loss> pathMTU`, e.g.
`2.10ms u0% b2% 1500`. `DOWN` = no probe answered, `b-` = target's HELLOs not
heard recently, `.` = no data.

Exit status with `-duration`: 0 every peer answers, 1 some peer never
answered, 2 no peer found, 3 setup error.

## Wi-Fi mesh notes

- **Choose the interface on purpose.** With batman-adv, `bat0` tests the
  batman overlay (multi-hop, batman's own MTU handling), while the underlying
  `mesh0`/`wlanX` tests the single radio hop. With 802.11s, `mesh0` is
  already a multi-hop L2 (HWMP).
- **Managed (client/AP, 3-address) Wi-Fi** can't send frames with a source
  MAC other than its own, which will matter when bridging an overlay later.
  Mesh point and 4-address/WDS modes don't have this limit. It's worth adding
  a "spoofed source MAC" probe to detect it.
- APs with client isolation drop station-to-station traffic, which shows up as
  DOWN or `b-`.
- `sniff -promisc` does little on most Wi-Fi drivers in managed mode. To see
  other stations' unicast you need monitor mode, which is a different capture
  format (radiotap/802.11) and not supported here.
- Cloud VPCs (AWS/GCP/Azure) are not real L2. Expect custom-EtherType and
  broadcast frames to be dropped.

## Known limitations / TODO

- [ ] Run it on real Linux (veth first, then the Wi-Fi mesh), then fix what
      breaks.
- [ ] Unicast loss is round-trip. Per-direction loss would need the target to
      report the probe seqs it received (or its own count per prober).
- [ ] MTU probing can't go above our own interface MTU. Also report the
      largest *received* probe per peer.
- [ ] The HELLO interval is assumed to be the same on all nodes (it's used for
      "heard recently" and staleness).
- [ ] Multicast is not tested separately from broadcast; on Wi-Fi they can
      behave differently.
- [ ] RTT uses userspace timestamps, so it includes scheduling jitter. Kernel
      timestamps (`SO_TIMESTAMPNS`) are possible later.
- [ ] No authentication: anyone on the segment can inject HELLOs and fake the
      matrix. Fine for a test tool, not for the overlay.
- [ ] Machine-readable output (`-json`) for scripting and history.
- [ ] Single interface per process.
- [ ] Only the agent logic is unit-tested; the socket I/O could go behind an
      interface so two agents can be tested in-process.

## Code map

- `main.go`: subcommands and flags
- `proto.go`: frame encoding/decoding
- `agent.go`: agent loop (HELLO, probes, replies, expiry, peer table)
- `stats.go`: sliding window for loss and RTT
- `matrix.go`: snapshot of agent state, matrix/table rendering, exit code
- `sniff.go`: passive mode
- `l2_test.go`: tests (no sockets needed)
