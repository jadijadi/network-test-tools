#!/bin/bash
# DNS / DoH / DoT / ECH status probe.
# Every test runs under a hard timeout so one hang can't starve the rest
# (the original script lost ~300s to a single hung DoH call).

set -uo pipefail

DATE=$(date +%Y%m%d-%H%M%S)
PCAP="doh-ech-tests-$DATE.pcap"
LOG="doh-ech-tests-$DATE.log"
CURL_BIN="/home/debian/src/curl-wolfssl"
TIMEOUT=8              # hard per-test cap in seconds
STALL_TIMEOUT=12       # a bit more headroom for the large research.cloudflare.com page
REPEAT=3               # trials per arm for the ECH-on vs ECH-off stall comparison

DOH_TARGET="cloudflare.com"                 # plain HTTPS/DoH target
ECH_TARGET="cloudflare-ech.com"             # Cloudflare's public ECH test domain
                                             # (its /cdn-cgi/trace reports sni=encrypted|plaintext server-side)
STALL_TARGET="research.cloudflare.com"      # large (~72KB) page on a shared Cloudflare ECH config;
                                             # a prior run stalled mid-transfer on this target with SNI
                                             # sent in cleartext - this script now retests with ECH
                                             # actually engaged to see if that stall goes away
ECH_DOH_URL="https://9.9.9.9/dns-query"     # curl only fetches the HTTPS/ECH DNS record automatically
                                             # when paired with --doh-url; 1.1.1.1 is blocked on this
                                             # network so use Quad9 here, confirmed working

DNS_SERVERS=(1.1.1.1 8.8.8.8 9.9.9.9)
declare -A DOH_URLS=(
  [cloudflare]="https://1.1.1.1/dns-query"
  [google]="https://8.8.8.8/dns-query"
  [quad9]="https://9.9.9.9/dns-query"
)

mark() {
  echo "MARKER[$(date '+%Y-%m-%d %H:%M:%S.%N')]: $*" | tee -a "$LOG"
}

# run <label> <timeout_seconds> <command...>
run() {
  local label=$1 to=$2; shift 2
  mark "START $label :: $*"
  { time timeout --signal=KILL "$to" "$@" ; } >>"$LOG" 2>&1
  echo "EXIT[$label]=$?" >>"$LOG"
  mark "END $label"
}

: > "$LOG"
echo "=== curl build ===" | tee -a "$LOG"
"$CURL_BIN" -V | tee -a "$LOG"
if "$CURL_BIN" -V | grep -Eq '(^| )ECH( |$)'; then
  echo "curl advertises ECH support" | tee -a "$LOG"
else
  echo "WARNING: this curl build does not advertise ECH support - --ech results below are not meaningful" | tee -a "$LOG"
fi

sudo tcpdump -i any -U -w "$PCAP" 'port 53 or port 853 or port 443 or icmp' &
TCPDUMP_PID=$!
sleep 2   # let tcpdump attach before generating any traffic

##### 1. Plain DNS baseline: UDP + TCP, multiple resolvers #####
for srv in "${DNS_SERVERS[@]}"; do
  run "dns-udp-A-$srv"    5 dig +time=3 +tries=1 @"$srv" "$DOH_TARGET" A
  run "dns-udp-AAAA-$srv" 5 dig +time=3 +tries=1 @"$srv" "$DOH_TARGET" AAAA
  run "dns-tcp-A-$srv"    5 dig +tcp +time=3 +tries=1 @"$srv" "$DOH_TARGET" A
done

##### 2. HTTPS/SVCB record lookup - shows whether an ECH config is even published #####
for srv in "${DNS_SERVERS[@]}"; do
  run "dns-https-record-$srv" 5 dig +time=3 +tries=1 @"$srv" "$ECH_TARGET" TYPE65
done

##### 3. DoT reachability (curl has no DoT support) #####
for srv in "${DNS_SERVERS[@]}"; do
  if command -v kdig >/dev/null 2>&1; then
    run "dot-query-$srv" 5 kdig +tls @"$srv" "$DOH_TARGET" A
  else
    mark "START dot-handshake-$srv (openssl fallback, connectivity only)"
    timeout 5 openssl s_client -connect "$srv:853" </dev/null >>"$LOG" 2>&1
    echo "EXIT[dot-handshake-$srv]=$?" >>"$LOG"
    mark "END dot-handshake-$srv"
  fi
done

##### 4. DoH resolution + fetch, per provider #####
for name in "${!DOH_URLS[@]}"; do
  run "doh-$name" "$TIMEOUT" "$CURL_BIN" -v \
    -w '\nHTTP=%{http_code} time_total=%{time_total} time_appconnect=%{time_appconnect}\n' \
    --doh-url "${DOH_URLS[$name]}" "https://$DOH_TARGET/"
done

##### 5. Baseline HTTPS, no DoH/no ECH, system resolver only #####
run "https-baseline" "$TIMEOUT" "$CURL_BIN" -v \
  -w '\nHTTP=%{http_code} time_total=%{time_total}\n' "https://$DOH_TARGET/"

##### 6. ECH ground truth via cloudflare-ech.com trace endpoint #####
# --doh-url is paired here so curl actually fetches the HTTPS/ECH DNS record and uses it;
# without it curl has no ECHConfig to apply and --ech true silently does nothing (confirmed
# last run: both arms logged "ECH: requested but no ECHConfig available" and sni=plaintext).
run "ech-true-groundtruth"  "$TIMEOUT" "$CURL_BIN" -v --doh-url "$ECH_DOH_URL" --ech true  "https://$ECH_TARGET/cdn-cgi/trace"
run "ech-false-groundtruth" "$TIMEOUT" "$CURL_BIN" -v --doh-url "$ECH_DOH_URL" --ech false "https://$ECH_TARGET/cdn-cgi/trace"

##### 7. ECH-on vs ECH-off against the target that previously stalled mid-transfer #####
# Interleaved and repeated REPEAT times per arm: if the stall is triggered by DPI matching
# the plaintext SNI, hiding it with real ECH should make it go away; if it's IP- or
# volume-triggered instead, it'll stall the same way in both arms.
for i in $(seq 1 "$REPEAT"); do
  run "ech-true-research-$i"  "$STALL_TIMEOUT" "$CURL_BIN" -v --doh-url "$ECH_DOH_URL" --ech true  "https://$STALL_TARGET/"
  run "ech-false-research-$i" "$STALL_TIMEOUT" "$CURL_BIN" -v --doh-url "$ECH_DOH_URL" --ech false "https://$STALL_TARGET/"
done

mark "All tests complete, draining capture"
sleep 5   # let any late/in-flight packets land before we stop capturing

sudo kill -INT "$TCPDUMP_PID"
wait "$TCPDUMP_PID" 2>/dev/null

echo "Capture: $PCAP"
echo "Log:     $LOG"
