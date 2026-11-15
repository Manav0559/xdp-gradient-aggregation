#!/usr/bin/env bash
# Smoke test for netsum-ctl on a veth pair (root, Linux): attach -> config ->
# stats -> a stuck 2-of-3 round -> sweep flushes it as PARTIAL to a listener
# -> sweep retires it -> detach. Checks exit codes and JSON shapes.
set -euo pipefail
CTL=${CTL:-./bin/netsum-ctl}
PIN=/sys/fs/bpf/netsum_smoke
cleanup() { "$CTL" --pin "$PIN" detach --ifname vs0 --unpin >/dev/null 2>&1 || true; ip link del vs0 2>/dev/null || true; ip netns del vsns 2>/dev/null || true; }
trap cleanup EXIT
cleanup
ip link add vs0 type veth peer name vs1
ip netns add vsns
ip link set vs1 netns vsns
ip addr add 10.77.0.1/24 dev vs0; ip link set vs0 up
ip netns exec vsns ip addr add 10.77.0.2/24 dev vs1
ip netns exec vsns ip link set vs1 up
ip netns exec vsns ip link set lo up

"$CTL" --pin "$PIN" --json attach --ifname vs0 --mode generic | tee /tmp/ctl_attach.json
python3 -c "import json; d=json.load(open('/tmp/ctl_attach.json')); assert d['attached']=='generic', d"
VS1_MAC=$(ip netns exec vsns ip link show vs1 | awk '/link\/ether/ {print $2}')
"$CTL" --pin "$PIN" --json config --ps-mac "$VS1_MAC" --ps-ip 10.77.0.2 --ps-port 9000 --slot-ttl-ms 100
"$CTL" --pin "$PIN" --json stats > /tmp/ctl_stats0.json
python3 -c "import json; d=json.load(open('/tmp/ctl_stats0.json')); assert len(d) >= 40 and sum(d.values()) == 0, d"

# Two of three contributions for job 77: the round is stuck.
for w in 0 1; do
    ip netns exec vsns python3 - "$w" <<'PY'
import socket, struct, sys
w = int(sys.argv[1])
bm = bytearray(32); bm[w // 8] |= 1 << (w % 8)
pkt = struct.pack(">IIIHHHH", 77, 0, 0, w, 3, 2, 0x2000) + struct.pack(">ii", 65536, 65536) + bytes(bm)
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(pkt, ("10.77.0.1", 9876))
PY
done
sleep 0.3
"$CTL" --pin "$PIN" --json slots --state accumulating > /tmp/ctl_slots.json
python3 -c "import json; d=json.load(open('/tmp/ctl_slots.json')); assert len(d)==1 and d[0]['contributors']==2 and d[0]['fanin']==3, d"

# A listener plays the PS; the sweeper must send it one PARTIAL for job 77.
python3 - > /tmp/ctl_partial.txt <<'PY' &
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 9555)); s.settimeout(5)
d = s.recv(2048)
job, rnd, chunk, wid, nw, cl, flags = struct.unpack(">IIIHHHH", d[:20])
print(job, wid, nw, cl, flags, struct.unpack(">i", d[20:24])[0], d[20 + 4 * cl])
PY
LISTENER=$!
sleep 0.3
"$CTL" --pin "$PIN" sweep --once --ttl-ms 0 --flush-to 127.0.0.1:9555 | tee /tmp/ctl_sweep1.json
wait $LISTENER
read -r job wid nw cl flags lane0 bm < /tmp/ctl_partial.txt
[ "$job" = 77 ] && [ "$wid" = 65535 ] && [ "$nw" = 3 ] && [ "$cl" = 2 ] && [ "$lane0" = 131072 ] && [ "$bm" = 3 ]
[ $((flags & 0x10)) -ne 0 ]
"$CTL" --pin "$PIN" --json slots --state flushed | python3 -c "import json,sys; d=json.load(sys.stdin); assert len(d)==1, d"
"$CTL" --pin "$PIN" sweep --once --ttl-ms 0 --flush-to 127.0.0.1:9555 | python3 -c "import json,sys; d=json.loads(sys.stdin.read().strip().splitlines()[-1]); assert d['retired']==1, d"
"$CTL" --pin "$PIN" --json slots | python3 -c "import json,sys; assert json.load(sys.stdin)==[]"
"$CTL" --pin "$PIN" --json stats | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['slot_flushed_partial']==1 and d['slot_retired_ttl']==1 and d['accepted']==2, d"
"$CTL" --pin "$PIN" detach --ifname vs0 --unpin
[ ! -e "$PIN" ]
echo "netsum-ctl smoke test: PASS"
