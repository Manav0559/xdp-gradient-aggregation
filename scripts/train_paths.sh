# Sourced by .github/workflows/train-demo.yml: runs examples/train_mlp/train.py
# through every NetSum path on the scripts/topo.sh topology. Needs OUT (CSV).
CTL="sudo ./bin/netsum-ctl --pin /sys/fs/bpf/netsum_train"
PSMAC=$(sudo bash scripts/topo.sh mac ns_ps veth_p1)
AGGMAC=$(sudo bash scripts/topo.sh mac "" veth_p0)
ps_up() { sudo ip netns exec ns_ps ./bin/paramserver --quiet --ack-to 10.10.2.1:9876 9000 agg > /tmp/ps.log 2>&1 & sleep 0.5; }
ps_down() { sudo pkill -f bin/paramserver || true; sleep 0.3; }
train() { # label to [train.py args]
  sudo ip netns exec ns_w python3 examples/train_mlp/train.py --steps 200 --paths net \
    --to "$2" --ps 10.10.2.2:9000 --label "$1" --job $((RANDOM % 60000 + 1000)) --out "$OUT" "${@:3}" | tee "/tmp/train-$1.txt"
}
all_paths() { # label-suffix [train.py args]: noagg, useragg, xdp, xdp with 5% loss on one worker link
  local sfx=$1; shift
  ps_up; train "noagg$sfx" 10.10.2.2:9000 "$@"; ps_down
  ps_up; sudo ./bin/agg --quiet 9876 10.10.2.2 9000 > /tmp/agg.log 2>&1 & sleep 0.3
  train "useragg$sfx" 10.10.1.1:9876 "$@"; sudo pkill -f bin/agg || true; ps_down
  $CTL attach --ifname veth_w0 --ifname veth_p0 --mode generic --obj xdp_agg/xdp_agg.o
  $CTL config --ps-mac "$PSMAC" --ps-ip 10.10.2.2 --ps-port 9000 --agg-mac "$AGGMAC" --agg-ip 10.10.2.1 --egress-ifname veth_p0
  ps_up; train "xdp$sfx" 10.10.1.1:9876 "$@"; ps_down
  sudo ip netns exec ns_w tc qdisc add dev veth_w1 root netem loss 5%
  ps_up; train "xdp-loss5$sfx" 10.10.1.1:9876 "$@"; ps_down
  sudo ip netns exec ns_w tc qdisc del dev veth_w1 root
  $CTL --json stats > /tmp/xdp-stats.json
  python3 -c "import json; d=json.load(open('/tmp/xdp-stats.json')); print({k: v for k, v in d.items() if v})"
  $CTL detach --ifname veth_w0 --ifname veth_p0 --unpin
}
