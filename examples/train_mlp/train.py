#!/usr/bin/env python3
"""Synchronous data-parallel training through NetSum (plain Python, no NumPy).

A 2-24-3 MLP (147 parameters, three 64-value chunks per gradient) learns a
deterministic three-ring classification set split across 4 workers. Every
step each worker computes its gradient, quantizes it to Q16.16, and the
summed gradient is applied by every worker: w -= lr * sum / workers.

Aggregation paths (--paths, comma separated):
  float   sum of float gradients computed locally (the reference curve)
  quant   quantize -> exact int32 sum -> dequantize, computed locally
  net     the same quantized gradients sent through NetSum (--to / --ps);
          the summed int32 vector must be bit-identical to `quant` at every
          step, whatever the path (noagg, userspace or XDP aggregation)

Writes one CSV row per (step, path): loss, accuracy, max |w - w_float|,
and for `net` the number of retransmissions so far.
Usage: train.py --steps 200 --paths float,quant[,net --to IP:PORT --ps IP:PORT]
                [--label NAME] [--out results/curves.csv] [--job N]"""
import argparse
import hashlib
import math
import os
import random
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netsum_client  # noqa: E402

Q = 1 << 16
WORKERS = 4
HIDDEN = 24
CLASSES = 3


def quantize(x):
    """Q16.16, round to nearest, saturate (the worker-side conversion)."""
    if x != x:
        return 0
    v = int(round(x * Q))
    return max(-2**31, min(2**31 - 1, v))


def make_rings(n_per_class=120, seed=7):
    rng = random.Random(seed)
    data = []
    for cls in range(CLASSES):
        for _ in range(n_per_class):
            r = 0.4 + 0.5 * cls + rng.gauss(0, 0.08)
            a = rng.uniform(0, 2 * math.pi)
            data.append((r * math.cos(a), r * math.sin(a), cls))
    rng.shuffle(data)
    return data


def init_params(seed=11):
    rng = random.Random(seed)
    w1 = [[rng.gauss(0, 0.7) for _ in range(2)] for _ in range(HIDDEN)]
    b1 = [0.0] * HIDDEN
    w2 = [[rng.gauss(0, 0.3) for _ in range(HIDDEN)] for _ in range(CLASSES)]
    b2 = [0.0] * CLASSES
    return flatten(w1, b1, w2, b2)


def flatten(w1, b1, w2, b2):
    return [x for row in w1 for x in row] + b1 + [x for row in w2 for x in row] + b2


def unflatten(p):
    i = 0
    w1 = [p[i + 2 * h:i + 2 * h + 2] for h in range(HIDDEN)]
    i += 2 * HIDDEN
    b1 = p[i:i + HIDDEN]
    i += HIDDEN
    w2 = [p[i + HIDDEN * c:i + HIDDEN * c + HIDDEN] for c in range(CLASSES)]
    i += HIDDEN * CLASSES
    b2 = p[i:i + CLASSES]
    return w1, b1, w2, b2


def forward(p, x, y):
    w1, b1, w2, b2 = unflatten(p)
    h = [math.tanh(w1[j][0] * x + w1[j][1] * y + b1[j]) for j in range(HIDDEN)]
    z = [sum(w2[c][j] * h[j] for j in range(HIDDEN)) + b2[c] for c in range(CLASSES)]
    m = max(z)
    e = [math.exp(v - m) for v in z]
    s = sum(e)
    return h, [v / s for v in e]


def loss_acc(p, data):
    loss, ok = 0.0, 0
    for x, y, cls in data:
        _, prob = forward(p, x, y)
        loss -= math.log(max(prob[cls], 1e-12))
        ok += max(range(CLASSES), key=lambda c: prob[c]) == cls
    return loss / len(data), ok / len(data)


def gradient(p, shard):
    """Mean cross-entropy gradient over a shard, as a flat list like p."""
    w1, b1, w2, b2 = unflatten(p)
    g = [0.0] * len(p)
    o_b1, o_w2 = 2 * HIDDEN, 3 * HIDDEN
    o_b2 = o_w2 + HIDDEN * CLASSES
    for x, y, cls in shard:
        h, prob = forward(p, x, y)
        dz = [prob[c] - (1.0 if c == cls else 0.0) for c in range(CLASSES)]
        for c in range(CLASSES):
            g[o_b2 + c] += dz[c]
            for j in range(HIDDEN):
                g[o_w2 + HIDDEN * c + j] += dz[c] * h[j]
        for j in range(HIDDEN):
            dh = sum(dz[c] * w2[c][j] for c in range(CLASSES)) * (1 - h[j] * h[j])
            g[o_b1 + j] += dh
            g[2 * j] += dh * x
            g[2 * j + 1] += dh * y
    return [v / len(shard) for v in g]


def weight_hash(p):
    return hashlib.sha256(struct.pack(f"<{len(p)}d", *p)).hexdigest()[:16]


def parse_hostport(s):
    host, port = s.rsplit(":", 1)
    return host, int(port)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--steps", type=int, default=200)
    ap.add_argument("--lr", type=float, default=0.5)
    ap.add_argument("--paths", default="float,quant")
    ap.add_argument("--to")
    ap.add_argument("--ps")
    ap.add_argument("--job", type=int, default=4242)
    ap.add_argument("--label", default="net")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "curves.csv"))
    ap.add_argument("--log-every", type=int, default=10)
    args = ap.parse_args()
    paths = args.paths.split(",")
    if "net" in paths and not (args.to and args.ps):
        ap.error("--paths net needs --to and --ps")

    data = make_rings()
    shards = [data[i::WORKERS] for i in range(WORKERS)]
    p0 = init_params()
    params = {name: [list(p0) for _ in range(WORKERS)] for name in paths}
    workers = []
    if "net" in paths:
        workers = [netsum_client.Worker(i, WORKERS, args.job, parse_hostport(args.to), parse_hostport(args.ps))
                   for i in range(WORKERS)]
        time.sleep(0.1)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    new = not os.path.exists(args.out)
    out = open(args.out, "a")
    if new:
        out.write("config,step,loss,accuracy,max_abs_w_diff_vs_float,retransmissions,bit_identical_to_quant\n")
    mismatched_steps = 0
    t0 = time.time()
    for step in range(args.steps + 1):
        if step % args.log_every == 0 or step == args.steps:  # log every path before any update
            for name in paths:
                ps = params[name]
                loss, acc = loss_acc(ps[0], data)
                ref = params["float"][0] if "float" in params else ps[0]
                diff = max(abs(a - b) for a, b in zip(ps[0], ref))
                label = args.label if name == "net" else name
                resent = sum(w.resent for w in workers) if name == "net" else 0
                out.write(f"{label},{step},{loss:.6f},{acc:.4f},{diff:.3e},{resent},"
                          f"{'' if name != 'net' else int(mismatched_steps == 0)}\n")
                out.flush()
                assert len({weight_hash(p) for p in ps}) == 1, f"{name}: workers diverged at step {step}"
        if step == args.steps:
            break
        for name in paths:
            ps = params[name]
            grads = [gradient(ps[i], shards[i]) for i in range(WORKERS)]
            if name == "float":
                agg = [sum(col) for col in zip(*grads)]
            else:
                q = [[quantize(v) for v in g] for g in grads]
                ints = [sum(col) for col in zip(*q)]
                if name == "net":
                    ints_net = netsum_client.allreduce(workers, step, q)
                    if ints_net != ints:
                        mismatched_steps += 1
                    ints = ints_net
                agg = [v / Q for v in ints]
            for i in range(WORKERS):
                ps[i] = [w - args.lr * a / WORKERS for w, a in zip(ps[i], agg)]
    if "net" in params and "quant" in params:
        same = params["net"][0] == params["quant"][0]
        print(f"network-path weights identical to local quantized weights after {args.steps} steps: {same}")
        if not same:
            mismatched_steps += 1
    out.close()
    for w in workers:
        w.close()
    summary = {name: loss_acc(params[name][0], data) for name in paths}
    print(f"{args.steps} steps in {time.time() - t0:.1f} s; final (loss, accuracy): "
          + ", ".join(f"{(args.label if n == 'net' else n)}={v[0]:.4f}/{v[1]:.3f}" for n, v in summary.items()))
    if workers:
        print(f"network path: {sum(w.resent for w in workers)} retransmissions; "
              f"steps whose summed gradient differed from the local quantized sum: {mismatched_steps}")
    return 1 if mismatched_steps else 0


if __name__ == "__main__":
    sys.exit(main())
