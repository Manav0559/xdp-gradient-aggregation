#!/usr/bin/env python3
"""Synchronous data-parallel training through NetSum (plain Python, no NumPy).

A 2-24-3 MLP (147 parameters, three 64-value chunks per gradient) learns a
deterministic three-ring classification set split across 4 workers. Every
step each worker computes its gradient, quantizes it to Q16.16, and the
summed gradient is applied by every worker: w -= lr * sum / workers.

Aggregation paths (--paths, comma separated):
  float   sum of float gradients computed locally (the reference curve)
  quant   quantize -> exact int32 sum -> dequantize, computed locally
  adapt   the same with a per-chunk exponent (wire v3): each chunk's
          exponent follows the previous step's summed int32 values
          (scale_rule.py), so small gradients keep their precision
  net     the same quantized gradients sent through NetSum (--to / --ps),
          as v2 Q16.16 (`quant`) or, with --net-format v3, as `adapt`; the
          summed int32 vector must be bit-identical to the local sum at every
          step, whatever the path (noagg, userspace or XDP aggregation)

--grad-scale S multiplies every gradient by S and divides the learning rate
by S, so the float curve is unchanged while the values on the wire shrink.
--spike-step K --spike-factor F multiplies the gradients sent at step K by F
and divides the summed result by F (training is unchanged; on the v3 paths
it forces chunks to overflow, so the in-step retry is exercised).

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
import scale_rule  # noqa: E402

Q = 1 << 16
WORKERS = 4
HIDDEN = 24
CLASSES = 3


def quantize(x):
    """Q16.16 exactly as netsum_to_fixed(): round half away from zero,
    saturate at the int32 limits, NaN -> 0."""
    if x != x:
        return 0
    s = x * Q
    if s >= 2147483647.0:
        return 2147483647
    if s <= -2147483648.0:
        return -2147483648
    return int(s + 0.5) if s >= 0 else -int(-s + 0.5)


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


def adaptive_step(name, step, grads, e, workers, stats, recompute=False):
    """One all-reduce at per-chunk exponents `e` (updated in place for the
    next step). Each worker's values are bounded by INT32_MAX // N, so a
    chunk overflows only when some worker saturates; it is then retried in
    this step at e - 8 under a fresh key (scale_rule.py). Local for `adapt`;
    through NetSum for `net`, where every attempt's result must equal the
    local one. Returns the dequantized sum, or None if the network differed
    (the caller then counts it and recomputes locally)."""
    ch = netsum_client.MAX_CHUNK
    n = len(grads[0])
    limit = scale_rule.worker_limit(len(grads))
    cur = list(e)
    done = {}
    pending = list(range(len(e)))
    for attempt in range(scale_rule.MAX_ATTEMPTS):
        if not pending:
            break
        local, items = {}, []
        for c in pending:
            lanes = range(c * ch, min(n, (c + 1) * ch))
            q, sat = [], []
            for g in grads:
                row = [scale_rule.quantize(g[j], cur[c], limit) for j in lanes]
                q.append([v for v, _ in row])
                sat.append(any(s for _, s in row))
            local[c] = ([sum(col) for col in zip(*q)], any(sat))
            items.append((netsum_client.retry_chunk_id(c, attempt), q, cur[c], sat))
        if name == "net" and not recompute:
            res = netsum_client.exchange(workers, step, items)
            for c in pending:
                got, over = res[netsum_client.retry_chunk_id(c, attempt)]
                if over != local[c][1] or (not over and got != local[c][0]):
                    return None
        retry = []
        for c in pending:
            ints, over = local[c]
            if not over:
                done[c] = ints
            elif cur[c] == scale_rule.E_MIN:
                raise OverflowError(f"{name}: step {step} chunk {c} overflows even at exponent 0")
            else:
                cur[c] = scale_rule.clamp_e(cur[c] - scale_rule.OVERFLOW_STEP)
                retry.append(c)
                stats["retried_chunks"] = stats.get("retried_chunks", 0) + 1
        pending = retry
    agg = [scale_rule.dequantize(v, cur[j // ch]) for j, v in enumerate(sum((done[c] for c in range(len(e))), []))]
    for c in range(len(e)):
        e[c] = scale_rule.next_exponent(done[c], cur[c])
    return agg


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
    ap.add_argument("--grad-scale", type=float, default=1.0)
    ap.add_argument("--net-format", choices=("v2", "v3"), default="v2")
    ap.add_argument("--spike-step", type=int, default=-1)
    ap.add_argument("--spike-factor", type=float, default=1.0)
    args = ap.parse_args()
    paths = args.paths.split(",")
    if "net" in paths and not (args.to and args.ps):
        ap.error("--paths net needs --to and --ps")

    data = make_rings()
    shards = [data[i::WORKERS] for i in range(WORKERS)]
    p0 = init_params()
    params = {name: [list(p0) for _ in range(WORKERS)] for name in paths}
    n_chunks = (len(p0) + netsum_client.MAX_CHUNK - 1) // netsum_client.MAX_CHUNK
    exps = {name: [scale_rule.Q16] * n_chunks for name in paths}
    adaptive = {name for name in paths if name == "adapt" or (name == "net" and args.net_format == "v3")}
    stats = {name: {} for name in paths}
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
            spike = args.spike_factor if step == args.spike_step else 1.0
            grads = [[v * args.grad_scale * spike for v in gradient(ps[i], shards[i])] for i in range(WORKERS)]
            if name == "float":
                agg = [sum(col) for col in zip(*grads)]
            elif name in adaptive:
                before = (list(exps[name]), dict(stats[name]))
                agg = adaptive_step(name, step, grads, exps[name], workers, stats[name])
                if agg is None:
                    mismatched_steps += 1
                    exps[name][:], stats[name] = before
                    agg = adaptive_step(name, step, grads, exps[name], None, stats[name], recompute=True)
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
                ps[i] = [w - (args.lr / args.grad_scale) * (a / spike) / WORKERS for w, a in zip(ps[i], agg)]
    ref_path = "adapt" if args.net_format == "v3" else "quant"
    if "net" in params and ref_path in params:
        same = params["net"][0] == params[ref_path][0]
        print(f"network-path weights identical to local {ref_path} weights after {args.steps} steps: {same}")
        if not same:
            mismatched_steps += 1
    out.close()
    for w in workers:
        w.close()
    summary = {name: loss_acc(params[name][0], data) for name in paths}
    print(f"{args.steps} steps in {time.time() - t0:.1f} s; final (loss, accuracy): "
          + ", ".join(f"{(args.label if n == 'net' else n)}={v[0]:.4f}/{v[1]:.3f}" for n, v in summary.items()))
    for name in sorted(adaptive):
        print(f"{args.label if name == 'net' else name}: chunks retried after OVERFLOW: {stats[name].get('retried_chunks', 0)}")
    if workers:
        print(f"network path: {sum(w.resent for w in workers)} retransmissions; "
              f"steps whose summed gradient differed from the local quantized sum: {mismatched_steps}")
    return 1 if mismatched_steps else 0


if __name__ == "__main__":
    sys.exit(main())
