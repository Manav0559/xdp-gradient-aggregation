#!/usr/bin/env python3
"""Quantization study (docs/DESIGN_NOTES.md §Fixed point): how well do
integer formats represent summed gradients? Plain Python, fixed seeds.

Formats
  q16      Q16.16 (NetSum's wire format): round(x * 2^16), int32
  atp1e8   ATP's scaled int32 (NSDI'21 §3.8): round(x * 1e8), int32
  blockexp per-chunk shared exponent (block floating point, as in SwitchML):
           scale = 2^e with e chosen from the chunk's max |x| and the fan-in so
           the int32 sum cannot overflow. Offline only: on the wire every
           worker must use the same e for a chunk, which needs an agreement
           step NetSum does not have.
  float32  IEEE single precision summed in float32 (the usual all-reduce)

Data: synthetic N(0, sigma^2) for sigma in {1e-4, 1e-2, 1}, Student-t (nu=3)
scaled by 1e-2, and real per-worker gradients captured from the
examples/train_mlp model at steps 0, 50 and 150.

Metrics per (format, data, fan-in N in {2, 8, 32, 256}): relative L2 error of
the summed vector against the exact float64 sum; the fraction of non-zero
inputs that quantize to 0 (underflow); the fraction of 64-value chunks with
an int32 overflow in the sum. Then the training demo is rerun with each
format and its final loss and accuracy compared.

Usage: quant_study.py [--out bench/v2] [--quick]"""
import argparse
import csv
import math
import os
import random
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "examples", "train_mlp"))
import train as mlp  # noqa: E402

I32_MIN, I32_MAX = -2**31, 2**31 - 1
CHUNK = 64


def round_away(s):
    return int(s + 0.5) if s >= 0 else -int(-s + 0.5)


def sat(v):
    return max(I32_MIN, min(I32_MAX, v))


def f32(x):
    return struct.unpack("f", struct.pack("f", x))[0]


def aggregate(fmt, vectors):
    """Returns (summed vector as floats, underflow count, nonzero count,
    overflowed chunk count, chunk count)."""
    n_vals = len(vectors[0])
    out, under, nonzero, ovf_chunks, chunks = [0.0] * n_vals, 0, 0, 0, 0
    for c0 in range(0, n_vals, CHUNK):
        lanes = range(c0, min(n_vals, c0 + CHUNK))
        chunks += 1
        if fmt == "float32":
            for i in lanes:
                acc = 0.0
                for v in vectors:
                    acc = f32(acc + f32(v[i]))
                out[i] = acc
            continue
        if fmt == "q16":
            scale = 65536.0
        elif fmt == "atp1e8":
            scale = 1e8
        else:  # blockexp: largest power of two with N * max|x| * 2^e <= INT32_MAX
            m = max((abs(v[i]) for v in vectors for i in lanes), default=0.0)
            e = 30 if m == 0 else math.floor(math.log2(I32_MAX / (len(vectors) * m)))
            scale = 2.0 ** max(-126, min(126, e))
        overflow = False
        for i in lanes:
            acc = 0
            for v in vectors:
                q = sat(round_away(v[i] * scale))
                nonzero += v[i] != 0
                under += v[i] != 0 and q == 0
                acc += q
            if acc > I32_MAX or acc < I32_MIN:
                overflow = True
            acc = ((acc - I32_MIN) % 2**32) + I32_MIN  # what an int32 accumulator holds
            out[i] = acc / scale
        ovf_chunks += overflow
    return out, under, nonzero, ovf_chunks, chunks


def rel_l2(approx, exact):
    num = math.sqrt(sum((a - b) ** 2 for a, b in zip(approx, exact)))
    den = math.sqrt(sum(b * b for b in exact))
    return num / den if den else 0.0


def synthetic(kind, n_workers, length, rng):
    if kind.startswith("gauss"):
        sigma = float(kind.split("_")[1])
        return [[rng.gauss(0, sigma) for _ in range(length)] for _ in range(n_workers)]
    # Student-t with nu = 3, scaled by 1e-2
    def t3():
        z = rng.gauss(0, 1)
        chi2 = sum(rng.gauss(0, 1) ** 2 for _ in range(3))
        return 1e-2 * z / math.sqrt(chi2 / 3)
    return [[t3() for _ in range(length)] for _ in range(n_workers)]


def real_gradients(n_workers, steps=(0, 50, 150)):
    """Per-worker gradients of the demo MLP at a few points of float training."""
    data = mlp.make_rings()
    shards = [data[i::mlp.WORKERS] for i in range(mlp.WORKERS)]
    p = mlp.init_params()
    out = {}
    for step in range(max(steps) + 1):
        grads = [mlp.gradient(p, shards[i]) for i in range(mlp.WORKERS)]
        if step in steps:
            out[step] = grads
        agg = [sum(col) for col in zip(*grads)]
        p = [w - 0.5 * a / mlp.WORKERS for w, a in zip(p, agg)]
    # fan-in > 4: reuse the 4 workers' gradients cyclically (same magnitudes)
    return {s: [g[i % len(g)] for i in range(n_workers)] for s, g in out.items()}


def train_with(fmt, steps):
    data = mlp.make_rings()
    shards = [data[i::mlp.WORKERS] for i in range(mlp.WORKERS)]
    p = mlp.init_params()
    for _ in range(steps):
        grads = [mlp.gradient(p, shards[i]) for i in range(mlp.WORKERS)]
        agg = aggregate(fmt, grads)[0] if fmt != "float64" else [sum(c) for c in zip(*grads)]
        p = [w - 0.5 * a / mlp.WORKERS for w, a in zip(p, agg)]
    return mlp.loss_acc(p, data)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(ROOT, "bench", "v2"))
    ap.add_argument("--quick", action="store_true", help="smaller vectors, for a fast check")
    args = ap.parse_args()
    rng = random.Random(1234)
    length = 256 if args.quick else 1024
    formats = ["q16", "atp1e8", "blockexp", "float32"]
    rows = []
    datasets = ["gauss_1e-4", "gauss_1e-2", "gauss_1", "student_t3"]
    for n in (2, 8, 32, 256):
        inputs = {d: synthetic(d, n, length, rng) for d in datasets}
        for step, g in real_gradients(n).items():
            inputs[f"mlp_step{step}"] = g
        for dname, vecs in inputs.items():
            exact = [math.fsum(col) for col in zip(*vecs)]
            for fmt in formats:
                agg, under, nonzero, ovf, chunks = aggregate(fmt, vecs)
                rows.append({"data": dname, "fanin": n, "format": fmt,
                             "rel_l2_error": f"{rel_l2(agg, exact):.3e}",
                             "underflow_fraction": f"{under / nonzero:.4f}" if nonzero else "0",
                             "overflow_chunk_fraction": f"{ovf / chunks:.4f}"})
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "quant_formats.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    steps = 100 if args.quick else 200
    train_rows = []
    for fmt in ["float64"] + formats:
        loss, acc = train_with(fmt, steps)
        train_rows.append({"format": fmt, "steps": steps, "final_loss": f"{loss:.6f}", "final_accuracy": f"{acc:.4f}"})
    with open(os.path.join(args.out, "quant_training.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(train_rows[0].keys()))
        w.writeheader()
        w.writerows(train_rows)
    print("data,fanin,format,rel_l2_error,underflow_fraction,overflow_chunk_fraction")
    for r in rows:
        print(",".join(str(v) for v in r.values()))
    for r in train_rows:
        print(r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
