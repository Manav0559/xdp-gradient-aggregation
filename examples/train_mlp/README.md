# Training through NetSum

A 2-24-3 MLP (147 parameters, so each gradient is three NetSum chunks of up
to 64 values) learns a deterministic three-ring classification set, split
across 4 workers that train with synchronous data-parallel SGD. Every step,
each worker's gradient is quantized to Q16.16 and summed, and every worker
applies `w -= lr * sum / 4`. Plain Python, no NumPy.

`train.py` compares, on the same data and initial weights:

| path | aggregation |
|---|---|
| `float` | float gradients summed locally: the reference |
| `quant` | quantize, exact int32 sum, dequantize, locally |
| `noagg`, `useragg`, `xdp`, `xdp-loss5` | the same quantized gradients sent through NetSum by `netsum_client.py` (the Python v2 client: register, chunk, resend, results) |

Integer addition is exact and order-independent, so every network path must
return a summed gradient **bit-identical** to `quant` at every step, and its
weights must equal `quant`'s at the end. `train.py` checks both and exits
non-zero otherwise. `float` and `quant` differ only by quantization error.

```sh
# local reference curves only
python3 examples/train_mlp/train.py --steps 200 --paths float,quant
# through a parameter server (macOS works: no kernel needed)
./bin/paramserver --quiet 9000 noagg &
python3 examples/train_mlp/train.py --paths quant,net --to 127.0.0.1:9000 --ps 127.0.0.1:9000 --label noagg
```

CI (`.github/workflows/train-demo.yml`) trains 200 steps through noagg,
userspace aggregation and XDP aggregation on the three-namespace topology,
and once more with 5% packet loss on the workers' link, so the Python
client's retransmissions are exercised. `results/curves.csv` comes from that
run (columns: config, step, loss, accuracy, max |w - w_float|, cumulative
retransmissions, bit-identical-to-quant flag). Results: `docs/RESULTS.md`
§Training.
