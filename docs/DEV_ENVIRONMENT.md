# Dev Environment — XDP/eBPF Toolchain

The `worker/`, `paramserver/`, and `userspace_agg/` components are plain BSD-socket
C programs — they build and run on macOS or Linux with nothing beyond a C compiler
(verified: `cc -Wall -Wextra -Wpedantic -std=c11` on macOS, zero warnings).

**`xdp_agg/` (the actual kernel program) is different: XDP/eBPF do not exist on
macOS/Darwin at all.** It needs a real Linux kernel (≥ 5.15, for stable
`bpf_spin_lock` + `BPF_MAP_TYPE_HASH` support) to compile, load, or run.

## Getting a working Linux environment

Three options, roughly in order of setup friction:

1. **A cloud VM** (a free-tier GCP/AWS/Oracle instance running Ubuntu 24.04) — the
   most reliable option, real kernel, no nested-virtualization surprises.
2. **A local Linux VM** via UTM or `multipass` on macOS:
   ```sh
   multipass launch 24.04 --name netsum --cpus 2 --memory 2G
   multipass shell netsum
   ```
3. **OrbStack's Linux VM**, if already installed — `docker run --privileged` gives a
   real Linux kernel underneath, but this repo's own setup found the OrbStack daemon
   would not come up without a one-time manual permission grant in **System Settings
   → General → Login Items & Extensions → Network Extensions** (macOS requires
   explicit user approval for OrbStack's network extension on first launch, which a
   non-interactive shell cannot click through). If you see
   `failed to connect to the docker API at unix:///.../docker.sock`, open OrbStack's
   app once directly and approve that permission dialog, then retry.

## Installing the toolchain (inside whichever Linux environment you pick)

```sh
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-tools-common linux-tools-generic
```

## Verifying it actually works before writing any BPF code

```sh
uname -r                     # confirm >= 5.15
bpftool version               # confirms libbpf-dev + linux-tools installed correctly
clang -target bpf -O2 -c xdp_agg/xdp_agg.c -o xdp_agg/xdp_agg.o   # once xdp_agg.c exists
```

A successful compile to `xdp_agg.o` with no verifier complaints is the real
milestone — BPF verifier errors are the single biggest source of schedule risk in
this project (see the spec's Known Risks table), and it is much cheaper to discover
verifier restrictions on a trivial one-map, one-lookup program than after the full
accumulation logic is written.

## What's already built and tested without any of this

`make && python3 tests/test_correctness.py` runs the full 6-test correctness suite
against the real worker/paramserver/userspace-aggregator binaries **right now, on
this machine, no Linux VM required** — the wire protocol, the slot-table
accumulation algorithm, duplicate-worker rejection, and the packet-reduction
property are all validated before a single line of BPF code is written. The XDP
program's job is then narrowly scoped: parse the same header, do the same
accumulate-and-check-completion logic (with `bpf_spin_lock` for the real
multi-core-safety property the userspace version doesn't need), and emit via
`XDP_TX` — not to reinvent or re-validate the algorithm itself.
