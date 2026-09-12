# NetSum: userspace components build natively on macOS or Linux (plain BSD
# sockets, no eBPF dependency). The xdp_agg/ kernel program compiles to real
# BPF bytecode with any clang that has the BPF backend (Homebrew LLVM's
# clang on macOS, or system clang on most Linux distros) -- codegen alone
# needs no Linux kernel, no libbpf, nothing beyond bpf_compat.h's vendored
# UAPI subset (see docs/DEV_ENVIRONMENT.md). LOADING it onto a real
# interface does need a real Linux kernel; `make bpf` only compiles.
CC = cc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -O2 -g
BIN_DIR = bin

# Prefer Homebrew LLVM's clang if present (macOS system clang lacks the BPF
# backend); fall back to whatever `clang` resolves to otherwise (Linux).
HOMEBREW_LLVM_CLANG = /opt/homebrew/opt/llvm/bin/clang
ifneq ($(wildcard $(HOMEBREW_LLVM_CLANG)),)
BPF_CC = $(HOMEBREW_LLVM_CLANG)
else
BPF_CC = clang
endif

.PHONY: all clean test bpf

all: $(BIN_DIR)/worker $(BIN_DIR)/paramserver $(BIN_DIR)/agg

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/worker: worker/worker.c protocol/grad_proto.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ worker/worker.c

$(BIN_DIR)/paramserver: paramserver/paramserver.c protocol/grad_proto.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ paramserver/paramserver.c

$(BIN_DIR)/agg: userspace_agg/agg.c protocol/grad_proto.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ userspace_agg/agg.c

test: all
	python3 tests/test_correctness.py

bpf: xdp_agg/xdp_agg.c xdp_agg/bpf_compat.h protocol/grad_proto.h
	$(BPF_CC) -target bpf -Wall -Wextra -O2 -g -c xdp_agg/xdp_agg.c -o xdp_agg/xdp_agg.o
	@echo "compiled xdp_agg/xdp_agg.o -- codegen-clean, not yet verifier/load-tested (needs a real Linux kernel, see docs/DEV_ENVIRONMENT.md)"

clean:
	rm -rf $(BIN_DIR) xdp_agg/*.o
