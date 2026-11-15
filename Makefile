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

.PHONY: all clean test unit bpf bpf-compat bpf-unit bpf-unit-bin ctl

all: $(BIN_DIR)/worker $(BIN_DIR)/paramserver $(BIN_DIR)/agg $(BIN_DIR)/lite_sender

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

HDRS = protocol/grad_proto.h protocol/grad_parse.h protocol/netsum_stats.h common/slot_table.h

$(BIN_DIR)/worker: worker/worker.c $(HDRS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ worker/worker.c

$(BIN_DIR)/paramserver: paramserver/paramserver.c $(HDRS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ paramserver/paramserver.c

$(BIN_DIR)/lite_sender: bench/lite_sender.c $(HDRS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ bench/lite_sender.c

$(BIN_DIR)/agg: userspace_agg/agg.c $(HDRS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ userspace_agg/agg.c

unit: tests/unit/test_slot_table.c $(HDRS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/test_slot_table tests/unit/test_slot_table.c
	./$(BIN_DIR)/test_slot_table

test: all unit
	python3 tests/test_correctness.py
	python3 tests/test_protocol_v2.py
	python3 tests/test_reliability.py

# On Linux with libbpf headers installed, build against the real UAPI and
# libbpf headers; otherwise use the vendored subset in xdp_agg/bpf_compat.h.
# `make bpf-compat` forces the vendored build (CI compares the two).
BPF_HDRS = xdp_agg/bpf_compat.h protocol/netsum_maps.h $(HDRS)
BPF_CFLAGS = -target bpf -mcpu=v3 -Wall -Wextra -O2 -g
ifeq ($(shell uname -s),Linux)
ifneq ($(wildcard /usr/include/bpf/bpf_helpers.h),)
BPF_CFLAGS += -DNETSUM_USE_SYSTEM_LIBBPF
endif
endif

bpf: xdp_agg/xdp_agg.c $(BPF_HDRS)
	$(BPF_CC) $(BPF_CFLAGS) -c xdp_agg/xdp_agg.c -o xdp_agg/xdp_agg.o
	@echo "compiled xdp_agg/xdp_agg.o; load it with CI or netsum-ctl on Linux (docs/DEV_ENVIRONMENT.md)"

bpf-compat: xdp_agg/xdp_agg.c $(BPF_HDRS)
	$(BPF_CC) $(filter-out -DNETSUM_USE_SYSTEM_LIBBPF,$(BPF_CFLAGS)) -c xdp_agg/xdp_agg.c -o xdp_agg/xdp_agg_compat.o

# Control plane (Linux, libbpf).
ctl: ctl/netsum_ctl.c protocol/netsum_maps.h $(HDRS) | $(BIN_DIR)
ifeq ($(shell uname -s),Linux)
	$(CC) -O2 -g -Wall -Wextra -o $(BIN_DIR)/netsum-ctl ctl/netsum_ctl.c -lbpf -lelf -lz
else
	@echo "netsum-ctl requires Linux and libbpf"
endif

# BPF_PROG_TEST_RUN harness (Linux, libbpf, root).
bpf-unit-bin: tests/bpf/run_xdp_tests.c protocol/netsum_maps.h $(HDRS) | $(BIN_DIR)
	$(CC) -O2 -g -Wall -Wextra -o $(BIN_DIR)/run_xdp_tests tests/bpf/run_xdp_tests.c -lbpf -lelf -lz

bpf-unit:
ifeq ($(shell uname -s),Linux)
	$(MAKE) bpf bpf-unit-bin
	sudo ./$(BIN_DIR)/run_xdp_tests xdp_agg/xdp_agg.o fuzz/corpus
else
	@echo "bpf-unit requires Linux (BPF_PROG_TEST_RUN); it runs in CI (.github/workflows/bpf-unit.yml)"
endif

clean:
	rm -rf $(BIN_DIR) xdp_agg/*.o
