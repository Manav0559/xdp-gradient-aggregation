# NetSum: userspace components build natively on macOS or Linux (plain BSD
# sockets, no eBPF dependency). The xdp_agg/ kernel program has its own
# build path (clang -target bpf) documented in docs/DEV_ENVIRONMENT.md and
# requires a real Linux kernel -- it is NOT part of this top-level `make`.
CC = cc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -O2 -g
BIN_DIR = bin

.PHONY: all clean test

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

clean:
	rm -rf $(BIN_DIR)
