BPF_SRC = gtp_teid_tc.bpf.c
BPF_OBJ = gtp_teid_tc.bpf.o
SKEL_HDR = gtp_teid_tc.skel.h
USER_OBJ = read_teid
IFACE ?= n3

.PHONY: all clean setup cleanup

all: $(USER_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	clang -O2 -g -target bpf -c $(BPF_SRC) -o $(BPF_OBJ)

$(SKEL_HDR): $(BPF_OBJ)
	bpftool gen skeleton $(BPF_OBJ) > $(SKEL_HDR)

$(USER_OBJ): read_teid.c $(SKEL_HDR)
	cc -O2 -g -Wall -o $(USER_OBJ) read_teid.c -lbpf -lelf -lz

setup:
	@echo "[*] Adding clsact qdisc to interface $(IFACE)"
	@if ! tc qdisc show dev $(IFACE) | grep -q clsact; then \
		tc qdisc add dev $(IFACE) clsact; \
	else \
		echo "[!] clsact already exists on $(IFACE)"; \
	fi

cleanup:
	tc qdisc del dev $(IFACE) clsact || true
	rm -f $(BPF_OBJ) $(SKEL_HDR) $(USER_OBJ) teid_log.txt

clean:
	rm -f $(BPF_OBJ) $(SKEL_HDR) $(USER_OBJ) teid_log.txt
