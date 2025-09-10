# Makefile for GTP throughput eBPF program

BPF_C = gtp_throughput.bpf.c
BPF_O = gtp_throughput.bpf.o
SKEL_H = gtp_throughput.skel.h
USER_C = gtp_throughput_user.c
USER_BIN = gtp_throughput_user
IFACE ?= n2
HANDLE ?= 1
PRIO ?= 1

CLANG = clang
BPFCFLAGS = -O2 -g -target bpf
USERCFLAGS = -O2 -g

INCLUDES = -I. -I/usr/include/bpf

.PHONY: all clean run

all: $(USER_BIN)

$(BPF_O): $(BPF_C)
	@echo ">> Compiling eBPF object"
	$(CLANG) $(BPFCFLAGS) -c $< -o $@

$(SKEL_H): $(BPF_O)
	@echo ">> Generating BPF skeleton header"
	bpftool gen skeleton $< > $@

$(USER_BIN): $(USER_C) $(SKEL_H)
	@echo ">> Compiling user-space program"
	gcc $(USERCFLAGS) $(INCLUDES) -o $@ $(USER_C) -lelf -lz -lbpf -ljson-c

run: all
	@echo ">> Ensuring clsact qdisc is installed on $(IFACE)"
	@tc qdisc show dev $(IFACE) | grep -q clsact || tc qdisc add dev $(IFACE) clsact
	@echo ">> Running user-space program:"
	@echo "   Interface: $(IFACE)"
	@echo "   Ingress Handle: $(INGRESS_HANDLE)"
	@echo "   Egress Handle: $(EGRESS_HANDLE)"
	@echo "   Priority: $(PRIO)"
	@echo "   TEIDs: $(TEIDS)"


clean:
	@echo ">> Cleaning up"
	rm -f $(USER_BIN) $(BPF_O) $(SKEL_H)



#./$(USER_BIN) $(IFACE) --ingress-handle $(INGRESS_HANDLE) --egress-handle $(EGRESS_HANDLE) --priority $(PRIO) $(TEIDS)
