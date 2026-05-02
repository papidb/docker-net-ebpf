package ebpfcollector

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" netwatch ../../../bpf/netwatch.bpf.c -- -I/usr/include
