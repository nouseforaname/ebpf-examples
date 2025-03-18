package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -tags linux user user.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -tags linux unlink unlink.c
