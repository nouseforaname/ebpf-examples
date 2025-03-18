package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/user"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

type exec_data_t struct {
	Pid    uint32
	F_name [128]byte
	Comm   [32]byte
}

type custom_message_t struct {
	Pid     uint32
	Message [128]byte
	Meta    [32]byte
}

func setlimit() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK,
		&unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}
}

func main() {
	setlimit()

	objs := unlinkObjects{}
	loadUnlinkObjects(&objs, nil)
	tp, err := link.Kprobe("do_unlinkat", objs.DoUnlinkat, nil)
	if err != nil {
		log.Fatalf("tracepoint err: %v", err)
	}
	defer tp.Close()
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("reader err")
	}
	i := 0
	for {
		log.Printf("i: %v", i)
		i++
		ev, err := rd.Read()
		if err != nil {
			log.Fatalf("Read fail")
		}
		if ev.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", ev.LostSamples)
			continue
		}
		b_arr := bytes.NewBuffer(ev.RawSample)
		var data custom_message_t
		if err = binary.Read(b_arr, binary.LittleEndian, &data); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}
		eventUser, err := user.LookupId(strings.Trim(fmt.Sprintf("%s", data.Meta), "\x00"))
		if err != nil {
			log.Fatalf("userLookup: %v", err)
		}
		fmt.Printf("delete event: %d \nmessage: \n'%s'\npid %d, \nmeta: %s\n",
			ev.CPU, data.Message, data.Pid, eventUser.Name)
	}
}
