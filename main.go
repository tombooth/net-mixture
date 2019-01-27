package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"

	"github.com/iovisor/gobpf/bcc"
)

import "C"

const source string = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

typedef struct {
	u32 pid;
    u32 saddr;
    u32 daddr;
    u64 dport;
} connect_event_t;

BPF_PERF_OUTPUT(connect_events);
BPF_HASH(connectcall, u32, connect_event_t);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();
    connect_event_t event = {
		.pid = pid,
        .saddr = sk->__sk_common.skc_rcv_saddr,
        .daddr = sk->__sk_common.skc_daddr,
        .dport = sk->__sk_common.skc_dport
	};
	// stash the sock ptr for lookup on return
	connectcall.update(&pid, &event);
	return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();
	connect_event_t *eventp = connectcall.lookup(&pid);
	if (eventp == 0) {
		return 0;	// missed entry
	}
	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		connectcall.delete(&pid);
		return 0;
	}
	// pull in details
    connect_event_t event = *eventp;
    // output
    connect_events.perf_submit(ctx, &event, sizeof(event));
    connectcall.delete(&pid);
	return 0;
}
`
type connectEvent struct {
	Pid         uint32
	Saddr       uint32
	Daddr       uint32
	Dport       uint64
}

func main() {
	m := bcc.NewModule(source, []string{})
	defer m.Close()

	connectKprobe, err := m.LoadKprobe("kprobe__tcp_v4_connect")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load kprobe__tcp_v4_connect: %s\n", err)
		os.Exit(1)
	}

	syscallName := bcc.GetSyscallFnName("connect")

	err = m.AttachKprobe(syscallName, connectKprobe)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach kprobe__tcp_v4_connect: %s\n", err)
		os.Exit(1)
	}

	connectKretprobe, err := m.LoadKprobe("kretprobe__tcp_v4_connect")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load kretprobe__tcp_v4_connect: %s\n", err)
		os.Exit(1)
	}

	err = m.AttachKretprobe(syscallName, connectKretprobe)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach kretprobe__tcp_v4_connect: %s\n", err)
		os.Exit(1)
	}

	table := bcc.NewTable(m.TableId("connect_events"), m)

	channel := make(chan []byte)

	perfMap, err := bcc.InitPerfMap(table, channel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var event connectEvent
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			fmt.Printf("pid %d called tcp_v4_connect(2) on %d %d %d\n",
				event.Pid, event.Saddr, event.Daddr, event.Dport)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
