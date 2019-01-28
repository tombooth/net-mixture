package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
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
	u64 pid;
    u32 saddr;
    u32 daddr;
    u16 dport;
    u16 __padding1;
    u32 __padding2;
} connect_event_t;

BPF_PERF_OUTPUT(connect_events);
BPF_HASH(connectcall, u64, struct sock *);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
	u64 pid = bpf_get_current_pid_tgid();
	connectcall.update(&pid, &sk);
	return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skp = connectcall.lookup(&pid);
	if (skp == 0) {
		return 0;	// missed entry
	}
	if (ret != 0) {
		connectcall.delete(&pid);
		return 0;
	}
        struct sock *sk = *skp;
        u16 dport = sk->__sk_common.skc_dport;
	// pull in details
  	  connect_event_t event = {
		.pid = pid,
		.saddr = sk->__sk_common.skc_rcv_saddr,
       	 	.daddr = sk->__sk_common.skc_daddr,
        	.dport = ntohs(dport)
	};
    // output
    connect_events.perf_submit(ctx, &event, sizeof(event));
    connectcall.delete(&pid);
	return 0;
}
`

type connectEvent struct {
	Pid   uint32
	Tgid  uint32
	Saddr uint32
	Daddr uint32
	Dport uint16
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

func main() {
	m := bcc.NewModule(source, []string{})
	defer m.Close()

	connectKprobe, err := m.LoadKprobe("kprobe__tcp_v4_connect")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load kprobe__tcp_v4_connect: %s\n", err)
		os.Exit(1)
	}

	syscallName := "tcp_v4_connect"

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
			buf := bytes.NewBuffer(data)
			err := binary.Read(buf, binary.LittleEndian, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			fmt.Printf("pid %d called tcp_v4_connect(2) on %s %s %d\n",
				event.Pid, int2ip(event.Saddr), int2ip(event.Daddr), event.Dport)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
