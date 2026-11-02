package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("egress_guardrail.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF collection spec: %v", err)
	}

	var objs struct {
		Prog *ebpf.Program `ebpf:"enforce_sovereign_boundary"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects into kernel: %v", err)
	}
	defer objs.Prog.Close()

	log.Println("[INFO] Sovereign eBPF bitwise guardrail compiled & loaded!")

	link, err := netlink.LinkByName("eth0")
	if err != nil {
		log.Fatalf("Failed to get eth0 interface: %v", err)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	_ = netlink.QdiscReplace(qdisc)

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  syscall.ETH_P_ALL,
		},
		Fd:           objs.Prog.FD(),
		Name:         "sovereign_guardrail",
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		log.Fatalf("Failed to attach TC filter: %v", err)
	}

	log.Println("🚀 Bitwise Sovereign Guardrail ACTIVE on eth0 egress! Press Ctrl+C to stop.")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	netlink.FilterDel(filter)
	log.Println("[INFO] Unloaded eBPF filter from network interface.")
}
