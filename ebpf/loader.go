package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove resource limits for eBPF loading
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load pre-compiled eBPF object file into a collection spec
	spec, err := ebpf.LoadCollectionSpec("egress_guardrail.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF collection spec: %v", err)
	}

	var objs struct {
		Prog           *ebpf.Program `ebpf:"enforce_sovereign_boundary"`
		SovereignIpMap *ebpf.Map     `ebpf:"sovereign_ip_map"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects into kernel: %v", err)
	}
	defer objs.Prog.Close()
	defer objs.SovereignIpMap.Close()

	log.Println("[INFO] Sovereign eBPF guardrail successfully loaded into Linux kernel!")

	// Populate sovereign IP map with an approved IP (e.g., 192.168.1.100 = 1 approved)
	approvedIP := binaryIP("192.168.1.100")
	var approvedVal uint8 = 1
	if err := objs.SovereignIpMap.Put(&approvedIP, &approvedVal); err != nil {
		log.Fatalf("Failed to update sovereign IP map: %v", err)
	}
	log.Printf("[INFO] Whitelisted sovereign IP 192.168.1.100 in kernel map.")

	// Wait for termination signal to keep eBPF program attached
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[INFO] Unloading Sovereign eBPF guardrail...")
}

// Convert string IP to big-endian uint32 for eBPF key lookup
func binaryIP(ipStr string) uint32 {
	ip := net.ParseIP(ipStr).To4()
	return uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
}


