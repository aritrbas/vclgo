// udp_echo_server is the UDP analogue of examples/echo_server. It uses
// Go's stdlib net.PacketConn API (which under the covers issues
// bind/recvfrom/sendto/close syscalls), containing ZERO vclgo/VPP
// imports on purpose. If a change is required here to make it work
// under vclgo, the UDP fastpath is broken.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("addr", ":9877", "listen address (UDP)")
	flag.Parse()

	pc, err := net.ListenPacket("udp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	fmt.Fprintf(os.Stderr, "udp_echo_server: listening on %s\n", pc.LocalAddr())

	var (
		pktsIn     atomic.Int64
		bytesTotal atomic.Int64
	)

	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for range t.C {
			fmt.Fprintf(os.Stderr,
				"udp_echo_server: pkts_in=%d total_bytes=%d\n",
				pktsIn.Load(), bytesTotal.Load())
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "udp_echo_server: shutting down")
		pc.Close()
	}()

	buf := make([]byte, 65536) // MAX datagram
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && !ne.Temporary() {
				return
			}
			log.Printf("readfrom: %v", err)
			return
		}
		pktsIn.Add(1)
		bytesTotal.Add(int64(n))
		if _, werr := pc.WriteTo(buf[:n], raddr); werr != nil {
			log.Printf("writeto %s: %v", raddr, werr)
			// Not fatal for UDP; keep serving.
		}
	}
}
