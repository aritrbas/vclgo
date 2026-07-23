// udp_echo_client is the UDP analogue of examples/echo_client. It
// fires N concurrent workers that each send M datagrams to a UDP echo
// server and verify the reply. Contains ZERO vclgo/VPP imports.
package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func icmpErrorProbe(network string, saddr *net.UDPAddr, timeout time.Duration) error {
	c, err := net.DialUDP(network, nil, saddr)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := c.Write([]byte("vclgo-icmp-error-probe")); err != nil &&
		errors.Is(err, syscall.ECONNREFUSED) {
		return nil
	} else if err != nil {
		return fmt.Errorf("UDP write: %w", err)
	}
	one := make([]byte, 1)
	_, err = c.Read(one)
	if err == nil {
		return fmt.Errorf("UDP read unexpectedly succeeded")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return fmt.Errorf("UDP read timed out instead of receiving ICMP error: %w", err)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("UDP error=%v, want ECONNREFUSED", err)
	}
	return nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1:9877", "server address")
	network := flag.String("network", "udp", "network: udp, udp4, or udp6")
	local := flag.String("local", "127.0.0.1:0",
		"local address for unconnected UDP")
	conc := flag.Int("conc", 4, "concurrent workers")
	msgs := flag.Int("msgs", 8, "datagrams per worker")
	size := flag.Int("size", 1024, "datagram size in bytes")
	timeout := flag.Duration("timeout", 5*time.Second, "per-datagram timeout")
	unconnected := flag.Bool("unconnected", false,
		"use unconnected UDP (WriteTo/ReadFrom sendto/recvfrom) instead of Dial (write/read)")
	icmpError := flag.Bool("icmp-error-probe", false,
		"send to an unused connected-UDP endpoint and require ECONNREFUSED")
	flag.Parse()

	if *size <= 0 || *size > 65000 {
		log.Fatalf("bad -size %d (must be 1..65000)", *size)
	}

	var (
		out    atomic.Int64
		in     atomic.Int64
		errors atomic.Int64
	)

	saddr, err := net.ResolveUDPAddr(*network, *addr)
	if err != nil {
		log.Fatalf("resolve %s: %v", *addr, err)
	}
	if *icmpError {
		if err := icmpErrorProbe(*network, saddr, *timeout); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintln(os.Stderr, "udp_echo_client: ICMP error probe OK")
		return
	}

	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			payload := make([]byte, *size)
			if _, err := rand.Read(payload); err != nil {
				log.Printf("[%d] rand: %v", id, err)
				errors.Add(1)
				return
			}

			var conn net.PacketConn
			var dialed *net.UDPConn
			if *unconnected {
				var err error
				conn, err = net.ListenPacket(*network, *local)
				if err != nil {
					log.Printf("[%d] listenpacket: %v", id, err)
					errors.Add(1)
					return
				}
				defer conn.Close()
			} else {
				c, err := net.DialUDP(*network, nil, saddr)
				if err != nil {
					log.Printf("[%d] dial: %v", id, err)
					errors.Add(1)
					return
				}
				dialed = c
				defer c.Close()
			}

			reply := make([]byte, *size+64)
			for m := 0; m < *msgs; m++ {
				var n int
				var err error
				if *unconnected {
					_ = conn.SetDeadline(time.Now().Add(*timeout))
					n, err = conn.WriteTo(payload, saddr)
				} else {
					_ = dialed.SetDeadline(time.Now().Add(*timeout))
					n, err = dialed.Write(payload)
				}
				if err != nil || n != len(payload) {
					log.Printf("[%d] send: n=%d err=%v", id, n, err)
					errors.Add(1)
					continue
				}
				out.Add(int64(n))

				var rn int
				if *unconnected {
					var raddr net.Addr
					rn, raddr, err = conn.ReadFrom(reply)
					if err == nil && raddr.String() != saddr.String() {
						log.Printf("[%d] read: bad peer %s (want %s)",
							id, raddr, saddr)
						errors.Add(1)
						continue
					}
				} else {
					rn, err = dialed.Read(reply)
				}
				if err != nil {
					log.Printf("[%d] read: %v", id, err)
					errors.Add(1)
					continue
				}
				if !bytes.Equal(payload, reply[:rn]) {
					log.Printf("[%d] payload mismatch: got %d bytes, want %d",
						id, rn, len(payload))
					errors.Add(1)
					continue
				}
				in.Add(int64(rn))
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)

	fmt.Fprintf(os.Stderr,
		"udp_echo_client: conc=%d msgs=%d size=%d elapsed=%s "+
			"out=%d in=%d errors=%d mbps=%.1f\n",
		*conc, *msgs, *size, elapsed,
		out.Load(), in.Load(), errors.Load(),
		float64(in.Load())*8/1e6/elapsed.Seconds())
	if errors.Load() > 0 {
		os.Exit(1)
	}
}
