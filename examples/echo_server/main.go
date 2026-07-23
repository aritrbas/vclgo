// echo_server is an intentionally boring stdlib-net TCP echo server used
// to validate that vclgo transparently redirects `net.Listen` / `Accept` /
// `Conn.Read` / `Conn.Write` onto VPP's VCL.
//
// It contains ZERO vclgo/VPP-specific imports on purpose. If a change is
// required here to make it work under vclgo, the launcher is broken.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("addr", ":9876", "listen address")
	network := flag.String("network", "tcp", "listen network: tcp, tcp4, or tcp6")
	resetAfterRead := flag.Bool("reset-after-read", false,
		"read one byte, leave queued data unread, and close to generate TCP RST")
	flag.Parse()

	ln, err := net.Listen(*network, *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	fmt.Fprintf(os.Stderr, "echo_server: listening on %s\n", ln.Addr())

	var (
		active     atomic.Int64
		bytesTotal atomic.Int64
	)

	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for range t.C {
			fmt.Fprintf(os.Stderr,
				"echo_server: active=%d total_bytes=%d\n",
				active.Load(), bytesTotal.Load())
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "echo_server: shutting down")
		ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && !ne.Temporary() {
				return
			}
			log.Printf("accept: %v", err)
			return
		}
		active.Add(1)
		go func(c net.Conn) {
			defer func() {
				c.Close()
				active.Add(-1)
			}()
			if *resetAfterRead {
				one := make([]byte, 1)
				if _, err := io.ReadFull(c, one); err != nil {
					log.Printf("reset probe read: %v", err)
					return
				}
				// Let the remaining probe payload reach the transport RX FIFO.
				// VPP's TCP close path emits RST when that FIFO is non-empty.
				time.Sleep(200 * time.Millisecond)
				return
			}
			buf := make([]byte, 32*1024)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					bytesTotal.Add(int64(n))
					if _, werr := c.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					if err != io.EOF {
						log.Printf("read from %s: %v", c.RemoteAddr(), err)
					}
					return
				}
			}
		}(c)
	}
}
