// echo_client is a stdlib-only companion for echo_server. It opens N
// concurrent connections, sends a fixed number of messages on each, and
// verifies the echo matches. Also serves as the concurrency stress test
// for the vclgo dispatcher's waiter map.
package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9876", "server address")
	conc := flag.Int("conc", 8, "concurrent connections")
	msgs := flag.Int("msgs", 32, "messages per connection")
	size := flag.Int("size", 4096, "bytes per message")
	timeout := flag.Duration("timeout", 30*time.Second, "per-op deadline")
	dialTimeout := flag.Duration("dial-timeout", 0,
		"connection deadline (defaults to -timeout)")
	idleRead := flag.Bool("idle-read", false,
		"wait for a read deadline without sending data")
	flag.Parse()
	effectiveDialTimeout := *dialTimeout
	if effectiveDialTimeout <= 0 {
		effectiveDialTimeout = *timeout
	}

	var (
		bytesOut atomic.Int64
		bytesIn  atomic.Int64
		errors   atomic.Int64
	)

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", *addr, effectiveDialTimeout)
			if err != nil {
				log.Printf("[%d] dial: %v", id, err)
				errors.Add(1)
				return
			}
			defer c.Close()
			buf := make([]byte, *size)
			echo := make([]byte, *size)
			if *idleRead {
				_ = c.SetReadDeadline(time.Now().Add(*timeout))
				_, err := c.Read(echo[:1])
				if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
					log.Printf("[%d] idle read: got %v, want deadline", id, err)
					errors.Add(1)
				}
				return
			}
			for m := 0; m < *msgs; m++ {
				if _, err := rand.Read(buf); err != nil {
					errors.Add(1)
					return
				}
				_ = c.SetDeadline(time.Now().Add(*timeout))
				if _, err := c.Write(buf); err != nil {
					log.Printf("[%d] write: %v", id, err)
					errors.Add(1)
					return
				}
				bytesOut.Add(int64(*size))
				if _, err := io.ReadFull(c, echo); err != nil {
					log.Printf("[%d] read: %v", id, err)
					errors.Add(1)
					return
				}
				bytesIn.Add(int64(*size))
				if !bytes.Equal(buf, echo) {
					log.Printf("[%d] echo mismatch on msg %d", id, m)
					errors.Add(1)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	fmt.Fprintf(os.Stderr,
		"echo_client: conc=%d msgs=%d size=%d elapsed=%s "+
			"out=%d in=%d errors=%d mbps=%.1f\n",
		*conc, *msgs, *size, elapsed,
		bytesOut.Load(), bytesIn.Load(), errors.Load(),
		float64(bytesOut.Load()+bytesIn.Load())*8/1e6/elapsed.Seconds(),
	)
	if errors.Load() > 0 {
		os.Exit(1)
	}
}
