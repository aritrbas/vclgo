// echo_client is a stdlib-only companion for echo_server. It opens N
// concurrent connections, sends a fixed number of messages on each, and
// verifies the echo matches. Also serves as the concurrency stress test
// for the vclgo dispatcher's waiter map.
package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	sysCloseRange         = 436 // linux/amd64 __NR_close_range
	closeRangeUnshare     = 1 << 1
	closeRangeCloseOnExec = 1 << 2
	vclgoReservedFDBase   = 0x000f0000
	vclgoReservedFDLimit  = 0x00100000
)

func mmapSixthArgumentProbe() error {
	f, err := os.CreateTemp("", "vclgo-mmap-probe-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()

	pageSize := syscall.Getpagesize()
	want := make([]byte, pageSize*2)
	for i := 0; i < pageSize; i++ {
		want[i] = 0x41
		want[pageSize+i] = 0x42
	}
	if _, err := f.Write(want); err != nil {
		return err
	}

	mapped, err := syscall.Mmap(int(f.Fd()), int64(pageSize), pageSize,
		syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		return fmt.Errorf("mmap at sixth-argument offset %d: %w", pageSize, err)
	}
	defer syscall.Munmap(mapped)
	if len(mapped) != pageSize || mapped[0] != 0x42 || mapped[len(mapped)-1] != 0x42 {
		return fmt.Errorf("mmap used the wrong offset: first=%#x last=%#x",
			mapped[0], mapped[len(mapped)-1])
	}
	return nil
}

func dialTCP(network, addr string, timeout time.Duration) (*net.TCPConn, error) {
	c, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return nil, err
	}
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("dial returned %T, want *net.TCPConn", c)
	}
	return tcp, nil
}

func tcpFD(c *net.TCPConn) (uintptr, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var fd uintptr
	if err := raw.Control(func(v uintptr) { fd = v }); err != nil {
		return 0, err
	}
	return fd, nil
}

func echoOnce(c *net.TCPConn, payload []byte, timeout time.Duration) error {
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := c.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("echo mismatch: got %d bytes", len(got))
	}
	return nil
}

func sendfileProbe(network, addr string, timeout time.Duration) error {
	c, err := dialTCP(network, addr, timeout)
	if err != nil {
		return err
	}
	defer c.Close()
	fd, err := tcpFD(c)
	if err != nil {
		return err
	}

	f, err := os.CreateTemp("", "vclgo-sendfile-probe-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	payload := make([]byte, 128*1024+37)
	for i := range payload {
		payload[i] = byte(i*31 + 7)
	}
	if _, err := f.Write(payload); err != nil {
		return err
	}

	offset := int64(0)
	sent := 0
	deadline := time.Now().Add(timeout)
	for sent < len(payload) {
		n, err := syscall.Sendfile(int(fd), int(f.Fd()), &offset,
			len(payload)-sent)
		sent += n
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			if time.Now().After(deadline) {
				return fmt.Errorf("sendfile timed out after %d bytes", sent)
			}
			time.Sleep(time.Millisecond)
			continue
		}
		if err != nil {
			return fmt.Errorf("sendfile after %d bytes: %w", sent, err)
		}
		if n == 0 {
			return fmt.Errorf("sendfile made no progress after %d bytes", sent)
		}
	}
	if offset != int64(len(payload)) {
		return fmt.Errorf("sendfile offset=%d, want %d", offset, len(payload))
	}
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("sendfile echo mismatch")
	}
	return nil
}

func closeRangeProbe(network, addr string, timeout time.Duration) error {
	c, err := dialTCP(network, addr, timeout)
	if err != nil {
		return err
	}
	defer c.Close()
	fd, err := tcpFD(c)
	if err != nil {
		return err
	}
	if fd < vclgoReservedFDBase || fd >= vclgoReservedFDLimit {
		return fmt.Errorf("connection fd %#x is outside the VCL reserved range", fd)
	}

	// Unsharing a thread's fd table cannot be reconciled with the process-wide
	// VCL registry. It must fail without closing the session.
	_, _, errno := syscall.Syscall6(sysCloseRange, fd, fd,
		closeRangeUnshare, 0, 0, 0)
	if errno != syscall.EOPNOTSUPP {
		return fmt.Errorf("close_range(UNSHARE) errno=%v, want %v",
			errno, syscall.EOPNOTSUPP)
	}
	if err := echoOnce(c, []byte("still-open-after-unshare"), timeout); err != nil {
		return fmt.Errorf("connection changed after rejected UNSHARE: %w", err)
	}

	// CLOEXEC changes only the kernel surrogate's descriptor flag; VCL
	// ownership and data-plane behavior must remain intact.
	_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, 0)
	if errno != 0 {
		return fmt.Errorf("clear FD_CLOEXEC: %w", errno)
	}
	_, _, errno = syscall.Syscall6(sysCloseRange, fd, fd,
		closeRangeCloseOnExec, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("close_range(CLOEXEC): %w", errno)
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
	if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
		return fmt.Errorf("FD_CLOEXEC not set: flags=%#x errno=%v", flags, errno)
	}
	if err := echoOnce(c, []byte("still-open-after-cloexec"), timeout); err != nil {
		return fmt.Errorf("connection closed by CLOEXEC mode: %w", err)
	}

	_, _, errno = syscall.Syscall6(sysCloseRange, fd, fd, 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("close_range: %w", errno)
	}
	if _, err := c.Write([]byte("must-fail-after-close-range")); err == nil {
		return fmt.Errorf("write succeeded after close_range")
	}
	return nil
}

func refusedProbe(network, addr string, timeout time.Duration) error {
	c, err := dialTCP(network, addr, timeout)
	if err == nil {
		c.Close()
		return fmt.Errorf("connect to unused endpoint unexpectedly succeeded")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return fmt.Errorf("connect timed out instead of returning ECONNREFUSED: %w", err)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("connect error=%v, want ECONNREFUSED", err)
	}
	return nil
}

func halfCloseProbe(network, addr string, timeout time.Duration) error {
	c, err := dialTCP(network, addr, timeout)
	if err != nil {
		return err
	}
	defer c.Close()
	payload := []byte("vclgo-half-close-payload")
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := c.Write(payload); err != nil {
		return fmt.Errorf("write before CloseWrite: %w", err)
	}
	if err := c.CloseWrite(); err != nil {
		return fmt.Errorf("CloseWrite: %w", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		return fmt.Errorf("read after CloseWrite: %w", err)
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("half-close echo mismatch")
	}
	one := make([]byte, 1)
	if n, err := c.Read(one); n != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("final read=(%d,%v), want (0,EOF)", n, err)
	}
	return nil
}

func peerResetProbe(network, addr string, timeout time.Duration) error {
	c, err := dialTCP(network, addr, timeout)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "echo_client: peer-reset probe ready")
	payload := make([]byte, 256*1024)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	for sent := 0; sent < len(payload); {
		n, err := c.Write(payload[sent:])
		if err != nil {
			if errors.Is(err, syscall.ECONNRESET) {
				return nil
			}
			return fmt.Errorf("reset probe write: %w", err)
		}
		sent += n
	}
	one := make([]byte, 1)
	_, err = c.Read(one)
	if err == nil {
		return fmt.Errorf("read succeeded after peer termination")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return fmt.Errorf("read timed out instead of observing peer reset: %w", err)
	}
	if !errors.Is(err, syscall.ECONNRESET) {
		return fmt.Errorf("peer termination error=%v, want ECONNRESET", err)
	}
	return nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1:9876", "server address")
	network := flag.String("network", "tcp", "dial network: tcp, tcp4, or tcp6")
	conc := flag.Int("conc", 8, "concurrent connections")
	msgs := flag.Int("msgs", 32, "messages per connection")
	size := flag.Int("size", 4096, "bytes per message")
	timeout := flag.Duration("timeout", 30*time.Second, "per-op deadline")
	dialTimeout := flag.Duration("dial-timeout", 0,
		"connection deadline (defaults to -timeout)")
	idleRead := flag.Bool("idle-read", false,
		"wait for a read deadline without sending data")
	mmapProbe := flag.Bool("mmap-probe", false,
		"verify sixth-argument raw-syscall passthrough")
	sendfileTest := flag.Bool("sendfile-probe", false,
		"verify sendfile translation to a VCL-owned TCP connection")
	closeRangeTest := flag.Bool("close-range-probe", false,
		"verify close_range VCL lifecycle and flag semantics")
	refusedTest := flag.Bool("refused-probe", false,
		"require ECONNREFUSED from an unused TCP endpoint")
	halfCloseTest := flag.Bool("half-close-probe", false,
		"verify CloseWrite followed by echo read and EOF")
	peerResetTest := flag.Bool("peer-reset-probe", false,
		"wait for a peer process termination and require ECONNRESET")
	flag.Parse()
	effectiveDialTimeout := *dialTimeout
	if effectiveDialTimeout <= 0 {
		effectiveDialTimeout = *timeout
	}
	if *mmapProbe {
		if err := mmapSixthArgumentProbe(); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintln(os.Stderr, "echo_client: mmap sixth-argument probe OK")
		return
	}
	if *sendfileTest {
		if err := sendfileProbe(*network, *addr, effectiveDialTimeout); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintln(os.Stderr, "echo_client: sendfile probe OK")
		return
	}
	if *closeRangeTest {
		if err := closeRangeProbe(*network, *addr, effectiveDialTimeout); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintln(os.Stderr, "echo_client: close_range probe OK")
		return
	}
	if *refusedTest {
		if err := refusedProbe(*network, *addr, effectiveDialTimeout); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintln(os.Stderr, "echo_client: connection-refused probe OK")
		return
	}
	if *halfCloseTest {
		if err := halfCloseProbe(*network, *addr, effectiveDialTimeout); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintln(os.Stderr, "echo_client: half-close probe OK")
		return
	}
	if *peerResetTest {
		if err := peerResetProbe(*network, *addr, effectiveDialTimeout); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintln(os.Stderr, "echo_client: peer-reset probe OK")
		return
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
			c, err := net.DialTimeout(*network, *addr, effectiveDialTimeout)
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
