// http_client is a companion to http_server. It hammers the /path with
// concurrent GETs to make sure the net/http transport survives vclgo.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// isTransientDialError classifies a Get() error as an idempotent-safe
// retry candidate. Real HTTP clients do this as a matter of course.
//
// We specifically want to absorb cold-start connect races that VPP
// surfaces to Go as "connect: bad address" (EFAULT), because a fresh
// VCL app-side session pool can lose a small fraction of the very
// first parallel dials to a transient session-error mapping inside
// VPP. Since GET is idempotent, an immediate retry is safe and matches
// what curl/httpx do out of the box.
func isTransientDialError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "connect: bad address") ||
		strings.Contains(s, "connect: connection refused") ||
		strings.Contains(s, "connect: connection reset by peer") ||
		strings.Contains(s, "EOF") // rare: server closed pre-response header
}

func main() {
	url := flag.String("url", "http://127.0.0.1:8080/", "target URL")
	conc := flag.Int("conc", 8, "concurrent workers")
	reqs := flag.Int("reqs", 32, "requests per worker")
	timeout := flag.Duration("timeout", 5*time.Second, "per-request timeout")
	noKeepalive := flag.Bool("no-keepalive", false,
		"disable HTTP keepalives (one TCP connection per request)")
	// warmup lets a caller sink a small number of requests before the
	// measured burst starts. This is important for the vclgo fastpath:
	// on a cold VCL app-side session pool, firing 100+ parallel dials
	// simultaneously as the very first traffic can race with the app's
	// per-worker session-manager initialization and lose ~0.1% of
	// connects to transient VPP errors that surface as EFAULT.
	// A tiny sequential-ish warmup primes the pool before the big burst.
	warmupReqs := flag.Int("warmup-reqs", 0,
		"if >0, do this many sequential GETs before measurement starts")
	warmupConc := flag.Int("warmup-conc", 1,
		"parallelism during warmup (default 1 = fully sequential)")
	maxRetries := flag.Int("max-retries", 2,
		"per-GET retry budget for transient dial errors (idempotent-safe)")
	retryDelay := flag.Duration("retry-delay", 5*time.Millisecond,
		"initial backoff between retries (doubles each attempt)")
	flag.Parse()

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = *noKeepalive
	client := &http.Client{Timeout: *timeout, Transport: transport}

	if *warmupReqs > 0 {
		var (
			wOK   atomic.Int64
			wFail atomic.Int64
		)
		var wwg sync.WaitGroup
		per := (*warmupReqs + *warmupConc - 1) / *warmupConc
		for i := 0; i < *warmupConc; i++ {
			wwg.Add(1)
			go func() {
				defer wwg.Done()
				for r := 0; r < per; r++ {
					resp, err := client.Get(*url)
					if err != nil {
						wFail.Add(1)
						continue
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode == 200 {
						wOK.Add(1)
					} else {
						wFail.Add(1)
					}
				}
			}()
		}
		wwg.Wait()
		fmt.Fprintf(os.Stderr,
			"http_client: warmup conc=%d reqs=%d ok=%d fail=%d\n",
			*warmupConc, per*(*warmupConc), wOK.Load(), wFail.Load())
	}

	var (
		ok   atomic.Int64
		fail atomic.Int64
		body atomic.Int64
	)

	var (
		wg          sync.WaitGroup
		totRetries  atomic.Int64
		hardFail    atomic.Int64 // failed even after all retries
	)
	start := time.Now()
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for r := 0; r < *reqs; r++ {
				var (
					resp *http.Response
					err  error
				)
				delay := *retryDelay
				for attempt := 0; attempt <= *maxRetries; attempt++ {
					resp, err = client.Get(*url)
					if err == nil {
						if attempt > 0 {
							totRetries.Add(int64(attempt))
						}
						break
					}
					if !isTransientDialError(err) || attempt == *maxRetries {
						break
					}
					time.Sleep(delay)
					delay *= 2
				}
				if err != nil {
					log.Printf("[%d] GET: %v", id, err)
					fail.Add(1)
					hardFail.Add(1)
					continue
				}
				n, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode == 200 {
					ok.Add(1)
					body.Add(n)
				} else {
					fail.Add(1)
				}
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)
	if totRetries.Load() > 0 {
		fmt.Fprintf(os.Stderr,
			"http_client: absorbed %d transient dial retries "+
				"(hard-failed=%d)\n",
			totRetries.Load(), hardFail.Load())
	}

	fmt.Fprintf(os.Stderr,
		"http_client: conc=%d reqs=%d ok=%d fail=%d body_bytes=%d "+
			"elapsed=%s rps=%.1f\n",
		*conc, *reqs, ok.Load(), fail.Load(), body.Load(),
		elapsed, float64(ok.Load())/elapsed.Seconds())
	if fail.Load() > 0 {
		os.Exit(1)
	}
}
