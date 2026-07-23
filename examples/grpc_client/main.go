// grpc_client performs concurrent health checks over one multiplexed gRPC
// (HTTP/2) connection and requires every response to report SERVING.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "server address")
	network := flag.String("network", "tcp", "dial network: tcp, tcp4, or tcp6")
	conc := flag.Int("conc", 32, "concurrent workers")
	reqs := flag.Int("reqs", 100, "health checks per worker")
	timeout := flag.Duration("timeout", 5*time.Second, "dial and per-RPC timeout")
	flag.Parse()

	dialCtx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	conn, err := grpc.DialContext(
		dialCtx,
		"passthrough:///"+*addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, *network, *addr)
		}),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "grpc_client: dial: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	client := healthpb.NewHealthClient(conn)

	var ok, failed atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < *reqs; j++ {
				ctx, cancel := context.WithTimeout(context.Background(), *timeout)
				response, err := client.Check(ctx, &healthpb.HealthCheckRequest{})
				cancel()
				if err != nil || response.GetStatus() != healthpb.HealthCheckResponse_SERVING {
					failed.Add(1)
					continue
				}
				ok.Add(1)
			}
		}()
	}
	wg.Wait()

	fmt.Fprintf(os.Stderr,
		"grpc_client: conc=%d reqs=%d ok=%d fail=%d elapsed=%s\n",
		*conc, *reqs, ok.Load(), failed.Load(), time.Since(start))
	if failed.Load() != 0 || ok.Load() != int64(*conc**reqs) {
		os.Exit(1)
	}
}
