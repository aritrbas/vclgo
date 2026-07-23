// grpc_server exposes the standard gRPC health service. It intentionally has
// no vclgo-specific code: LD_PRELOAD must carry its HTTP/2 TCP connection over
// VCL without changing the application.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	addr := flag.String("addr", ":50051", "listen address")
	network := flag.String("network", "tcp", "listen network: tcp, tcp4, or tcp6")
	flag.Parse()

	ln, err := net.Listen(*network, *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	server := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, healthServer)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		server.GracefulStop()
	}()

	fmt.Fprintf(os.Stderr, "grpc_server: listening on %s\n", ln.Addr())
	if err := server.Serve(ln); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
