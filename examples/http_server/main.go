// http_server exercises the net/http path. It exists to demonstrate that
// vclgo works with idiomatic Go frameworks — the same launcher command
// that runs echo_server should run this program with no changes.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	var hits atomic.Int64

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprintf(w, "vclgo http_server\npath=%s\nremote=%s\ntime=%s\n",
			r.URL.Path, r.RemoteAddr, time.Now().Format(time.RFC3339Nano))
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hits=%d\n", hits.Load())
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Fprintf(os.Stderr, "http_server: listening on %s\n", *addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("http: %v", err)
	}
}
