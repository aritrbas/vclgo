// http_server exercises the net/http path. It exists to demonstrate that
// vclgo works with idiomatic Go frameworks — the same launcher command
// that runs echo_server should run this program with no changes.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

func ephemeralCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "vclgo-test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl,
		&key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	network := flag.String("network", "tcp", "listen network: tcp, tcp4, or tcp6")
	useTLS := flag.Bool("tls", false, "serve HTTPS using an ephemeral test certificate")
	delay := flag.Duration("delay", 0, "delay /delay responses (for cancellation tests)")
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
	mux.HandleFunc("/delay", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if *delay > 0 {
			timer := time.NewTimer(*delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-r.Context().Done():
				return
			}
		}
		fmt.Fprintln(w, "vclgo delayed response")
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen(*network, *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	mode := "HTTP"
	if *useTLS {
		cert, err := ephemeralCertificate()
		if err != nil {
			log.Fatalf("certificate: %v", err)
		}
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		mode = "HTTPS"
	}
	fmt.Fprintf(os.Stderr, "http_server: listening on %s (%s)\n", ln.Addr(), mode)
	if *useTLS {
		err = srv.ServeTLS(ln, "", "")
	} else {
		err = srv.Serve(ln)
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("http: %v", err)
	}
}
