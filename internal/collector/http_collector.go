//go:build !pcap

package collector

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// PacketEvent в "HTTP-режиме" трактуется как событие запроса.
// Поля TCPSYN/TCPACK не используются (оставлены для совместимости с режимом pcap).
type PacketEvent struct {
	Ts     time.Time
	SrcIP  string
	DstIP  string
	Proto  string // для HTTP считаем "TCP"
	Length int

	TCPSYN bool
	TCPACK bool
}

// Options: в режиме !pcap используются ListenAddr и BackendURL.
type Options struct {
	// HTTP proxy mode
	ListenAddr string
	BackendURL string

	// pcap mode options (ignored here)
	Interface string
	BPF       string
	SnapLen   int32
	Promisc   bool
	Timeout   time.Duration
}

func Run(ctx context.Context, opt Options, out chan<- PacketEvent) error {
	if opt.ListenAddr == "" {
		opt.ListenAddr = ":8080"
	}
	if opt.BackendURL == "" {
		return fmt.Errorf("backend_url is required in !pcap mode")
	}
	backend, err := url.Parse(opt.BackendURL)
	if err != nil {
		return fmt.Errorf("parse backend_url: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(backend)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		// Оценка "размера" события: ContentLength + длина URL (очень грубо)
		ln := 0
		if r.ContentLength > 0 {
			ln = int(r.ContentLength)
		}
		ln += len(r.URL.String())

		ev := PacketEvent{
			Ts:     time.Now(),
			SrcIP:  ip,
			DstIP:  backend.Host,
			Proto:  "TCP",
			Length: ln,
		}

		// Не блокируем обработку запросов, если канал переполнен
		select {
		case out <- ev:
		default:
			// drop
		}

		proxy.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:              opt.ListenAddr,
		Handler:           h,
		ReadHeaderTimeout: 3 * time.Second,
	}

	// graceful shutdown
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	fmt.Println("HTTP proxy collector listening on", opt.ListenAddr, "->", opt.BackendURL)
	err = srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func clientIP(r *http.Request) string {
	// Пробуем X-Forwarded-For (первый IP)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		return xr
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}
