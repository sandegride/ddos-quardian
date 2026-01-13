package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
	"time"
)

//go:embed web/*
var embeddedWebFS embed.FS

func Start(ctx context.Context, addr string, store *Store) error {
	if addr == "" {
		addr = ":8090"
	}

	mux := http.NewServeMux()

	// Health for quick checks.
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":   true,
			"ts":   time.Now().Format(time.RFC3339),
			"addr": addr,
		})
	})

	// Latest window snapshot.
	mux.HandleFunc("/api/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")

		rec, ok := store.Latest()
		if !ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(rec)
	})

	// Recent window list (default limit=120).
	mux.HandleFunc("/api/windows", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")

		limit := 120
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 2000 {
				limit = n
			}
		}
		_ = json.NewEncoder(w).Encode(store.List(limit))
	})

	// Static web UI.
	sub, err := fs.Sub(embeddedWebFS, "web")
	if err != nil {
		return err
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}

	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	return srv.ListenAndServe()
}
