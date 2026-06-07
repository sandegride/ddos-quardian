package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
	"time"

	"ddos-detector/internal/config"
	"ddos-detector/internal/loadgen"
	"ddos-detector/internal/runtime"
)

//go:embed web/*
var embeddedWebFS embed.FS

// Deps carries the live objects the dashboard exposes through its API.
type Deps struct {
	Store     *Store
	Params    *runtime.Params
	Whitelist *config.Whitelist
	LoadGen   *loadgen.Runner
	Auth      AdminAuth
}

func Start(ctx context.Context, addr string, deps Deps) error {
	if addr == "" {
		addr = ":8090"
	}

	mux := http.NewServeMux()

	// --- read-only metrics endpoints -------------------------------------
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     true,
			"ts":     time.Now().Format(time.RFC3339),
			"addr":   addr,
			"admin":  deps.Auth.enabled(),
			"target": deps.LoadGen.Target(),
		})
	})

	mux.HandleFunc("/api/latest", func(w http.ResponseWriter, r *http.Request) {
		rec, ok := deps.Store.Latest()
		if !ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, rec)
	})

	mux.HandleFunc("/api/windows", func(w http.ResponseWriter, r *http.Request) {
		limit := 120
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 2000 {
				limit = n
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(deps.Store.List(limit))
	})

	// --- admin / loadtest endpoints --------------------------------------
	registerAdmin(mux, deps.Params, deps.Whitelist, deps.LoadGen, deps.Auth)

	// --- static web UI ---------------------------------------------------
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
