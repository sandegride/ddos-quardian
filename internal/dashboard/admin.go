package dashboard

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"ddos-detector/internal/config"
	"ddos-detector/internal/loadgen"
	"ddos-detector/internal/runtime"
)

// AdminAuth holds credentials for the basic-auth protected mutation endpoints.
// If User is empty the mutation endpoints respond with 503 (admin disabled).
type AdminAuth struct {
	User string
	Pass string
}

func (a AdminAuth) enabled() bool { return a.User != "" && a.Pass != "" }

// requireAuth wraps a handler with basic-auth and the "disabled" guard.
func (a AdminAuth) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.enabled() {
			http.Error(w, `{"error":"admin disabled: set ADMIN_USER and ADMIN_PASS env vars"}`,
				http.StatusServiceUnavailable)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(user), []byte(a.User)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(a.Pass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="ddos-guardian admin"`)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// registerAdmin wires up admin / loadtest routes on the given mux.
func registerAdmin(
	mux *http.ServeMux,
	params *runtime.Params,
	wl *config.Whitelist,
	lg *loadgen.Runner,
	auth AdminAuth,
) {
	// --- params ---------------------------------------------------------
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, params.Snapshot())
		case http.MethodPost:
			auth.requireAuth(func(w http.ResponseWriter, r *http.Request) {
				var s runtime.Snapshot
				if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
					writeJSON(w, http.StatusBadRequest, errMsg(err))
					return
				}
				// preserve window_ms (read-only at runtime)
				cur := params.Snapshot()
				s.WindowMs = cur.WindowMs
				if err := params.Update(s); err != nil {
					writeJSON(w, http.StatusBadRequest, errMsg(err))
					return
				}
				writeJSON(w, http.StatusOK, params.Snapshot())
			})(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// --- whitelist ------------------------------------------------------
	mux.HandleFunc("/api/whitelist", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]any{"entries": wl.Entries()})
		case http.MethodPost:
			auth.requireAuth(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Entries []string `json:"entries"`
					Text    string   `json:"text"` // alternative: newline-separated
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					writeJSON(w, http.StatusBadRequest, errMsg(err))
					return
				}
				lines := body.Entries
				if len(lines) == 0 && body.Text != "" {
					lines = strings.Split(body.Text, "\n")
				}
				if err := wl.ReplaceLines(lines); err != nil {
					writeJSON(w, http.StatusBadRequest, errMsg(err))
					return
				}
				writeJSON(w, http.StatusOK, map[string]any{"entries": wl.Entries()})
			})(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// --- loadtest -------------------------------------------------------
	mux.HandleFunc("/api/loadtest/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, lg.Status())
	})

	mux.HandleFunc("/api/loadtest/start", auth.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Preset   string           `json:"preset"`
			Scenario loadgen.Scenario `json:"scenario"`
		}
		// empty body is allowed → defaults to demo preset
		_ = json.NewDecoder(r.Body).Decode(&body)

		scn := body.Scenario
		if len(scn.Phases) == 0 || body.Preset == "demo" {
			scn = loadgen.DefaultDemoScenario()
		}
		if err := lg.Start(scn); err != nil {
			writeJSON(w, http.StatusConflict, errMsg(err))
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{
			"started": true,
			"target":  lg.Target(),
			"status":  lg.Status(),
		})
	}))

	mux.HandleFunc("/api/loadtest/stop", auth.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		lg.Stop()
		writeJSON(w, http.StatusOK, map[string]any{"stopped": true})
	}))
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func errMsg(err error) map[string]string {
	return map[string]string{"error": err.Error()}
}
