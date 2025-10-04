package handler

import (
    "encoding/json"
    "net/http"
    "time"
)

// Handler is the entrypoint for Vercel Go serverless functions.
// It responds with a simple JSON payload for health checks.
func Handler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json; charset=utf-8")

    // Basic no-cache to avoid stale responses during testing
    w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")

    resp := map[string]any{
        "message": "pong",
        "time":    time.Now().UTC().Format(time.RFC3339Nano),
        "method":  r.Method,
        "path":    r.URL.Path,
    }

    _ = json.NewEncoder(w).Encode(resp)
}

