package handler

import (
    "crypto/sha1"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "sort"
    "strconv"
    "time"
)

// verifySignature verifies the WeChat signature (SHA1 of sorted token/timestamp/nonce).
// If token is empty, it skips verification and returns true for convenience during local dev.
func verifySignature(token, signature, timestamp, nonce string) bool {
    if token == "" {
        return true
    }
    parts := []string{token, timestamp, nonce}
    sort.Strings(parts)
    h := sha1.New()
    _, _ = io.WriteString(h, parts[0]+parts[1]+parts[2])
    sum := h.Sum(nil)
    calc := hex.EncodeToString(sum)
    return calc == signature
}

// Handler handles WeChat Kf webhook callbacks.
// - GET with `echostr` is used for URL verification.
// - POST receives JSON events/messages. We echo back the payload and format the time.
func Handler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")

    q := r.URL.Query()
    token := os.Getenv("WECHAT_TOKEN")

    switch r.Method {
    case http.MethodGet:
        echostr := q.Get("echostr")
        signature := q.Get("signature")
        if echostr == "" {
            w.WriteHeader(http.StatusOK)
            _ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "message": "wechat kf webhook"})
            return
        }

        if !verifySignature(token, signature, q.Get("timestamp"), q.Get("nonce")) {
            w.WriteHeader(http.StatusUnauthorized)
            _ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid signature"})
            return
        }

        // Echo back for URL verification
        // Although kf webhook may also use msg_signature in some modes, this simple handler
        // supports plaintext verification commonly used for initial connectivity checks.
        w.WriteHeader(http.StatusOK)
        _, _ = w.Write([]byte(echostr))
        return

    case http.MethodPost:
        body, err := io.ReadAll(r.Body)
        if err != nil {
            w.WriteHeader(http.StatusBadRequest)
            _ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "read body failed"})
            return
        }

        // Optionally verify signature for POST if present (plaintext mode). If you enable AES mode
        // you should switch to msg_signature verification and decrypt payload — omitted here for brevity.
        if sig := q.Get("signature"); sig != "" {
            if !verifySignature(token, sig, q.Get("timestamp"), q.Get("nonce")) {
                w.WriteHeader(http.StatusUnauthorized)
                _ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid signature"})
                return
            }
        }

        var payload map[string]any
        if err := json.Unmarshal(body, &payload); err != nil {
            // Some callbacks (e.g., AES) may not be JSON; return the raw string for inspection.
            payload = map[string]any{"raw": string(body)}
        }

        // Normalize/create a human-readable time derived from create_time when present.
        var tsRFC3339 string
        var tsInt64 int64
        if v, ok := payload["create_time"]; ok {
            switch t := v.(type) {
            case float64:
                // JSON numbers come as float64
                tsInt64 = int64(t)
            case string:
                if n, err := strconv.ParseInt(t, 10, 64); err == nil {
                    tsInt64 = n
                }
            }
        }
        if tsInt64 > 0 {
            tsRFC3339 = time.Unix(tsInt64, 0).UTC().Format(time.RFC3339)
            payload["create_time_rfc3339"] = tsRFC3339
        }

        resp := map[string]any{
            "ok":       true,
            "message":  "received",
            "method":   r.Method,
            "query":    q,
            "received": payload,
        }

        // WeChat expects 200 OK within a short timeout window.
        w.WriteHeader(http.StatusOK)
        _ = json.NewEncoder(w).Encode(resp)
        return

    default:
        w.WriteHeader(http.StatusMethodNotAllowed)
        _ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": fmt.Sprintf("method %s not allowed", r.Method)})
        return
    }
}

