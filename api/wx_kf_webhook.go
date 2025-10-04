package handler

import (
    "crypto/sha1"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "sort"
    "strings"
)

// verifySignature checks plain WeChat signature: sha1(sort(token,timestamp,nonce)).
// If token is empty, it returns true to ease local testing.
func verifySignature(token, signature, timestamp, nonce string) bool {
    if token == "" {
        return true
    }
    parts := []string{token, timestamp, nonce}
    sort.Strings(parts)
    h := sha1.New()
    io.WriteString(h, parts[0]+parts[1]+parts[2])
    calc := hex.EncodeToString(h.Sum(nil))
    return calc == signature
}

// Handler implements a minimal WeChat Kefu webhook.
// - GET: URL verification (plaintext). Echoes `echostr` as text/plain when signature matches.
// - POST: Accepts webhook body, forwards it to `/api/ping` as a query param, and replies `success`.
func Handler(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query()
    token := strings.TrimSpace(os.Getenv("WECHAT_TOKEN"))

    switch r.Method {
    case http.MethodGet:
        echostr := q.Get("echostr")
        // If no echostr, just provide a simple JSON info response.
        if echostr == "" {
            w.Header().Set("Content-Type", "application/json; charset=utf-8")
            _ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "route": "/api/wx_kf_webhook"})
            return
        }

        if !verifySignature(token, q.Get("signature"), q.Get("timestamp"), q.Get("nonce")) {
            w.WriteHeader(http.StatusUnauthorized)
            w.Header().Set("Content-Type", "text/plain; charset=utf-8")
            _, _ = w.Write([]byte("signature check failed"))
            return
        }
        // Verified: echo back echostr exactly as text/plain
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
        _, _ = w.Write([]byte(echostr))
        return

    case http.MethodPost:
        body, _ := io.ReadAll(r.Body)
        // Log body to Vercel logs (truncate to keep logs readable)
        preview := string(body)
        if len(preview) > 2048 {
            preview = preview[:2048] + "...<truncated>"
        }
        fmt.Println("wx_kf_webhook POST:", "len=", len(body), "preview=", preview)
        // Also try to fetch and log WeCom access_token if credentials are set
        go logAccessTokenAsync()
        // Forward the message body to /api/ping as a best-effort fire-and-forget.
        go forwardToPing(r, string(body))
        // WeChat expects quick ACK; reply with plaintext `success`.
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
        _, _ = w.Write([]byte("success"))
        return

    default:
        w.WriteHeader(http.StatusMethodNotAllowed)
        w.Header().Set("Content-Type", "application/json; charset=utf-8")
        _ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
        return
    }
}

// forwardToPing calls the sibling /api/ping endpoint with the webhook message as a query param.
func forwardToPing(r *http.Request, msg string) {
    host := r.Host
    if host == "" {
        return
    }
    // Derive scheme from headers (vercel sets X-Forwarded-Proto)
    scheme := "https"
    if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "http") {
        scheme = "http"
    }
    // Pass the raw body as `msg` (URL-encoded) and a small marker
    v := url.Values{}
    v.Set("from", "wx_kf_webhook")
    if msg != "" {
        // Truncate to avoid overly long URLs
        if len(msg) > 2000 {
            msg = msg[:2000]
        }
        v.Set("msg", msg)
    }
    pingURL := scheme + "://" + host + "/api/ping?" + v.Encode()
    req, err := http.NewRequest(http.MethodGet, pingURL, nil)
    if err != nil {
        return
    }
    req.Header.Set("User-Agent", "wx-kf-webhook/mini")
    // Best-effort request; ignore response and errors.
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return
    }
    io.Copy(io.Discard, resp.Body)
    resp.Body.Close()
}

// logAccessTokenAsync fetches the enterprise WeCom access_token and prints it.
// Requires env: WECHAT_CORPID and WECHAT_KF_SECRET (or WECHAT_CORPSECRET).
func logAccessTokenAsync() {
    corpid := os.Getenv("WECHAT_CORPID")
    if corpid == "" {
        corpid = os.Getenv("WECHAT_CORP_ID")
    }
    secret := os.Getenv("WECHAT_KF_SECRET")
    if secret == "" {
        secret = os.Getenv("WECHAT_CORPSECRET")
    }
    if corpid == "" || secret == "" {
        fmt.Println("gettoken skipped: missing WECHAT_CORPID/WECHAT_KF_SECRET envs")
        return
    }
    token, expiresIn, err := getWeComAccessToken(corpid, secret)
    if err != nil {
        fmt.Println("gettoken error:", err)
        return
    }
    // Print full token as requested; consider masking in production.
    fmt.Println("gettoken ok: access_token=", token, "expires_in=", expiresIn)
}

// getWeComAccessToken gets access_token via WeCom API.
func getWeComAccessToken(corpid, secret string) (string, int, error) {
    endpoint := "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
    v := url.Values{}
    v.Set("corpid", corpid)
    v.Set("corpsecret", secret)
    u := endpoint + "?" + v.Encode()
    resp, err := http.Get(u)
    if err != nil {
        return "", 0, err
    }
    defer resp.Body.Close()
    var data struct {
        ErrCode     int    `json:"errcode"`
        ErrMsg      string `json:"errmsg"`
        AccessToken string `json:"access_token"`
        ExpiresIn   int    `json:"expires_in"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
        return "", 0, err
    }
    if data.ErrCode != 0 {
        return "", 0, fmt.Errorf("errcode=%d errmsg=%s", data.ErrCode, data.ErrMsg)
    }
    return data.AccessToken, data.ExpiresIn, nil
}
