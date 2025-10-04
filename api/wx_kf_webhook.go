package handler

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/sha1"
    "encoding/base64"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "encoding/xml"
    "errors"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "sort"
    "strconv"
    "strings"
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

func verifyMsgSignature(token, msgSignature, timestamp, nonce, encrypt string) bool {
    if token == "" {
        return true
    }
    parts := []string{token, timestamp, nonce, encrypt}
    sort.Strings(parts)
    h := sha1.New()
    _, _ = io.WriteString(h, parts[0]+parts[1]+parts[2]+parts[3])
    return hex.EncodeToString(h.Sum(nil)) == msgSignature
}

func pkcs7Unpad(plain []byte) ([]byte, error) {
    if len(plain) == 0 {
        return nil, errors.New("empty plain")
    }
    pad := int(plain[len(plain)-1])
    if pad == 0 || pad > aes.BlockSize || pad > len(plain) {
        return nil, errors.New("invalid padding")
    }
    for i := 0; i < pad; i++ {
        if plain[len(plain)-1-i] != byte(pad) {
            return nil, errors.New("bad padding content")
        }
    }
    return plain[:len(plain)-pad], nil
}

// decryptWeChat decrypts the base64 ciphertext using EncodingAESKey and validates appid/corpid suffix if provided.
func decryptWeChat(b64Cipher, encodingAESKey, wantAppID, wantCorpID string) ([]byte, error) {
    if encodingAESKey == "" {
        return nil, errors.New("missing encoding aes key")
    }
    // Trim possible accidental whitespaces when set via dashboard
    encodingAESKey = strings.TrimSpace(encodingAESKey)
    // Prefer RawStdEncoding to avoid padding pitfalls; EncodingAESKey should be 43 chars
    key, err := base64.RawStdEncoding.DecodeString(encodingAESKey)
    if err != nil {
        // Fallback to StdEncoding with '=' in case env contains 43 chars but decoder differs
        key2, err2 := base64.StdEncoding.DecodeString(encodingAESKey + "=")
        if err2 != nil {
            return nil, fmt.Errorf("decode aes key: %w / %v", err, err2)
        }
        key = key2
    }
    if len(key) != 32 {
        return nil, fmt.Errorf("invalid aes key length: %d", len(key))
    }
    // Cipher sometimes contains newlines; both decoders accept
    cipherData, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64Cipher))
    if err != nil {
        return nil, fmt.Errorf("decode cipher: %w", err)
    }
    if len(cipherData)%aes.BlockSize != 0 {
        // Log useful info for diagnostics
        fmt.Println("cipher len not block aligned:", len(cipherData))
    }
    iv := key[:16]
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("new cipher: %w", err)
    }
    if len(cipherData)%aes.BlockSize != 0 {
        return nil, errors.New("cipher not block aligned")
    }
    mode := cipher.NewCBCDecrypter(block, iv)
    plain := make([]byte, len(cipherData))
    mode.CryptBlocks(plain, cipherData)
    plain, err = pkcs7Unpad(plain)
    if err != nil {
        // Try a fallback: some producers prefix IV in the first 16 bytes of cipher.
        // WeChat shouldn't, but try to aid diagnostics.
        if len(cipherData) > aes.BlockSize {
            iv2 := cipherData[:aes.BlockSize]
            rest := cipherData[aes.BlockSize:]
            if len(rest)%aes.BlockSize == 0 {
                mode2 := cipher.NewCBCDecrypter(block, iv2)
                plain2 := make([]byte, len(rest))
                mode2.CryptBlocks(plain2, rest)
                if p2, e2 := pkcs7Unpad(plain2); e2 == nil {
                    fmt.Println("decrypt fallback with IV from cipher succeeded")
                    plain = p2
                    err = nil
                } else {
                    fmt.Println("decrypt fallback also failed:", e2)
                }
            }
        }
        if err != nil {
            // Emit short diagnostics without leaking plaintext
            if len(plain) >= 1 {
                fmt.Println("unpad failed; last byte=", int(plain[len(plain)-1]), "plain len=", len(plain))
            }
            return nil, fmt.Errorf("unpad: %w", err)
        }
    }
    if len(plain) < 20 {
        return nil, errors.New("plain too short")
    }
    // 16 bytes random, 4 bytes big-endian length, then msg, then appid/corpid
    content := plain[16:]
    if len(content) < 4 {
        return nil, errors.New("content too short")
    }
    msgLen := binary.BigEndian.Uint32(content[:4])
    if int(4+msgLen) > len(content) {
        return nil, errors.New("msg length out of range")
    }
    msg := content[4 : 4+msgLen]
    appID := string(content[4+msgLen:])
    // Accept either AppID or CorpID when both are provided; check only provided ones
    if wantAppID == "" && wantCorpID == "" {
        // no check
    } else {
        ok := false
        if wantAppID != "" && appID == wantAppID {
            ok = true
        }
        if wantCorpID != "" && appID == wantCorpID {
            ok = true
        }
        if !ok {
            return nil, fmt.Errorf("id mismatch: got %s", appID)
        }
    }
    return msg, nil
}

// Handler handles WeChat Kf webhook callbacks.
// - GET with `echostr` is used for URL verification.
// - POST receives JSON events/messages. We echo back the payload and format the time.
func Handler(w http.ResponseWriter, r *http.Request) {
    // Default to JSON for diagnostics, but for WeCom verification we will
    // override to text/plain to strictly match expectations.
    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")

    q := r.URL.Query()
    token := os.Getenv("WECHAT_TOKEN")
    encodingAESKey := os.Getenv("WECHAT_ENCODING_AES_KEY")
    appID := os.Getenv("WECHAT_APPID")
    corpID := os.Getenv("WECHAT_CORPID")

    switch r.Method {
    case http.MethodGet:
        if q.Get("diag") == "1" {
            // Safe diagnostics without leaking secrets
            info := map[string]any{
                "ok":                true,
                "message":           "diag",
                "has_token":         token != "",
                "has_encoding_aes":  encodingAESKey != "",
                "has_appid":         appID != "",
                "has_corpid":        corpID != "",
                "saw_msg_signature": q.Get("msg_signature") != "",
                "saw_signature":     q.Get("signature") != "",
            }
            _ = json.NewEncoder(w).Encode(info)
            return
        }
        echostr := q.Get("echostr")
        if echostr == "" {
            w.WriteHeader(http.StatusOK)
            _ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "message": "wechat kf webhook"})
            return
        }

        // Prefer OpenAPI/Work style: msg_signature with encrypted echostr
        if msig := q.Get("msg_signature"); msig != "" {
            if !verifyMsgSignature(token, msig, q.Get("timestamp"), q.Get("nonce"), echostr) {
                w.WriteHeader(http.StatusUnauthorized)
                _ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid msg_signature"})
                return
            }
            // Decrypt echostr and return the decrypted plain text
            if encodingAESKey == "" {
                // In rare cases of no AES key configured, just echo back as text
                w.Header().Set("Content-Type", "text/plain; charset=utf-8")
                w.WriteHeader(http.StatusOK)
                _, _ = w.Write([]byte(echostr))
                return
            }
            plain, err := decryptWeChat(echostr, encodingAESKey, appID, corpID)
            if err != nil {
                w.WriteHeader(http.StatusInternalServerError)
                _ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "decrypt echostr failed"})
                return
            }
            // WeCom expects the exact decrypted string with text/plain
            w.Header().Set("Content-Type", "text/plain; charset=utf-8")
            w.WriteHeader(http.StatusOK)
            _, _ = w.Write(plain)
            return
        }

        // Fallback: Official Account plaintext verification
        signature := q.Get("signature")
        if !verifySignature(token, signature, q.Get("timestamp"), q.Get("nonce")) {
            w.WriteHeader(http.StatusUnauthorized)
            _ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid signature"})
            return
        }
        // Public account plaintext verification path
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
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
        // Basic request diagnostics (no secrets)
        fmt.Println("POST /wx_kf_webhook", "qs has msg_signature:", q.Get("msg_signature") != "", "len(body):", len(body))

        // Detect encrypted OpenAPI payload {"encrypt":"..."}
        type encReq struct{ Encrypt string `json:"encrypt"` }
        var er encReq
        if json.Unmarshal(body, &er) == nil && er.Encrypt != "" {
            // Verify msg_signature for encrypted body
            msig := q.Get("msg_signature")
            if !verifyMsgSignature(token, msig, q.Get("timestamp"), q.Get("nonce"), er.Encrypt) {
                w.WriteHeader(http.StatusUnauthorized)
                _ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid msg_signature"})
                return
            }
            fmt.Println("encrypted JSON payload detected; encrypt len:", len(er.Encrypt))
            plain, err := decryptWeChat(er.Encrypt, encodingAESKey, appID, corpID)
            if err != nil {
                // Log and still ACK success to avoid repeated retries; but we cannot process downstream.
                fmt.Println("decrypt error json:", err)
                w.Header().Set("Content-Type", "text/plain; charset=utf-8")
                w.WriteHeader(http.StatusOK)
                _, _ = w.Write([]byte("success"))
                return
            }
            // Kick off async downstream handling (sync_msg + Readwise).
            go handleDecryptedCallback(plain)

            // For WeCom callbacks a 200 with body "success" is sufficient and recommended.
            w.Header().Set("Content-Type", "text/plain; charset=utf-8")
            w.WriteHeader(http.StatusOK)
            _, _ = w.Write([]byte("success"))
            return
        }

        // Detect encrypted XML payload: <xml><Encrypt>...</Encrypt></xml>
        type encXML struct {
            XMLName xml.Name `xml:"xml"`
            Encrypt string   `xml:"Encrypt"`
        }
        var ex encXML
        if xml.Unmarshal(body, &ex) == nil && ex.Encrypt != "" {
            // WeCom uses msg_signature over token,timestamp,nonce,encrypt
            msig := q.Get("msg_signature")
            if !verifyMsgSignature(token, msig, q.Get("timestamp"), q.Get("nonce"), ex.Encrypt) {
                w.WriteHeader(http.StatusUnauthorized)
                _, _ = w.Write([]byte("invalid msg_signature"))
                return
            }
            fmt.Println("encrypted XML payload detected; encrypt len:", len(ex.Encrypt))
            plain, err := decryptWeChat(ex.Encrypt, encodingAESKey, appID, corpID)
            if err != nil {
                fmt.Println("decrypt error xml:", err)
                w.Header().Set("Content-Type", "text/plain; charset=utf-8")
                w.WriteHeader(http.StatusOK)
                _, _ = w.Write([]byte("success"))
                return
            }
            // Async process and ack
            go handleDecryptedCallback(plain)
            w.Header().Set("Content-Type", "text/plain; charset=utf-8")
            w.WriteHeader(http.StatusOK)
            _, _ = w.Write([]byte("success"))
            return
        }

        // Plaintext mode: optionally verify signature
        if sig := q.Get("signature"); sig != "" {
            if !verifySignature(token, sig, q.Get("timestamp"), q.Get("nonce")) {
                w.WriteHeader(http.StatusUnauthorized)
                _ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid signature"})
                return
            }
        }

        // Plaintext mode: try to process as XML/JSON; then respond success
        go handleDecryptedCallback(body)

        // Plaintext mode: also respond with the canonical "success"
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
        w.WriteHeader(http.StatusOK)
        _, _ = w.Write([]byte("success"))
        return

    default:
        w.WriteHeader(http.StatusMethodNotAllowed)
        _ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": fmt.Sprintf("method %s not allowed", r.Method)})
        return
    }
}

// normalizeCreateTime walks simple JSON structures to add RFC3339 time when create_time present.
func normalizeCreateTime(v any) any {
    switch t := v.(type) {
    case map[string]any:
        // shallow only; nested events can be extended if needed
        if ct, ok := t["create_time"]; ok {
            var ts int64
            switch x := ct.(type) {
            case json.Number:
                if n, err := x.Int64(); err == nil {
                    ts = n
                }
            case float64:
                ts = int64(x)
            case string:
                if n, err := strconv.ParseInt(x, 10, 64); err == nil {
                    ts = n
                }
            }
            if ts > 0 {
                t["create_time_rfc3339"] = time.Unix(ts, 0).UTC().Format(time.RFC3339)
            }
        }
        return t
    default:
        return v
    }
}

// ===== Downstream processing: sync_msg + Readwise =====

// Minimal XML struct for kf_msg_or_event
type kfEventXML struct {
    XMLName     xml.Name `xml:"xml"`
    ToUserName  string   `xml:"ToUserName"`
    CreateTime  int64    `xml:"CreateTime"`
    MsgType     string   `xml:"MsgType"`
    Event       string   `xml:"Event"`
    Token       string   `xml:"Token"`
    OpenKfId    string   `xml:"OpenKfId"`
}

// handleDecryptedCallback parses the decrypted payload, pulls messages and sends URLs to Readwise.
func handleDecryptedCallback(plain []byte) {
    fmt.Println("handling decrypted callback; bytes:", len(plain))
    // 1) Try XML first
    var ev kfEventXML
    if err := xml.Unmarshal(plain, &ev); err == nil && strings.EqualFold(ev.Event, "kf_msg_or_event") {
        fmt.Println("parsed XML event; open_kfid:", ev.OpenKfId != "", "has token:", ev.Token != "")
        if ev.Token != "" {
            go syncAndPushToReadwise(ev.Token, ev.OpenKfId)
        }
        return
    }
    // 2) Try JSON form
    var m map[string]any
    if json.Unmarshal(plain, &m) == nil {
        if strings.EqualFold(getString(m["Event"]), "kf_msg_or_event") {
            tok := getString(m["Token"])
            open := getString(m["OpenKfId"]) // note camel case in docs; JSON may use snake too
            if tok == "" {
                tok = getString(m["token"]) // tolerate lower-case
            }
            if open == "" {
                open = getString(m["open_kfid"])
            }
            fmt.Println("parsed JSON event; open_kfid:", open != "", "has token:", tok != "")
            if tok != "" {
                go syncAndPushToReadwise(tok, open)
            }
        }
    }
}

func getString(v any) string {
    switch t := v.(type) {
    case string:
        return t
    case json.Number:
        return t.String()
    default:
        return ""
    }
}

// syncAndPushToReadwise fetches access_token, pulls messages, extracts URLs and pushes to Readwise.
func syncAndPushToReadwise(eventToken, openKfID string) {
    corpid := os.Getenv("WECHAT_CORPID")
    if corpid == "" {
        corpid = os.Getenv("WECHAT_CORP_ID")
    }
    secret := os.Getenv("WECHAT_KF_SECRET")
    if secret == "" {
        secret = os.Getenv("WECHAT_CORPSECRET")
    }
    if corpid == "" || secret == "" {
        fmt.Println("skip sync: missing corpid/secret")
        return
    }

    accessToken, _ := getWeComAccessToken(corpid, secret)
    if accessToken == "" {
        fmt.Println("gettoken failed")
        return
    }

    // Pull messages; try up to 1 page to keep fast
    msgs := syncWeComMessages(accessToken, eventToken, openKfID, 100)
    if len(msgs) == 0 {
        fmt.Println("sync_msg returned 0 messages")
        return
    }

    urls := extractURLsFromMessages(msgs)
    if len(urls) == 0 {
        fmt.Println("no url extracted from messages")
        return
    }

    rwToken := os.Getenv("READWISE_TOKEN")
    if rwToken == "" {
        rwToken = os.Getenv("READWISE_API_TOKEN")
    }
    if rwToken == "" {
        fmt.Println("missing READWISE token; skip push")
        return
    }
    for _, u := range urls {
        if err := saveToReadwise(rwToken, u); err != nil {
            fmt.Println("readwise save error:", err)
        } else {
            fmt.Println("readwise saved:", u)
        }
    }
}

func getWeComAccessToken(corpid, secret string) (string, error) {
    endpoint := "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
    values := url.Values{}
    values.Set("corpid", corpid)
    values.Set("corpsecret", secret)
    reqURL := endpoint + "?" + values.Encode()
    resp, err := http.Get(reqURL)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()
    var data struct {
        ErrCode     int    `json:"errcode"`
        ErrMsg      string `json:"errmsg"`
        AccessToken string `json:"access_token"`
        ExpiresIn   int    `json:"expires_in"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
        return "", err
    }
    if data.ErrCode != 0 {
        return "", fmt.Errorf("gettoken err: %d %s", data.ErrCode, data.ErrMsg)
    }
    return data.AccessToken, nil
}

// syncWeComMessages calls kf/sync_msg once.
func syncWeComMessages(accessToken, eventToken, openKfID string, limit int) []map[string]any {
    if limit <= 0 || limit > 1000 {
        limit = 100
    }
    endpoint := "https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token=" + url.QueryEscape(accessToken)
    payload := map[string]any{
        "token":        eventToken,
        "limit":        limit,
        "voice_format": 0,
    }
    if openKfID != "" {
        payload["open_kfid"] = openKfID
    }
    b, _ := json.Marshal(payload)
    req, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(b))
    req.Header.Set("Content-Type", "application/json")
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()
    var data struct {
        ErrCode   int                      `json:"errcode"`
        ErrMsg    string                   `json:"errmsg"`
        MsgList   []map[string]any         `json:"msg_list"`
        NextCursor string                  `json:"next_cursor"`
        HasMore   int                      `json:"has_more"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
        return nil
    }
    if data.ErrCode != 0 {
        fmt.Println("sync_msg err:", data.ErrCode, data.ErrMsg)
        return nil
    }
    return data.MsgList
}

var urlRegex = regexp.MustCompile(`https?://[\w\-\.\?\,\'/\\\+&%\$#_=:@]+`)

func extractURLsFromMessages(msgs []map[string]any) []string {
    var out []string
    seen := map[string]struct{}{}
    for _, m := range msgs {
        // Try link message
        if getString(m["msgtype"]) == "link" {
            if link, ok := m["link"].(map[string]any); ok {
                u := getString(link["url"])
                if u != "" {
                    if _, dup := seen[u]; !dup {
                        seen[u] = struct{}{}
                        out = append(out, u)
                    }
                    continue
                }
            }
        }
        // Try text content
        if t, ok := m["text"].(map[string]any); ok {
            content := getString(t["content"])
            if content != "" {
                found := urlRegex.FindAllString(content, -1)
                for _, u := range found {
                    if _, dup := seen[u]; !dup {
                        seen[u] = struct{}{}
                        out = append(out, u)
                    }
                }
            }
        }
    }
    return out
}

func saveToReadwise(token, urlStr string) error {
    api := "https://readwise.io/api/v3/save/"
    body := map[string]any{
        "url":          urlStr,
        "saved_using":  "wecom-kf-webhook",
        "should_clean_html": false,
        "category":     "article",
        "tags":         []string{"wecom", "kf"},
    }
    b, _ := json.Marshal(body)
    req, _ := http.NewRequest(http.MethodPost, api, bytes.NewReader(b))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Token "+token)
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    // Accept 200 or 201
    if resp.StatusCode != 200 && resp.StatusCode != 201 {
        io.Copy(io.Discard, resp.Body)
        return fmt.Errorf("readwise status %d", resp.StatusCode)
    }
    io.Copy(io.Discard, resp.Body)
    return nil
}
