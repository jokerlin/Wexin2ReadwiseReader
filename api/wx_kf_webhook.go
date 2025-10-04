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
    "errors"
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
    key, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
    if err != nil {
        return nil, fmt.Errorf("decode aes key: %w", err)
    }
    if len(key) != 32 {
        return nil, fmt.Errorf("invalid aes key length: %d", len(key))
    }
    cipherData, err := base64.StdEncoding.DecodeString(b64Cipher)
    if err != nil {
        return nil, fmt.Errorf("decode cipher: %w", err)
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
        return nil, fmt.Errorf("unpad: %w", err)
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
    if wantAppID != "" && appID != wantAppID {
        return nil, fmt.Errorf("appid mismatch: got %s", appID)
    }
    if wantCorpID != "" && appID != wantCorpID {
        return nil, fmt.Errorf("corpid mismatch: got %s", appID)
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
            plain, err := decryptWeChat(er.Encrypt, encodingAESKey, appID, corpID)
            if err != nil {
                w.WriteHeader(http.StatusBadRequest)
                _ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "decrypt failed"})
                return
            }

            // Try parse as JSON, else return text
            var payload any
            dec := json.NewDecoder(bytes.NewReader(plain))
            dec.UseNumber()
            if err := dec.Decode(&payload); err != nil {
                payload = map[string]any{"raw": string(plain)}
            }
            payload = normalizeCreateTime(payload)

            // For WeCom callbacks a 200 with body "success" is sufficient and recommended.
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

        var payload any
        dec := json.NewDecoder(bytes.NewReader(body))
        dec.UseNumber()
        if err := dec.Decode(&payload); err != nil {
            payload = map[string]any{"raw": string(body)}
        }
        payload = normalizeCreateTime(payload)

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
