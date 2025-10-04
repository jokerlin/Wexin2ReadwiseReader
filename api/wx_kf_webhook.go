package handler

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/sha1"
    "encoding/base64"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "encoding/xml"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "sort"
    "strings"
)

// EncryptedMsg represents the XML structure of encrypted WeChat messages
type EncryptedMsg struct {
    XMLName      xml.Name `xml:"xml"`
    ToUserName   string   `xml:"ToUserName"`
    Encrypt      string   `xml:"Encrypt"`
    AgentID      string   `xml:"AgentID"`
}

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

// decryptMsg decrypts WeChat encrypted message using AES-256-CBC
func decryptMsg(encodingAESKey, corpID, encryptedData string) (string, error) {
    // Convert base64-encoded AES key to bytes
    aesKey, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
    if err != nil {
        return "", fmt.Errorf("invalid AES key: %w", err)
    }

    // Decode encrypted data
    cipherText, err := base64.StdEncoding.DecodeString(encryptedData)
    if err != nil {
        return "", fmt.Errorf("invalid encrypted data: %w", err)
    }

    // Create AES cipher
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return "", fmt.Errorf("failed to create cipher: %w", err)
    }

    // Decrypt using CBC mode
    if len(cipherText) < aes.BlockSize {
        return "", fmt.Errorf("ciphertext too short")
    }

    iv := aesKey[:aes.BlockSize]
    mode := cipher.NewCBCDecrypter(block, iv)
    plainText := make([]byte, len(cipherText))
    mode.CryptBlocks(plainText, cipherText)

    // Remove PKCS7 padding
    plainText, err = pkcs7Unpad(plainText)
    if err != nil {
        return "", fmt.Errorf("unpad failed: %w", err)
    }

    // Format: random(16) + msgLen(4) + msg + corpID
    if len(plainText) < 20 {
        return "", fmt.Errorf("decrypted data too short")
    }

    // Extract message length
    msgLen := binary.BigEndian.Uint32(plainText[16:20])
    if len(plainText) < int(20+msgLen) {
        return "", fmt.Errorf("invalid message length")
    }

    // Extract message
    msg := plainText[20 : 20+msgLen]

    // Verify corpID
    receivedCorpID := string(plainText[20+msgLen:])
    if receivedCorpID != corpID {
        return "", fmt.Errorf("corpID mismatch: expected %s, got %s", corpID, receivedCorpID)
    }

    return string(msg), nil
}

// pkcs7Unpad removes PKCS7 padding
func pkcs7Unpad(data []byte) ([]byte, error) {
    length := len(data)
    if length == 0 {
        return nil, fmt.Errorf("empty data")
    }
    padding := int(data[length-1])
    if padding < 1 || padding > aes.BlockSize || padding > length {
        return nil, fmt.Errorf("invalid padding")
    }
    return data[:length-padding], nil
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

        // Log original encrypted body
        fmt.Println("Encrypted body:", string(body))

        // Try to decrypt if it's an encrypted message
        var encMsg EncryptedMsg

        if err := xml.Unmarshal(body, &encMsg); err == nil && encMsg.Encrypt != "" {
            // This is an encrypted message
            encodingAESKey := strings.TrimSpace(os.Getenv("WECHAT_ENCODING_AES_KEY"))
            corpID := strings.TrimSpace(os.Getenv("WECHAT_CORPID"))
            if corpID == "" {
                corpID = strings.TrimSpace(os.Getenv("WECHAT_CORP_ID"))
            }

            if encodingAESKey != "" && corpID != "" {
                decrypted, err := decryptMsg(encodingAESKey, corpID, encMsg.Encrypt)
                if err != nil {
                    fmt.Println("Decryption failed:", err)
                } else {
                    fmt.Println("Decrypted message:", decrypted)
                }
            } else {
                fmt.Println("Missing WECHAT_ENCODING_AES_KEY or WECHAT_CORPID, cannot decrypt")
            }
        } else {
            fmt.Println("Not an encrypted message or XML parse failed")
        }

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
// Requires env: WECHAT_CORPID and WECHAT_KF_SECRET.
func logAccessTokenAsync() {
    corpid := os.Getenv("WECHAT_CORPID")
    if corpid == "" {
        corpid = os.Getenv("WECHAT_CORP_ID")
    }
    secret := os.Getenv("WECHAT_KF_SECRET")
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
