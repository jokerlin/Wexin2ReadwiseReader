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
	XMLName    xml.Name `xml:"xml"`
	ToUserName string   `xml:"ToUserName"`
	Encrypt    string   `xml:"Encrypt"`
	AgentID    string   `xml:"AgentID"`
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
		return "", fmt.Errorf("invalid message length: need %d, have %d", 20+msgLen, len(plainText))
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
	if padding < 1 || padding > 32 {
		return nil, fmt.Errorf("invalid padding: %d", padding)
	}
	if padding > length {
		return nil, fmt.Errorf("padding size larger than data")
	}
	// Verify all padding bytes are the same
	for i := 0; i < padding; i++ {
		if data[length-1-i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding bytes")
		}
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
					fmt.Println("Decrypted XML:", decrypted)
					// Parse decrypted XML to extract token
					var decryptedMsg struct {
						Token    string `xml:"Token"`
						OpenKfId string `xml:"OpenKfId"`
					}
					if err := xml.Unmarshal([]byte(decrypted), &decryptedMsg); err != nil {
						fmt.Println("Failed to parse decrypted XML:", err)
					} else if decryptedMsg.Token == "" {
						fmt.Println("No token found in decrypted message")
					} else {
						fmt.Printf("Extracted token: %s, openKfId: %s\n", decryptedMsg.Token, decryptedMsg.OpenKfId)
						// Fetch messages asynchronously
						go syncKfMessages(corpID, decryptedMsg.Token, decryptedMsg.OpenKfId)
					}
				}
			} else {
				fmt.Println("Missing WECHAT_ENCODING_AES_KEY or WECHAT_CORPID, cannot decrypt")
			}
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

// syncKfMessages fetches messages from WeChat Kefu API using token from webhook
func syncKfMessages(corpID, token, openKfId string) {
	fmt.Printf("syncKfMessages called: corpID=%s, token=%s, openKfId=%s\n", corpID, token, openKfId)

	// Get access_token first
	secret := os.Getenv("WECHAT_KF_SECRET")
	if secret == "" {
		fmt.Println("syncKfMessages: missing WECHAT_KF_SECRET")
		return
	}

	fmt.Println("Getting access_token...")
	accessToken, _, err := getWeComAccessToken(corpID, secret)
	if err != nil {
		fmt.Println("syncKfMessages: failed to get access_token:", err)
		return
	}
	fmt.Println("Got access_token successfully")

	// Call sync_msg API
	endpoint := "https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token=" + accessToken

	reqBody := map[string]interface{}{
		"token":     token,
		"limit":     1000,
		"open_kfid": openKfId,
	}

	reqJSON, _ := json.Marshal(reqBody)
	fmt.Printf("Calling sync_msg API with body: %s\n", string(reqJSON))

	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(reqJSON))
	if err != nil {
		fmt.Println("syncKfMessages: request failed:", err)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	fmt.Println("syncKfMessages response:", string(respBody))
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
	fmt.Printf("Requesting access_token from: %s\n", u)

	resp, err := http.Get(u)
	if err != nil {
		fmt.Println("HTTP request error:", err)
		return "", 0, err
	}
	defer resp.Body.Close()

	fmt.Printf("Response status: %d\n", resp.StatusCode)

	var data struct {
		ErrCode     int    `json:"errcode"`
		ErrMsg      string `json:"errmsg"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		fmt.Println("JSON decode error:", err)
		return "", 0, err
	}

	fmt.Printf("API response: errcode=%d, errmsg=%s\n", data.ErrCode, data.ErrMsg)

	if data.ErrCode != 0 {
		return "", 0, fmt.Errorf("errcode=%d errmsg=%s", data.ErrCode, data.ErrMsg)
	}
	return data.AccessToken, data.ExpiresIn, nil
}
