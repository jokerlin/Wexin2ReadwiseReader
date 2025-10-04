package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/jokerlin/Wexin2ReadwiseReader/internal/app"
	"github.com/jokerlin/Wexin2ReadwiseReader/internal/config"
	"github.com/jokerlin/Wexin2ReadwiseReader/internal/wechat"
)

const maxBodySize = 1 << 20 // 1 MiB safety limit

// Handler implements the WeChat KF webhook supporting signature verification and message sync.
const routeTag = "route=/api/wx_kf_webhook"

func Handler(w http.ResponseWriter, r *http.Request) {
	logger := log.Default()

	cfg, err := config.FromEnv()
	if err != nil {
		logger.Printf("ERROR %s configuration error: %v", routeTag, err)
		httpError(w, http.StatusInternalServerError, "configuration invalid")
		return
	}

	switch r.Method {
	case http.MethodGet:
		handleVerification(w, r, cfg, logger)
	case http.MethodPost:
		handleCallback(w, r, cfg, logger)
	default:
		httpError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handleVerification(w http.ResponseWriter, r *http.Request, cfg config.Config, logger *log.Logger) {
	q := r.URL.Query()
	echostr := q.Get("echostr")
	timestamp := q.Get("timestamp")
	nonce := q.Get("nonce")

	if echostr == "" {
		respondJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "wechat kf webhook"})
		return
	}

	if timestamp == "" || nonce == "" {
		httpError(w, http.StatusBadRequest, "timestamp and nonce required")
		return
	}

	msgSignature := q.Get("msg_signature")
	signature := q.Get("signature")

	switch {
	case msgSignature != "":
		if !wechat.VerifyMessageSignature(cfg.WechatToken, msgSignature, timestamp, nonce, echostr) {
			httpError(w, http.StatusUnauthorized, "msg signature mismatch")
			return
		}
		if cfg.WechatEncodingAESKey == "" || cfg.WechatCorpID == "" {
			httpError(w, http.StatusInternalServerError, "encryption keys not configured")
			return
		}
		crypter, err := wechat.NewCrypter(cfg.WechatEncodingAESKey, cfg.WechatCorpID)
		if err != nil {
			logger.Printf("ERROR %s crypter init failed: %v", routeTag, err)
			httpError(w, http.StatusInternalServerError, "decoder init failed")
			return
		}
		plain, err := crypter.DecryptEchoString(echostr)
		if err != nil {
			logger.Printf("ERROR %s echostr decrypt failed: %v", routeTag, err)
			httpError(w, http.StatusInternalServerError, "decrypt failed")
			return
		}
		respondText(w, http.StatusOK, plain)

	case signature != "":
		if !wechat.VerifySignature(cfg.WechatToken, signature, timestamp, nonce) {
			httpError(w, http.StatusUnauthorized, "signature mismatch")
			return
		}
		respondText(w, http.StatusOK, echostr)

	default:
		httpError(w, http.StatusBadRequest, "missing signature parameters")
	}
}

func handleCallback(w http.ResponseWriter, r *http.Request, cfg config.Config, logger *log.Logger) {
	defer r.Body.Close()
	limited := io.LimitReader(r.Body, maxBodySize)
	body, err := io.ReadAll(limited)
	if err != nil {
		httpError(w, http.StatusBadRequest, "unable to read body")
		return
	}

	timestamp := r.URL.Query().Get("timestamp")
	nonce := r.URL.Query().Get("nonce")
	if timestamp == "" || nonce == "" {
		httpError(w, http.StatusBadRequest, "timestamp and nonce required")
		return
	}

	msgSignature := r.URL.Query().Get("msg_signature")
	if msgSignature != "" {
		handleEncryptedCallback(w, r.Context(), cfg, msgSignature, timestamp, nonce, body, logger)
		return
	}

	signature := r.URL.Query().Get("signature")
	if signature == "" {
		httpError(w, http.StatusBadRequest, "signature required")
		return
	}
	if !wechat.VerifySignature(cfg.WechatToken, signature, timestamp, nonce) {
		httpError(w, http.StatusUnauthorized, "signature mismatch")
		return
	}

	// Plain payload fallback (rare for enterprise wechat but handled defensively).
	if err := processPayload(r.Context(), cfg, body, logger); err != nil {
		logger.Printf("ERROR %s payload processing failed: %v", routeTag, err)
		httpError(w, http.StatusInternalServerError, "processing failed")
		return
	}
	respondText(w, http.StatusOK, "success")
}

func handleEncryptedCallback(w http.ResponseWriter, ctx context.Context, cfg config.Config, msgSignature, timestamp, nonce string, body []byte, logger *log.Logger) {
	encrypted, _, err := wechat.ExtractEncryptedField(body)
	if err != nil {
		logger.Printf("ERROR %s encrypted field missing: %v", routeTag, err)
		httpError(w, http.StatusBadRequest, "encrypted field missing")
		return
	}

	if !wechat.VerifyMessageSignature(cfg.WechatToken, msgSignature, timestamp, nonce, encrypted) {
		httpError(w, http.StatusUnauthorized, "msg signature mismatch")
		return
	}

	if cfg.WechatEncodingAESKey == "" {
		httpError(w, http.StatusInternalServerError, "encoding aes key missing")
		return
	}

	crypter, err := wechat.NewCrypter(cfg.WechatEncodingAESKey, cfg.WechatCorpID)
	if err != nil {
		logger.Printf("ERROR %s crypter init failed: %v", routeTag, err)
		httpError(w, http.StatusInternalServerError, "decoder init failed")
		return
	}

	decrypted, err := crypter.Decrypt(encrypted)
	if err != nil {
		logger.Printf("ERROR %s decrypt failed: %v", routeTag, err)
		httpError(w, http.StatusInternalServerError, "decrypt failed")
		return
	}

	if err := processPayload(ctx, cfg, decrypted, logger); err != nil {
		logger.Printf("ERROR %s payload processing failed: %v", routeTag, err)
		httpError(w, http.StatusInternalServerError, "processing failed")
		return
	}

	respondText(w, http.StatusOK, "success")
}

func processPayload(ctx context.Context, cfg config.Config, payload []byte, logger *log.Logger) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	processor := app.NewProcessor(cfg, logger)
	if processor == nil {
		return errors.New("processor init failed")
	}

	if err := processor.ProcessDecryptedPayload(ctx, payload); err != nil {
		return err
	}
	return nil
}

func httpError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]any{"error": message})
}

func respondJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func respondText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}
