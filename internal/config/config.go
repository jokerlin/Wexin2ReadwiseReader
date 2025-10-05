package config

import (
    "errors"
    "fmt"
    "os"
    "strings"
    "sync"
    "time"
)

// Config holds runtime configuration resolved from environment variables.
type Config struct {
    WechatToken          string
    WechatEncodingAESKey string
    WechatCorpID         string
    WechatKFSecret       string
    ReadwiseToken        string

    KVRestAPIURL   string
    KVRestAPIToken string

    // HTTP timeouts that can be tuned via envs for integration calls.
    HTTPClientTimeout time.Duration
    KVClientTimeout   time.Duration
}

var (
    loaded Config
    once   sync.Once
    loadErr error
)

// FromEnv loads configuration once from the process environment, memoizing the result.
func FromEnv() (Config, error) {
    once.Do(func() {
        cfg := Config{
            WechatToken:          strings.TrimSpace(os.Getenv("WECHAT_TOKEN")),
            WechatEncodingAESKey: strings.TrimSpace(os.Getenv("WECHAT_ENCODING_AES_KEY")),
            WechatCorpID:         strings.TrimSpace(os.Getenv("WECHAT_CORPID")),
            WechatKFSecret:       strings.TrimSpace(os.Getenv("WECHAT_KF_SECRET")),
            ReadwiseToken:        strings.TrimSpace(os.Getenv("READWISE_TOKEN")),
            KVRestAPIURL:         strings.TrimSpace(os.Getenv("KV_REST_API_URL")),
            KVRestAPIToken:       strings.TrimSpace(os.Getenv("KV_REST_API_TOKEN")),
            HTTPClientTimeout:    parseDurationOrDefault(os.Getenv("HTTP_TIMEOUT"), 5*time.Second),
            KVClientTimeout:      parseDurationOrDefault(os.Getenv("KV_HTTP_TIMEOUT"), 3*time.Second),
        }

        if err := validate(cfg); err != nil {
            loadErr = err
            return
        }
        loaded = cfg
    })

    return loaded, loadErr
}

func parseDurationOrDefault(raw string, fallback time.Duration) time.Duration {
    raw = strings.TrimSpace(raw)
    if raw == "" {
        return fallback
    }
    d, err := time.ParseDuration(raw)
    if err != nil {
        return fallback
    }
    if d <= 0 {
        return fallback
    }
    return d
}

func validate(cfg Config) error {
    if cfg.WechatToken == "" {
        return errors.New("missing WECHAT_TOKEN environment variable")
    }
    if cfg.WechatEncodingAESKey != "" && len(cfg.WechatEncodingAESKey) != 43 {
        return fmt.Errorf("WECHAT_ENCODING_AES_KEY must be 43 chars when set; got %d", len(cfg.WechatEncodingAESKey))
    }
    return nil
}

// WithOverrides lets tests provide custom configuration without touching process env.
func WithOverrides(cfg Config) {
    once = sync.Once{}
    loaded = cfg
    loadErr = nil
}
