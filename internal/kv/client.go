package kv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client interacts with the Vercel KV (Upstash REST) API.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// New returns a new KV client or nil if the configuration is incomplete.
func New(baseURL, token string, timeout time.Duration) *Client {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" || token == "" {
		return nil
	}
	return &Client{
		baseURL:    baseURL,
		token:      token,
		httpClient: &http.Client{Timeout: timeout},
	}
}

// Get retrieves the value stored under key. Empty string is returned when key is missing.
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	if c == nil {
		return "", nil
	}

	endpoint := fmt.Sprintf("%s/get/%s", c.baseURL, url.PathEscape(key))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var payload struct {
		Result string `json:"result"`
		Error  string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if payload.Error != "" {
		return "", fmt.Errorf("kv: %s", payload.Error)
	}
	return payload.Result, nil
}

// Set stores the provided value under key.
func (c *Client) Set(ctx context.Context, key, value string) error {
	if c == nil {
		return nil
	}
	endpoint := fmt.Sprintf("%s/set/%s/%s", c.baseURL, url.PathEscape(key), url.PathEscape(value))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var payload struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if payload.Error != "" {
		return fmt.Errorf("kv: %s", payload.Error)
	}
	return nil
}

const releaseLockScript = `if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("DEL", KEYS[1]) else return 0 end`

func ttlSeconds(ttl time.Duration) (int64, error) {
	if ttl <= 0 {
		return 0, fmt.Errorf("kv: ttl must be positive")
	}
	return int64((ttl + time.Second - 1) / time.Second), nil
}

func (c *Client) AcquireLock(ctx context.Context, key, owner string, ttl time.Duration) (bool, error) {
	seconds, err := ttlSeconds(ttl)
	if err != nil {
		return false, err
	}
	endpoint := fmt.Sprintf("%s/set/%s/%s/NX/EX/%d", c.baseURL, url.PathEscape(key), url.PathEscape(owner), seconds)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var payload struct {
		Result *string `json:"result"`
		Error  string  `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, err
	}
	if payload.Error != "" {
		return false, fmt.Errorf("kv: %s", payload.Error)
	}
	return payload.Result != nil && *payload.Result == "OK", nil
}

func (c *Client) ReleaseLock(ctx context.Context, key, owner string) error {
	body, err := json.Marshal([]any{"EVAL", releaseLockScript, 1, key, owner})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var payload struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if payload.Error != "" {
		return fmt.Errorf("kv: %s", payload.Error)
	}
	return nil
}

func (c *Client) SetWithTTL(ctx context.Context, key, value string, ttl time.Duration) error {
	seconds, err := ttlSeconds(ttl)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/set/%s/%s/EX/%d", c.baseURL, url.PathEscape(key), url.PathEscape(value), seconds)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var payload struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if payload.Error != "" {
		return fmt.Errorf("kv: %s", payload.Error)
	}
	return nil
}
