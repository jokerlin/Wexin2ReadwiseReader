package kv

import (
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
    baseURL string
    token   string
    httpClient *http.Client
}

// New returns a new KV client or nil if the configuration is incomplete.
func New(baseURL, token string, timeout time.Duration) *Client {
    baseURL = strings.TrimRight(baseURL, "/")
    if baseURL == "" || token == "" {
        return nil
    }
    return &Client{
        baseURL: baseURL,
        token: token,
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

