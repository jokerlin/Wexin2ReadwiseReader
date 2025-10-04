package readwise

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
    "time"
)

// Client wraps interactions with the Readwise Reader API.
type Client struct {
    token string
    httpClient *http.Client
}

// NewClient returns a Client configured with the provided API token and timeout.
func NewClient(token string, timeout time.Duration) *Client {
    token = strings.TrimSpace(token)
    if token == "" {
        return nil
    }
    return &Client{
        token: token,
        httpClient: &http.Client{Timeout: timeout},
    }
}

// SaveURL sends the provided URL (and optional title) to Readwise Reader.
func (c *Client) SaveURL(ctx context.Context, pageURL, title string) error {
    if pageURL == "" {
        return fmt.Errorf("readwise: empty url")
    }
    if c == nil || c.httpClient == nil {
        return fmt.Errorf("readwise: uninitialised client")
    }
    payload := map[string]any{"url": pageURL}
    if title != "" {
        payload["title"] = title
    }
    body, err := json.Marshal(payload)
    if err != nil {
        return fmt.Errorf("readwise: encode payload: %w", err)
    }

    req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://readwise.io/api/v3/save/", bytes.NewReader(body))
    if err != nil {
        return fmt.Errorf("readwise: build request: %w", err)
    }
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Token "+c.token)

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("readwise: request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 400 {
        return fmt.Errorf("readwise: api returned status %d", resp.StatusCode)
    }
    return nil
}
