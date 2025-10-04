package wechat

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
    "time"
)

// APIClient wraps common WeCom Kefu API calls required by the application.
type APIClient struct {
    corpID string
    secret string
    httpClient *http.Client
}

// NewAPIClient constructs a client with the provided credentials. Returns nil when
// required credentials are missing so the caller can safely skip sync work.
func NewAPIClient(corpID, secret string, timeout time.Duration) *APIClient {
    if corpID == "" || secret == "" {
        return nil
    }
    return &APIClient{
        corpID: corpID,
        secret: secret,
        httpClient: &http.Client{Timeout: timeout},
    }
}

// AccessToken represents the token response from the WeCom API.
type AccessToken struct {
    Token     string
    ExpiresIn int
}

// GetAccessToken fetches a fresh access token.
func (c *APIClient) GetAccessToken(ctx context.Context) (AccessToken, error) {
    if c == nil {
        return AccessToken{}, fmt.Errorf("wechat api client unconfigured")
    }
    endpoint := "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
    values := url.Values{}
    values.Set("corpid", c.corpID)
    values.Set("corpsecret", c.secret)

    req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+values.Encode(), nil)
    if err != nil {
        return AccessToken{}, err
    }

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return AccessToken{}, err
    }
    defer resp.Body.Close()

    var payload struct {
        ErrCode     int    `json:"errcode"`
        ErrMsg      string `json:"errmsg"`
        AccessToken string `json:"access_token"`
        ExpiresIn   int    `json:"expires_in"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
        return AccessToken{}, err
    }
    if payload.ErrCode != 0 {
        return AccessToken{}, fmt.Errorf("wechat gettoken errcode=%d errmsg=%s", payload.ErrCode, payload.ErrMsg)
    }
    return AccessToken{Token: payload.AccessToken, ExpiresIn: payload.ExpiresIn}, nil
}

// SyncRequest is the payload sent to the sync_msg endpoint.
type SyncRequest struct {
    Token     string `json:"token"`
    Limit     int    `json:"limit"`
    Cursor    string `json:"cursor,omitempty"`
    OpenKfID  string `json:"open_kfid"`
    VoiceFmt  int    `json:"voice_format"`
}

// MessageLink represents the nested link payload inside messages.
type MessageLink struct {
    Title  string `json:"title"`
    Desc   string `json:"desc"`
    URL    string `json:"url"`
    PicURL string `json:"pic_url"`
}

// Message captures the subset of fields the application cares about.
type Message struct {
    MsgID    string      `json:"msgid"`
    MsgType  string      `json:"msgtype"`
    SendTime int64       `json:"send_time"`
    Link     MessageLink `json:"link"`
}

// SyncResponse is the response from the sync_msg endpoint.
type SyncResponse struct {
    ErrCode    int       `json:"errcode"`
    ErrMsg     string    `json:"errmsg"`
    NextCursor string    `json:"next_cursor"`
    HasMore    int       `json:"has_more"`
    MsgList    []Message `json:"msg_list"`
}

// SyncMessages retrieves messages from the WeChat Kefu API.
func (c *APIClient) SyncMessages(ctx context.Context, accessToken string, req SyncRequest) (SyncResponse, error) {
    if c == nil {
        return SyncResponse{}, fmt.Errorf("wechat api client unconfigured")
    }
    if accessToken == "" {
        return SyncResponse{}, fmt.Errorf("wechat: empty access token")
    }
    endpoint := "https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token=" + accessToken
    body, err := json.Marshal(req)
    if err != nil {
        return SyncResponse{}, err
    }
    httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
    if err != nil {
        return SyncResponse{}, err
    }
    httpReq.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(httpReq)
    if err != nil {
        return SyncResponse{}, err
    }
    defer resp.Body.Close()

    var payload SyncResponse
    if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
        return SyncResponse{}, err
    }
    if payload.ErrCode != 0 {
        return SyncResponse{}, fmt.Errorf("wechat sync_msg errcode=%d errmsg=%s", payload.ErrCode, payload.ErrMsg)
    }
    return payload, nil
}

// HasMorePages reports whether the API indicates additional messages are available.
func (resp SyncResponse) HasMorePages() bool {
    return resp.HasMore != 0 && resp.NextCursor != ""
}

