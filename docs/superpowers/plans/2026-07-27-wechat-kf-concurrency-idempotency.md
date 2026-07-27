# WeChat KF Concurrent Callback Idempotency Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent concurrent or retried WeChat KF callbacks from saving the same `msgid` to Readwise multiple times while allowing a new `msgid` for the same URL to be saved again.

**Architecture:** Serialize each `open_kfid` stream with an Upstash `SET NX EX` distributed lock, then record successfully saved `msgid` values with a seven-day TTL before advancing the shared cursor. Keep concrete HTTP clients behind small internal interfaces so concurrency, retry, and failure behavior can be exercised deterministically.

**Tech Stack:** Go 1.24.x, standard library HTTP/JSON/context/synchronization packages, Upstash Redis REST API, `httptest`, Go race detector.

## Global Constraints

- Preserve the existing behavior of inspecting only the last message returned by `sync_msg`.
- Use `wechat_kf_cursor:<suffix>`, `wechat_kf_sync_lock:<suffix>`, and `wechat_kf_processed:<suffix>:<msgid>` keys, where an empty `OpenKfId` maps to suffix `default`.
- Use a 15-second lock TTL and a seven-day processed-message TTL.
- A busy lock and all KV, WeChat, or Readwise failures must remain retryable processor errors.
- Do not add a queue, URL canonicalization, Readwise cleanup, or message pagination.
- Keep dependencies limited to the Go standard library and the modules already present in `go.mod`.

## File Map

- Modify `internal/kv/client.go`: add atomic lock acquisition, owner-safe release, and TTL-backed writes.
- Create `internal/kv/client_test.go`: verify exact Upstash REST commands and error handling.
- Modify `internal/app/processor.go`: introduce dependency interfaces, distributed locking, `msgid` markers, and fatal error propagation.
- Create `internal/app/processor_test.go`: hold reusable thread-safe fakes and processor behavior tests.
- Modify `README.md`: describe KV as required for concurrency safety and update troubleshooting.
- Modify `docs/ARCHITECTURE.md`: document lock/marker data flow, key names, and retry semantics.

---

### Task 1: Add atomic Upstash primitives

**Files:**
- Modify: `internal/kv/client.go:1-93`
- Create: `internal/kv/client_test.go`

**Interfaces:**
- Consumes: existing `kv.Client`, its REST URL/token configuration, and `context.Context`.
- Produces:
  - `func (c *Client) AcquireLock(ctx context.Context, key, owner string, ttl time.Duration) (bool, error)`
  - `func (c *Client) ReleaseLock(ctx context.Context, key, owner string) error`
  - `func (c *Client) SetWithTTL(ctx context.Context, key, value string, ttl time.Duration) error`

- [ ] **Step 1: Write failing REST-contract tests**

Create `internal/kv/client_test.go` in package `kv`. Use `httptest.Server` and literal expected commands:

```go
package kv

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAcquireLock(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		wantLocked bool
	}{
		{name: "acquired", response: `{"result":"OK"}`, wantLocked: true},
		{name: "busy", response: `{"result":null}`, wantLocked: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got, want := r.URL.EscapedPath(), "/set/lock:wk-1/owner-1/NX/EX/15"; got != want {
					t.Fatalf("path = %q, want %q", got, want)
				}
				if got, want := r.Header.Get("Authorization"), "Bearer token"; got != want {
					t.Fatalf("authorization = %q, want %q", got, want)
				}
				_, _ = io.WriteString(w, tt.response)
			}))
			defer server.Close()

			client := New(server.URL, "token", time.Second)
			locked, err := client.AcquireLock(context.Background(), "lock:wk-1", "owner-1", 15*time.Second)
			if err != nil {
				t.Fatalf("AcquireLock() error = %v", err)
			}
			if locked != tt.wantLocked {
				t.Fatalf("AcquireLock() = %v, want %v", locked, tt.wantLocked)
			}
		})
	}
}

func TestReleaseLockUsesOwnerCheckedLua(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		var command []any
		if err := json.NewDecoder(r.Body).Decode(&command); err != nil {
			t.Fatalf("decode command: %v", err)
		}
		if got, want := command[0], "EVAL"; got != want {
			t.Fatalf("command = %v, want %v", got, want)
		}
		script, ok := command[1].(string)
		if !ok || !strings.Contains(script, `redis.call("GET", KEYS[1])`) ||
			!strings.Contains(script, `redis.call("DEL", KEYS[1])`) {
			t.Fatalf("script is not owner-checked: %v", command[1])
		}
		if got, want := command[2], float64(1); got != want {
			t.Fatalf("key count = %v, want %v", got, want)
		}
		if got, want := command[3], "lock:wk-1"; got != want {
			t.Fatalf("key = %v, want %v", got, want)
		}
		if got, want := command[4], "owner-1"; got != want {
			t.Fatalf("owner = %v, want %v", got, want)
		}
		_, _ = io.WriteString(w, `{"result":1}`)
	}))
	defer server.Close()

	client := New(server.URL, "token", time.Second)
	if err := client.ReleaseLock(context.Background(), "lock:wk-1", "owner-1"); err != nil {
		t.Fatalf("ReleaseLock() error = %v", err)
	}
}

func TestSetWithTTL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.EscapedPath(), "/set/processed:wk-1:msg-1/1/EX/604800"; got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
		_, _ = io.WriteString(w, `{"result":"OK"}`)
	}))
	defer server.Close()

	client := New(server.URL, "token", time.Second)
	if err := client.SetWithTTL(
		context.Background(),
		"processed:wk-1:msg-1",
		"1",
		7*24*time.Hour,
	); err != nil {
		t.Fatalf("SetWithTTL() error = %v", err)
	}
}

func TestLockCommandsPropagateUpstashAndJSONErrors(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     string
	}{
		{name: "upstash", response: `{"error":"ERR denied"}`, want: "kv: ERR denied"},
		{name: "json", response: `{`, want: "unexpected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, tt.response)
			}))
			defer server.Close()

			client := New(server.URL, "token", time.Second)
			_, err := client.AcquireLock(context.Background(), "lock", "owner", time.Second)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("AcquireLock() error = %v, want substring %q", err, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run the new tests and verify RED**

Run:

```bash
GOCACHE=$(pwd)/.cache/go-build go test ./internal/kv -run 'Test(AcquireLock|ReleaseLock|SetWithTTL|LockCommands)' -count=1
```

Expected: compilation fails because `AcquireLock`, `ReleaseLock`, and `SetWithTTL` do not exist.

- [ ] **Step 3: Implement the minimal KV commands**

In `internal/kv/client.go`, add the `bytes` import, keep REST parsing local, and
use this owner-safe script:

```go
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
	endpoint := fmt.Sprintf(
		"%s/set/%s/%s/NX/EX/%d",
		c.baseURL,
		url.PathEscape(key),
		url.PathEscape(owner),
		seconds,
	)
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
	endpoint := fmt.Sprintf(
		"%s/set/%s/%s/EX/%d",
		c.baseURL,
		url.PathEscape(key),
		url.PathEscape(value),
		seconds,
	)
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
```

Retain the existing nil-safe behavior for `Get` and `Set`; `Processor` will reject a nil KV dependency before invoking these methods.

- [ ] **Step 4: Format and verify GREEN**

Run:

```bash
gofmt -w internal/kv/client.go internal/kv/client_test.go
GOCACHE=$(pwd)/.cache/go-build go test ./internal/kv -count=1
```

Expected: all `internal/kv` tests pass.

- [ ] **Step 5: Commit the atomic KV primitives**

```bash
git add internal/kv/client.go internal/kv/client_test.go
git commit -m "feat: add atomic kv lock operations"
```

---

### Task 2: Serialize processor work per OpenKfId

**Files:**
- Modify: `internal/app/processor.go:1-116`
- Create: `internal/app/processor_test.go`

**Interfaces:**
- Consumes: Task 1's `AcquireLock`, `ReleaseLock`, and `SetWithTTL` methods.
- Produces:
  - `var ErrSyncInProgress error`
  - Internal `wechatService`, `kvStore`, and `readwiseService` interfaces.
  - Internal `func randomLockOwner() (string, error)`.
  - Key helpers `lockKeyForKf(string) string` and a shared `kfKeySuffix(string) string`.

- [ ] **Step 1: Write the failing concurrency test and thread-safe fakes**

Create `internal/app/processor_test.go` in package `app`. Define fakes that implement the exact internal interfaces:

```go
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jokerlin/Wexin2ReadwiseReader/internal/config"
	"github.com/jokerlin/Wexin2ReadwiseReader/internal/wechat"
)

var testPayload = []byte(`<xml><Token>callback-token</Token><OpenKfId>wk-1</OpenKfId></xml>`)

type fakeWechatService struct {
	mu        sync.Mutex
	responses []wechat.SyncResponse
	syncErr   error
	calls     int
	started   chan struct{}
	unblock   chan struct{}
	startOnce sync.Once
}

func (f *fakeWechatService) GetAccessToken(context.Context) (wechat.AccessToken, error) {
	return wechat.AccessToken{Token: "access-token"}, nil
}

func (f *fakeWechatService) SyncMessages(
	context.Context,
	string,
	wechat.SyncRequest,
) (wechat.SyncResponse, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.started != nil {
		f.startOnce.Do(func() { close(f.started) })
	}
	if f.unblock != nil {
		<-f.unblock
	}
	if f.syncErr != nil {
		return wechat.SyncResponse{}, f.syncErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.responses) == 0 {
		return wechat.SyncResponse{}, nil
	}
	response := f.responses[0]
	if len(f.responses) > 1 {
		f.responses = f.responses[1:]
	}
	return response, nil
}

type fakeKVStore struct {
	mu             sync.Mutex
	values         map[string]string
	ttls           map[string]time.Duration
	locks          map[string]string
	getErrFor      map[string]error
	setFailuresFor map[string]int
	setTTLFailure  error
	acquireErr     error
	releaseErr     error
}

func newFakeKVStore() *fakeKVStore {
	return &fakeKVStore{
		values:         make(map[string]string),
		ttls:           make(map[string]time.Duration),
		locks:          make(map[string]string),
		getErrFor:      make(map[string]error),
		setFailuresFor: make(map[string]int),
	}
}

func (f *fakeKVStore) Get(_ context.Context, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.getErrFor[key]; err != nil {
		return "", err
	}
	return f.values[key], nil
}

func (f *fakeKVStore) Set(_ context.Context, key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setFailuresFor[key] > 0 {
		f.setFailuresFor[key]--
		return errors.New("set failed")
	}
	f.values[key] = value
	return nil
}

func (f *fakeKVStore) SetWithTTL(_ context.Context, key, value string, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setTTLFailure != nil {
		return f.setTTLFailure
	}
	f.values[key] = value
	f.ttls[key] = ttl
	return nil
}

func (f *fakeKVStore) AcquireLock(_ context.Context, key, owner string, _ time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acquireErr != nil {
		return false, f.acquireErr
	}
	if _, exists := f.locks[key]; exists {
		return false, nil
	}
	f.locks[key] = owner
	return true, nil
}

func (f *fakeKVStore) ReleaseLock(_ context.Context, key, owner string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.releaseErr != nil {
		return f.releaseErr
	}
	if f.locks[key] == owner {
		delete(f.locks, key)
	}
	return nil
}

type fakeReadwiseService struct {
	mu    sync.Mutex
	urls  []string
	err   error
}

func (f *fakeReadwiseService) SaveURL(_ context.Context, pageURL, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.urls = append(f.urls, pageURL)
	return nil
}

func testProcessor(
	wechatClient wechatService,
	kvClient kvStore,
	readwiseClient readwiseService,
) *Processor {
	var owners atomic.Int64
	return &Processor{
		cfg: config.Config{
			HTTPClientTimeout: time.Second,
			KVClientTimeout:   time.Second,
		},
		wechatClient: wechatClient,
		kvClient:     kvClient,
		readwise:     readwiseClient,
		logger:       log.New(io.Discard, "", 0),
		newLockOwner: func() (string, error) {
			return fmt.Sprintf("owner-%d", owners.Add(1)), nil
		},
	}
}

func linkResponse(msgID, pageURL, nextCursor string) wechat.SyncResponse {
	return wechat.SyncResponse{
		NextCursor: nextCursor,
		MsgList: []wechat.Message{{
			MsgID:   msgID,
			MsgType: "link",
			Link:    wechat.MessageLink{URL: pageURL, Title: "Article"},
		}},
	}
}

func TestProcessDecryptedPayloadSerializesConcurrentCallbacks(t *testing.T) {
	started := make(chan struct{})
	unblock := make(chan struct{})
	wechatClient := &fakeWechatService{
		responses: []wechat.SyncResponse{linkResponse("msg-1", "https://example.com/article", "cursor-1")},
		started:   started,
		unblock:   unblock,
	}
	kvClient := newFakeKVStore()
	readwiseClient := &fakeReadwiseService{}
	processor := testProcessor(wechatClient, kvClient, readwiseClient)

	firstErr := make(chan error, 1)
	go func() {
		firstErr <- processor.ProcessDecryptedPayload(context.Background(), testPayload)
	}()
	<-started

	secondErr := processor.ProcessDecryptedPayload(context.Background(), testPayload)
	if !errors.Is(secondErr, ErrSyncInProgress) {
		t.Fatalf("second call error = %v, want ErrSyncInProgress", secondErr)
	}
	close(unblock)
	if err := <-firstErr; err != nil {
		t.Fatalf("first call error = %v", err)
	}

	readwiseClient.mu.Lock()
	defer readwiseClient.mu.Unlock()
	if got, want := len(readwiseClient.urls), 1; got != want {
		t.Fatalf("Readwise saves = %d, want %d", got, want)
	}
}

func TestProcessDecryptedPayloadRequiresKV(t *testing.T) {
	wechatClient := &fakeWechatService{}
	readwiseClient := &fakeReadwiseService{}
	processor := testProcessor(wechatClient, nil, readwiseClient)

	err := processor.ProcessDecryptedPayload(context.Background(), testPayload)
	if err == nil || err.Error() != "kv client not configured" {
		t.Fatalf("error = %v, want kv client not configured", err)
	}
	if wechatClient.calls != 0 {
		t.Fatalf("sync calls = %d, want 0", wechatClient.calls)
	}
}

func TestProcessDecryptedPayloadPropagatesLockAndCursorReadErrors(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fakeKVStore)
	}{
		{
			name: "lock acquisition",
			setup: func(kv *fakeKVStore) {
				kv.acquireErr = errors.New("lock failed")
			},
		},
		{
			name: "cursor read",
			setup: func(kv *fakeKVStore) {
				kv.getErrFor["wechat_kf_cursor:wk-1"] = errors.New("get failed")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kvClient := newFakeKVStore()
			tt.setup(kvClient)
			processor := testProcessor(
				&fakeWechatService{},
				kvClient,
				&fakeReadwiseService{},
			)
			if err := processor.ProcessDecryptedPayload(context.Background(), testPayload); err == nil {
				t.Fatal("ProcessDecryptedPayload() error = nil, want non-nil")
			}
		})
	}
}

func TestProcessDecryptedPayloadIgnoresLockReleaseFailure(t *testing.T) {
	wechatClient := &fakeWechatService{responses: []wechat.SyncResponse{{}}}
	kvClient := newFakeKVStore()
	kvClient.releaseErr = errors.New("release failed")
	processor := testProcessor(wechatClient, kvClient, &fakeReadwiseService{})

	if err := processor.ProcessDecryptedPayload(context.Background(), testPayload); err != nil {
		t.Fatalf("ProcessDecryptedPayload() error = %v", err)
	}
}
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```bash
GOCACHE=$(pwd)/.cache/go-build go test ./internal/app -run TestProcessDecryptedPayload -count=1
```

Expected: compilation fails because the service interfaces, `newLockOwner`, and `ErrSyncInProgress` do not exist and `Processor` still requires concrete clients.

- [ ] **Step 3: Introduce interfaces and distributed locking**

In `internal/app/processor.go`, define the interfaces from the fake method sets and update `Processor` fields:

```go
var ErrSyncInProgress = errors.New("wechat kf sync already in progress")

const syncLockTTL = 15 * time.Second

type wechatService interface {
	GetAccessToken(context.Context) (wechat.AccessToken, error)
	SyncMessages(context.Context, string, wechat.SyncRequest) (wechat.SyncResponse, error)
}

type kvStore interface {
	Get(context.Context, string) (string, error)
	Set(context.Context, string, string) error
	SetWithTTL(context.Context, string, string, time.Duration) error
	AcquireLock(context.Context, string, string, time.Duration) (bool, error)
	ReleaseLock(context.Context, string, string) error
}

type readwiseService interface {
	SaveURL(context.Context, string, string) error
}

type Processor struct {
	cfg          config.Config
	wechatClient wechatService
	kvClient     kvStore
	readwise     readwiseService
	logger       *log.Logger
	newLockOwner func() (string, error)
}
```

Set `newLockOwner: randomLockOwner` in `NewProcessor`. Implement a 128-bit random owner:

```go
func randomLockOwner() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate lock owner: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
```

After payload/client validation and after creating the bounded processor context, fail closed on nil KV, generate an owner, acquire the per-stream lock, and install owner-safe cleanup before reading the cursor:

```go
if p.kvClient == nil {
	return errors.New("kv client not configured")
}
owner, err := p.newLockOwner()
if err != nil {
	return err
}
lockKey := lockKeyForKf(tokenEnv.OpenKfID)
locked, err := p.kvClient.AcquireLock(ctx, lockKey, owner, syncLockTTL)
if err != nil {
	return fmt.Errorf("acquire sync lock: %w", err)
}
if !locked {
	return ErrSyncInProgress
}
defer func() {
	releaseCtx, releaseCancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		p.cfg.KVClientTimeout,
	)
	defer releaseCancel()
	if err := p.kvClient.ReleaseLock(releaseCtx, lockKey, owner); err != nil {
		p.logger.Printf("WARN sync lock release failed: %v", err)
	}
}()
```

Make cursor reads fatal:

```go
cursor, err := p.kvClient.Get(ctx, cursorKey)
if err != nil {
	return fmt.Errorf("fetch cursor: %w", err)
}
```

Use a common suffix helper for cursor and lock keys:

```go
func kfKeySuffix(openKfID string) string {
	if openKfID == "" {
		return "default"
	}
	return openKfID
}

func cursorKeyForKf(openKfID string) string {
	return "wechat_kf_cursor:" + kfKeySuffix(openKfID)
}

func lockKeyForKf(openKfID string) string {
	return "wechat_kf_sync_lock:" + kfKeySuffix(openKfID)
}
```

- [ ] **Step 4: Format and verify GREEN**

Run:

```bash
gofmt -w internal/app/processor.go internal/app/processor_test.go
GOCACHE=$(pwd)/.cache/go-build go test ./internal/app -count=1
GOCACHE=$(pwd)/.cache/go-build go test -race ./internal/app -count=1
```

Expected: both commands pass and the race detector reports no races.

- [ ] **Step 5: Commit stream serialization**

```bash
git add internal/app/processor.go internal/app/processor_test.go
git commit -m "fix: serialize wechat callback processing"
```

---

### Task 3: Add `msgid` completion markers and retry-safe failures

**Files:**
- Modify: `internal/app/processor.go`
- Modify: `internal/app/processor_test.go`

**Interfaces:**
- Consumes: Task 2's interfaces and locking flow.
- Produces:
  - `const processedMessageTTL = 7 * 24 * time.Hour`
  - `func processedKeyForMessage(openKfID, msgID string) string`
  - Fatal propagation for marker reads/writes, Readwise saves, and cursor writes.

- [ ] **Step 1: Write failing marker and retry tests**

Append these tests to `internal/app/processor_test.go`:

```go
func TestProcessDecryptedPayloadSkipsCompletedMessage(t *testing.T) {
	wechatClient := &fakeWechatService{
		responses: []wechat.SyncResponse{linkResponse("msg-1", "https://example.com/article", "cursor-1")},
	}
	kvClient := newFakeKVStore()
	kvClient.values["wechat_kf_processed:wk-1:msg-1"] = "1"
	readwiseClient := &fakeReadwiseService{}
	processor := testProcessor(wechatClient, kvClient, readwiseClient)

	if err := processor.ProcessDecryptedPayload(context.Background(), testPayload); err != nil {
		t.Fatalf("ProcessDecryptedPayload() error = %v", err)
	}
	if got := len(readwiseClient.urls); got != 0 {
		t.Fatalf("Readwise saves = %d, want 0", got)
	}
	if got, want := kvClient.values["wechat_kf_cursor:wk-1"], "cursor-1"; got != want {
		t.Fatalf("cursor = %q, want %q", got, want)
	}
}

func TestProcessDecryptedPayloadRetriesCursorWithoutResaving(t *testing.T) {
	response := linkResponse("msg-1", "https://example.com/article", "cursor-1")
	wechatClient := &fakeWechatService{responses: []wechat.SyncResponse{response, response}}
	kvClient := newFakeKVStore()
	kvClient.setFailuresFor["wechat_kf_cursor:wk-1"] = 1
	readwiseClient := &fakeReadwiseService{}
	processor := testProcessor(wechatClient, kvClient, readwiseClient)

	if err := processor.ProcessDecryptedPayload(context.Background(), testPayload); err == nil {
		t.Fatal("first call error = nil, want cursor persistence error")
	}
	if err := processor.ProcessDecryptedPayload(context.Background(), testPayload); err != nil {
		t.Fatalf("second call error = %v", err)
	}

	if got, want := len(readwiseClient.urls), 1; got != want {
		t.Fatalf("Readwise saves = %d, want %d", got, want)
	}
	if got, want := kvClient.values["wechat_kf_cursor:wk-1"], "cursor-1"; got != want {
		t.Fatalf("cursor = %q, want %q", got, want)
	}
	if got, want := kvClient.ttls["wechat_kf_processed:wk-1:msg-1"], 7*24*time.Hour; got != want {
		t.Fatalf("processed marker TTL = %s, want %s", got, want)
	}
}

func TestProcessDecryptedPayloadAllowsSameURLForDifferentMessageIDs(t *testing.T) {
	wechatClient := &fakeWechatService{responses: []wechat.SyncResponse{
		linkResponse("msg-1", "https://example.com/article", "cursor-1"),
		linkResponse("msg-2", "https://example.com/article", "cursor-2"),
	}}
	kvClient := newFakeKVStore()
	readwiseClient := &fakeReadwiseService{}
	processor := testProcessor(wechatClient, kvClient, readwiseClient)

	for i := 0; i < 2; i++ {
		if err := processor.ProcessDecryptedPayload(context.Background(), testPayload); err != nil {
			t.Fatalf("call %d error = %v", i+1, err)
		}
	}
	if got, want := len(readwiseClient.urls), 2; got != want {
		t.Fatalf("Readwise saves = %d, want %d", got, want)
	}
}

func TestProcessDecryptedPayloadPropagatesStateAndSaveFailures(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fakeKVStore, *fakeReadwiseService)
	}{
		{
			name: "processed marker read",
			setup: func(kv *fakeKVStore, _ *fakeReadwiseService) {
				kv.getErrFor["wechat_kf_processed:wk-1:msg-1"] = errors.New("get failed")
			},
		},
		{
			name: "readwise save",
			setup: func(_ *fakeKVStore, reader *fakeReadwiseService) {
				reader.err = errors.New("save failed")
			},
		},
		{
			name: "processed marker write",
			setup: func(kv *fakeKVStore, _ *fakeReadwiseService) {
				kv.setTTLFailure = errors.New("set ttl failed")
			},
		},
		{
			name: "cursor write",
			setup: func(kv *fakeKVStore, _ *fakeReadwiseService) {
				kv.setFailuresFor["wechat_kf_cursor:wk-1"] = 1
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wechatClient := &fakeWechatService{
				responses: []wechat.SyncResponse{linkResponse("msg-1", "https://example.com/article", "cursor-1")},
			}
			kvClient := newFakeKVStore()
			readwiseClient := &fakeReadwiseService{}
			tt.setup(kvClient, readwiseClient)
			processor := testProcessor(wechatClient, kvClient, readwiseClient)

			if err := processor.ProcessDecryptedPayload(context.Background(), testPayload); err == nil {
				t.Fatal("ProcessDecryptedPayload() error = nil, want non-nil")
			}
		})
	}
}
```

- [ ] **Step 2: Run the marker tests and verify RED**

Run:

```bash
GOCACHE=$(pwd)/.cache/go-build go test ./internal/app -run 'TestProcessDecryptedPayload(Skips|Retries|Allows|PropagatesState)' -count=1
```

Expected failures:

- Completed messages are still sent to Readwise.
- Cursor-write and Readwise failures are swallowed.
- No processed-message key is written.

- [ ] **Step 3: Implement minimal marker and failure behavior**

Add the TTL and key helper:

```go
const processedMessageTTL = 7 * 24 * time.Hour

func processedKeyForMessage(openKfID, msgID string) string {
	return "wechat_kf_processed:" + kfKeySuffix(openKfID) + ":" + msgID
}
```

Replace the existing link-processing block with:

```go
if len(syncResp.MsgList) > 0 {
	msg := syncResp.MsgList[len(syncResp.MsgList)-1]
	if msg.MsgType == "link" && msg.Link.URL != "" {
		if msg.MsgID == "" {
			return errors.New("link message missing msgid")
		}
		processedKey := processedKeyForMessage(tokenEnv.OpenKfID, msg.MsgID)
		processed, err := p.kvClient.Get(ctx, processedKey)
		if err != nil {
			return fmt.Errorf("fetch processed marker: %w", err)
		}
		if processed != "" {
			p.logger.Printf("INFO duplicate message skipped msgid=%s", msg.MsgID)
		} else {
			if err := p.readwise.SaveURL(ctx, msg.Link.URL, msg.Link.Title); err != nil {
				return fmt.Errorf("save to readwise: %w", err)
			}
			if err := p.kvClient.SetWithTTL(ctx, processedKey, "1", processedMessageTTL); err != nil {
				return fmt.Errorf("persist processed marker: %w", err)
			}
			p.logger.Printf("INFO readwise save ok msgid=%s url=%s", msg.MsgID, msg.Link.URL)
		}
	}
}
```

Make cursor persistence fatal:

```go
if syncResp.NextCursor != "" {
	if err := p.kvClient.Set(ctx, cursorKey, syncResp.NextCursor); err != nil {
		return fmt.Errorf("persist cursor: %w", err)
	}
}
```

- [ ] **Step 4: Format and verify GREEN**

Run:

```bash
gofmt -w internal/app/processor.go internal/app/processor_test.go
GOCACHE=$(pwd)/.cache/go-build go test ./internal/app -count=1
GOCACHE=$(pwd)/.cache/go-build go test -race ./internal/app -count=1
```

Expected: all processor tests pass with no race reports.

- [ ] **Step 5: Commit message idempotency**

```bash
git add internal/app/processor.go internal/app/processor_test.go
git commit -m "fix: deduplicate wechat messages by msgid"
```

---

### Task 4: Document the operational contract and verify the repository

**Files:**
- Modify: `README.md:12-17,36-49,85-88`
- Modify: `docs/ARCHITECTURE.md:14-58`

**Interfaces:**
- Consumes: Tasks 1-3 behavior and key names.
- Produces: deployment documentation that treats KV as required for safe processing and explains retryable lock contention.

- [ ] **Step 1: Update user-facing documentation**

In `README.md`:

- Change the KV highlight to state that Upstash stores the cursor, distributed lock, and seven-day `msgid` markers.
- Replace the note that missing KV can still run with: missing KV makes webhook processing fail closed to prevent duplicate Readwise writes.
- Change troubleshooting to explain that a transient HTTP 500 may mean another callback owns the synchronization lock and WeChat should retry.

In `docs/ARCHITECTURE.md`:

- Insert lock acquisition before cursor reading in the POST flow.
- Insert processed-marker lookup/write around the Readwise call.
- State that KV, Readwise, and cursor errors propagate as HTTP 500.
- Replace “KV optional” and the future `msgid` extension note with the implemented lock/marker invariant.
- Document the three storage key shapes and their `default` suffix behavior.

- [ ] **Step 2: Check documentation and source formatting**

Run:

```bash
rg -n "KV 缓存可选|未配置 KV 时流程仍可运行|消息去重.*目前仅使用游标" README.md docs/ARCHITECTURE.md
git diff --check
```

Expected:

- `rg` returns no matches.
- `git diff --check` exits successfully.

- [ ] **Step 3: Run the complete verification suite**

Run:

```bash
gofmt -w internal/kv/client.go internal/kv/client_test.go internal/app/processor.go internal/app/processor_test.go
GOCACHE=$(pwd)/.cache/go-build go test ./... -count=1
GOCACHE=$(pwd)/.cache/go-build go test -race ./... -count=1
GOCACHE=$(pwd)/.cache/go-build go build ./...
git diff --check
git status --short
```

Expected:

- All tests pass.
- The race detector reports no races.
- The full build exits with status 0.
- `git diff --check` exits with status 0.
- Only the intended source, test, documentation, and plan files are modified or untracked.

- [ ] **Step 4: Review the final diff against the approved design**

Run:

```bash
git diff -- internal/kv/client.go internal/kv/client_test.go internal/app/processor.go internal/app/processor_test.go README.md docs/ARCHITECTURE.md
```

Confirm:

- Lock acquisition precedes cursor reading.
- A busy lock cannot reach WeChat sync or cursor writes.
- Readwise success precedes marker success, which precedes cursor advancement.
- Replayed `msgid` values skip Readwise.
- New `msgid` values remain eligible even when the URL matches.
- Lock release compares the stored owner before deletion.

- [ ] **Step 5: Commit documentation and final verification state**

```bash
git add README.md docs/ARCHITECTURE.md
git commit -m "docs: explain webhook idempotency"
```
