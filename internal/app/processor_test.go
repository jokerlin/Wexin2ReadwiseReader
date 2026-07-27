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
	ctx context.Context,
	_ string,
	_ wechat.SyncRequest,
) (wechat.SyncResponse, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.started != nil {
		f.startOnce.Do(func() { close(f.started) })
	}
	if f.unblock != nil {
		select {
		case <-f.unblock:
		case <-ctx.Done():
			return wechat.SyncResponse{}, ctx.Err()
		}
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
	setCalls       int
	acquireCalls   int
	acquireKey     string
	acquireOwner   string
	acquireTTL     time.Duration
	releaseCalls   int
	releaseKey     string
	releaseOwner   string
	releaseCtxErr  error
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
	f.setCalls++
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

func (f *fakeKVStore) AcquireLock(_ context.Context, key, owner string, ttl time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acquireCalls++
	f.acquireKey = key
	f.acquireOwner = owner
	f.acquireTTL = ttl
	if f.acquireErr != nil {
		return false, f.acquireErr
	}
	if _, exists := f.locks[key]; exists {
		return false, nil
	}
	f.locks[key] = owner
	return true, nil
}

func (f *fakeKVStore) ReleaseLock(ctx context.Context, key, owner string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releaseCalls++
	f.releaseKey = key
	f.releaseOwner = owner
	f.releaseCtxErr = ctx.Err()
	if f.releaseErr != nil {
		return f.releaseErr
	}
	if f.locks[key] == owner {
		delete(f.locks, key)
	}
	return nil
}

type fakeReadwiseService struct {
	mu   sync.Mutex
	urls []string
	err  error
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

func waitForStarted(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("sync did not start")
	}
}

func waitForProcess(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		t.Fatal("ProcessDecryptedPayload did not return")
		return nil
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
	waitForStarted(t, started)

	kvClient.mu.Lock()
	firstOwner := kvClient.acquireOwner
	if got, want := kvClient.acquireKey, "wechat_kf_sync_lock:wk-1"; got != want {
		kvClient.mu.Unlock()
		t.Fatalf("lock key = %q, want %q", got, want)
	}
	if got, want := kvClient.acquireTTL, 15*time.Second; got != want {
		kvClient.mu.Unlock()
		t.Fatalf("lock TTL = %v, want %v", got, want)
	}
	kvClient.mu.Unlock()

	secondErr := processor.ProcessDecryptedPayload(context.Background(), testPayload)
	if !errors.Is(secondErr, ErrSyncInProgress) {
		t.Fatalf("second call error = %v, want ErrSyncInProgress", secondErr)
	}
	wechatClient.mu.Lock()
	if got, want := wechatClient.calls, 1; got != want {
		wechatClient.mu.Unlock()
		t.Fatalf("sync calls while lock is busy = %d, want %d", got, want)
	}
	wechatClient.mu.Unlock()
	kvClient.mu.Lock()
	if got, want := kvClient.setCalls, 0; got != want {
		kvClient.mu.Unlock()
		t.Fatalf("cursor writes while lock is busy = %d, want %d", got, want)
	}
	if got := kvClient.values["wechat_kf_cursor:wk-1"]; got != "" {
		kvClient.mu.Unlock()
		t.Fatalf("cursor while lock is busy = %q, want empty", got)
	}
	kvClient.mu.Unlock()
	close(unblock)
	if err := waitForProcess(t, firstErr); err != nil {
		t.Fatalf("first call error = %v", err)
	}

	readwiseClient.mu.Lock()
	defer readwiseClient.mu.Unlock()
	if got, want := len(readwiseClient.urls), 1; got != want {
		t.Fatalf("Readwise saves = %d, want %d", got, want)
	}

	kvClient.mu.Lock()
	if got, want := kvClient.releaseCalls, 1; got != want {
		kvClient.mu.Unlock()
		t.Fatalf("lock release calls = %d, want %d", got, want)
	}
	if got, want := kvClient.releaseKey, "wechat_kf_sync_lock:wk-1"; got != want {
		kvClient.mu.Unlock()
		t.Fatalf("released lock key = %q, want %q", got, want)
	}
	if got, want := kvClient.releaseOwner, firstOwner; got != want {
		kvClient.mu.Unlock()
		t.Fatalf("released lock owner = %q, want %q", got, want)
	}
	if got := kvClient.releaseCtxErr; got != nil {
		kvClient.mu.Unlock()
		t.Fatalf("release context error = %v, want nil", got)
	}
	kvClient.mu.Unlock()

	reacquired, err := kvClient.AcquireLock(context.Background(), "wechat_kf_sync_lock:wk-1", "next-owner", 15*time.Second)
	if err != nil {
		t.Fatalf("reacquire released lock: %v", err)
	}
	if !reacquired {
		t.Fatal("reacquire released lock = false, want true")
	}
}

func TestProcessDecryptedPayloadReleasesLockWithCancellationIndependentContext(t *testing.T) {
	started := make(chan struct{})
	wechatClient := &fakeWechatService{
		started: started,
		unblock: make(chan struct{}),
	}
	kvClient := newFakeKVStore()
	processor := testProcessor(wechatClient, kvClient, &fakeReadwiseService{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- processor.ProcessDecryptedPayload(ctx, testPayload)
	}()
	waitForStarted(t, started)
	cancel()

	if err := waitForProcess(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("ProcessDecryptedPayload() error = %v, want context.Canceled", err)
	}
	kvClient.mu.Lock()
	defer kvClient.mu.Unlock()
	if got, want := kvClient.releaseCalls, 1; got != want {
		t.Fatalf("lock release calls = %d, want %d", got, want)
	}
	if got := kvClient.releaseCtxErr; got != nil {
		t.Fatalf("release context error = %v, want nil", got)
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
