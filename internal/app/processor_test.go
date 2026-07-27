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
