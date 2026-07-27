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
	if err := client.SetWithTTL(context.Background(), "processed:wk-1:msg-1", "1", 7*24*time.Hour); err != nil {
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
