package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jokerlin/Wexin2ReadwiseReader/internal/config"
	"github.com/jokerlin/Wexin2ReadwiseReader/internal/kv"
	"github.com/jokerlin/Wexin2ReadwiseReader/internal/readwise"
	"github.com/jokerlin/Wexin2ReadwiseReader/internal/wechat"
)

var ErrSyncInProgress = errors.New("wechat kf sync already in progress")

const (
	syncLockTTL         = 15 * time.Second
	processedMessageTTL = 7 * 24 * time.Hour
)

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

// Processor coordinates interactions between WeChat, KV storage, and Readwise.
type Processor struct {
	cfg          config.Config
	wechatClient wechatService
	kvClient     kvStore
	readwise     readwiseService
	logger       *log.Logger
	newLockOwner func() (string, error)
}

// NewProcessor builds a processor from configuration.
func NewProcessor(cfg config.Config, logger *log.Logger) *Processor {
	if logger == nil {
		logger = log.Default()
	}
	var wechatClient wechatService
	if client := wechat.NewAPIClient(cfg.WechatCorpID, cfg.WechatKFSecret, cfg.HTTPClientTimeout); client != nil {
		wechatClient = client
	}
	var kvClient kvStore
	if client := kv.New(cfg.KVRestAPIURL, cfg.KVRestAPIToken, cfg.KVClientTimeout); client != nil {
		kvClient = client
	}
	var readwiseClient readwiseService
	if client := readwise.NewClient(cfg.ReadwiseToken, cfg.HTTPClientTimeout); client != nil {
		readwiseClient = client
	}

	return &Processor{
		cfg:          cfg,
		wechatClient: wechatClient,
		kvClient:     kvClient,
		readwise:     readwiseClient,
		logger:       logger,
		newLockOwner: randomLockOwner,
	}
}

// ProcessDecryptedPayload takes the decrypted webhook payload and triggers downstream syncing.
func (p *Processor) ProcessDecryptedPayload(ctx context.Context, payload []byte) error {
	if len(payload) == 0 {
		return errors.New("empty payload")
	}

	tokenEnv, err := wechat.ExtractTokenEnvelope(payload)
	if err != nil {
		p.logger.Printf("WARN payload missing token metadata: %v", err)
		return err
	}
	if tokenEnv.Token == "" {
		return errors.New("payload missing token")
	}

	if p.wechatClient == nil {
		return errors.New("wechat api client not configured")
	}
	if p.readwise == nil {
		return errors.New("readwise client not configured")
	}

	ctx, cancel := context.WithTimeout(ctx, p.cfg.HTTPClientTimeout+2*time.Second)
	defer cancel()

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

	accessToken, err := p.wechatClient.GetAccessToken(ctx)
	if err != nil {
		p.logger.Printf("ERROR fetch access token failed: %v", err)
		return err
	}

	cursorKey := cursorKeyForKf(tokenEnv.OpenKfID)
	cursor, err := p.kvClient.Get(ctx, cursorKey)
	if err != nil {
		return fmt.Errorf("fetch cursor: %w", err)
	}

	syncResp, err := p.wechatClient.SyncMessages(ctx, accessToken.Token, wechat.SyncRequest{
		Token:    tokenEnv.Token,
		Limit:    1000,
		Cursor:   cursor,
		OpenKfID: tokenEnv.OpenKfID,
		VoiceFmt: 0,
	})
	if err != nil {
		p.logger.Printf("ERROR sync messages failed: %v", err)
		return err
	}

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

	if syncResp.NextCursor != "" {
		if err := p.kvClient.Set(ctx, cursorKey, syncResp.NextCursor); err != nil {
			return fmt.Errorf("persist cursor: %w", err)
		}
	}

	return nil
}

func randomLockOwner() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate lock owner: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func kfKeySuffix(openKfID string) string {
	if openKfID == "" {
		return "default"
	}
	return openKfID
}

func cursorKeyForKf(openKfID string) string {
	return "wechat_kf_cursor:" + kfKeySuffix(openKfID)
}

func processedKeyForMessage(openKfID, msgID string) string {
	return "wechat_kf_processed:" + kfKeySuffix(openKfID) + ":" + msgID
}

func lockKeyForKf(openKfID string) string {
	return "wechat_kf_sync_lock:" + kfKeySuffix(openKfID)
}
