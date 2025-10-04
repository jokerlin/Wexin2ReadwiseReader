package app

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/jokerlin/Wexin2ReadwiseReader/internal/config"
	"github.com/jokerlin/Wexin2ReadwiseReader/internal/kv"
	"github.com/jokerlin/Wexin2ReadwiseReader/internal/readwise"
	"github.com/jokerlin/Wexin2ReadwiseReader/internal/wechat"
)

// Processor coordinates interactions between WeChat, KV storage, and Readwise.
type Processor struct {
	cfg          config.Config
	wechatClient *wechat.APIClient
	kvClient     *kv.Client
	readwise     *readwise.Client
	logger       *log.Logger
}

// NewProcessor builds a processor from configuration.
func NewProcessor(cfg config.Config, logger *log.Logger) *Processor {
	if logger == nil {
		logger = log.Default()
	}

	return &Processor{
		cfg:          cfg,
		wechatClient: wechat.NewAPIClient(cfg.WechatCorpID, cfg.WechatKFSecret, cfg.HTTPClientTimeout),
		kvClient:     kv.New(cfg.KVRestAPIURL, cfg.KVRestAPIToken, cfg.KVClientTimeout),
		readwise:     readwise.NewClient(cfg.ReadwiseToken, cfg.HTTPClientTimeout),
		logger:       logger,
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

	accessToken, err := p.wechatClient.GetAccessToken(ctx)
	if err != nil {
		p.logger.Printf("ERROR fetch access token failed: %v", err)
		return err
	}

	cursorKey := cursorKeyForKf(tokenEnv.OpenKfID)
	var cursor string
	if p.kvClient != nil {
		cursor, err = p.kvClient.Get(ctx, cursorKey)
		if err != nil {
			p.logger.Printf("WARN cursor fetch failed: %v", err)
		}
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

	for _, msg := range syncResp.MsgList {
		if msg.MsgType == "link" && msg.Link.URL != "" {
			if err := p.readwise.SaveURL(ctx, msg.Link.URL, msg.Link.Title); err != nil {
				p.logger.Printf("WARN readwise save failed url=%s err=%v", msg.Link.URL, err)
			} else {
				p.logger.Printf("INFO readwise save ok url=%s", msg.Link.URL)
			}
		}
	}

	if syncResp.NextCursor != "" && p.kvClient != nil {
		if err := p.kvClient.Set(ctx, cursorKey, syncResp.NextCursor); err != nil {
			p.logger.Printf("WARN cursor persist failed: %v", err)
		}
	}

	return nil
}

func cursorKeyForKf(openKfID string) string {
	if openKfID == "" {
		return "wechat_kf_cursor:default"
	}
	return "wechat_kf_cursor:" + openKfID
}
