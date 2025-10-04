# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Vercel Go serverless application that integrates WeChat Work (企业微信) customer service webhooks with Readwise Reader. The system receives WeChat webhook callbacks, processes messages, and automatically saves link-type messages to Readwise Reader.

## Architecture

The codebase follows a clean architecture pattern:

- `api/` - Vercel serverless function entrypoints
  - `ping/` - Health check endpoint
  - `wx_kf_webhook/` - Main webhook handler
- `pkg/wxkfwebhook/` - Public HTTP handler package
- `internal/` - Domain services and business logic
  - `app/` - Processor orchestrating all services
  - `config/` - Environment variable loading and validation
  - `wechat/` - WeChat signature verification, AES encryption/decryption, message structures
  - `readwise/` - Readwise Reader API client
  - `kv/` - Upstash/Vercel KV storage client
  - `httpx/` - Shared HTTP utilities

## Development Commands

### Building and Testing
```bash
# Build all packages (uses local cache for Vercel compatibility)
GOCACHE=$(pwd)/.cache/go-build go build ./...

# Run all tests
GOCACHE=$(pwd)/.cache/go-build go test ./...

# Run specific test (e.g., crypto utilities)
go test ./internal/wechat -run TestDecrypt
```

### Local Development
```bash
# Install Vercel CLI
npm i -g vercel
vercel login

# Start local development server
vercel dev

# Endpoints:
# Health check: http://localhost:3000/api/ping  
# Webhook: http://localhost:3000/api/wx_kf_webhook
```

### Deployment
```bash
vercel            # Preview environment
vercel --prod     # Production environment
```

## Required Environment Variables

- `WECHAT_TOKEN` - WeChat callback token for signature verification
- `WECHAT_ENCODING_AES_KEY` - 43-character AES key for decryption
- `WECHAT_CORPID` / `WECHAT_CORP_ID` / `WECHAT_APPID` - Enterprise ID for verification
- `WECHAT_KF_SECRET` / `WECHAT_CORPSECRET` - Customer service secret for access tokens
- `READWISE_TOKEN` / `READWISE_API_TOKEN` - Readwise Reader API token
- `KV_REST_API_URL` - Vercel KV REST endpoint
- `KV_REST_API_TOKEN` - Vercel KV REST token

Optional:
- `HTTP_TIMEOUT` - External HTTP request timeout (default: 5s)
- `KV_HTTP_TIMEOUT` - KV request timeout (default: 3s)

## Key Workflow

1. WeChat sends webhook to `/api/wx_kf_webhook`
2. Handler verifies signature and decrypts payload if encrypted
3. Processor fetches access token and syncs messages from WeChat API
4. Link-type messages are filtered and sent to Readwise Reader
5. Cursor position is saved to KV store for incremental sync

## Security Features

- Mandatory signature verification using WeChat token
- AES-256-CBC decryption for encrypted callbacks
- Structured logging with key=value format
- Timeout controls for all external requests
- Error propagation to trigger WeChat retry mechanism

## Code Style

- Go 1.24.x target
- Use `gofmt -w` before committing
- Package names: lower_snake_case (`wxkfwebhook`)
- Constructor pattern: `NewProcessor`, `NewClient`
- Table-driven tests preferred
- Early return on errors