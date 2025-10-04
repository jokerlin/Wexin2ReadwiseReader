# Repository Guidelines

## Project Structure & Module Organization
- `api/` hosts Vercel entrypoints. `api/wx_kf_webhook/index.go` delegates to the reusable package handler, while `api/ping/index.go` stays a health probe.
- `pkg/wxkfwebhook/` contains the public HTTP handler that orchestrates signature checks, payload decryption, and downstream processing.
- `internal/` holds domain services: `config` (env loader), `app` (Processor), `wechat`, `readwise`, `kv`, and shared `httpx` helpers. Treat these as non-exported modules.
- `docs/` stores design notes such as `ARCHITECTURE.md`; update alongside significant behavior changes.

## Build, Test, and Development Commands
- `GOCACHE=$(pwd)/.cache/go-build go build ./...` compiles all packages without touching the host cache that Vercel disallows.
- `GOCACHE=$(pwd)/.cache/go-build go test ./...` runs the Go test suite (currently focused in `internal/wechat`).
- `go test ./internal/wechat -run TestDecrypt` helps when iterating on crypto utilities.

## Coding Style & Naming Conventions
- Target Go `1.24.x`. Use `gofmt -w` before committing; prefer organizing imports via `goimports` if available.
- Package names remain lower_snake (`wxkfwebhook`), files use lowercase with underscores only when improving clarity.
- Favor constructor-style helpers (e.g., `NewProcessor`, `NewClient`) and return early on error, matching existing patterns.

## Testing Guidelines
- Add `_test.go` files adjacent to the code under test. Table-driven tests are preferred for signature, crypto, and HTTP scenarios.
- Mock external services via lightweight fakes rather than network calls; reuse context timeouts from `config.Config` to mirror production.
- Aim to cover new branches around signature validation, KV persistence, and Readwise interactions.

## Commit & Pull Request Guidelines
- Follow the history convention: lowercase type prefix (`feat:`, `fix:`, `chore:`) plus a succinct imperative summary.
- Each PR should link relevant issues, describe configuration/env implications, and include log or test snippets when touching webhook flows.
- Screenshot or sample payloads are encouraged when altering handler responses to aid verification.

## Security & Configuration Tips
- Required env vars: `WECHAT_TOKEN`, optional but recommended `WECHAT_ENCODING_AES_KEY`, `WECHAT_CORPID`, `WECHAT_KF_SECRET`, `READWISE_TOKEN`, and KV credentials. Document new envs in `docs/`.
- Never commit real tokens. Use `.env.example` updates or inline comments to guide deployment teams.
