# 架构说明

本文档补充项目的模块划分、关键流程与安全考量，便于二次开发和运营。

## 1. 整体拓扑
```
WeCom -> /api/wx_kf_webhook -> Processor -> WeChat API
                                           -> Readwise API
                                           -> Vercel KV
```
1. 企业微信回调触发 `api/wx_kf_webhook`。
2. Handler 校验签名（支持 `signature` 与 `msg_signature`），并视情况解密回调体。
3. 解密后的 payload 交由 `internal/app.Processor`。
4. Processor 使用 Token/OpenKfId 调用 WeCom `sync_msg` 拉取会话消息；将链接消息推送给 Readwise；同时使用 KV 记录游标。

## 2. 模块职责
| 模块 | 作用 |
| ---- | ---- |
| `api/ping` | 健康检查；无外部依赖 |
| `api/wx_kf_webhook` | HTTP Handler，负责校验、解密、速返 `success` |
| `internal/config` | 装载环境变量、统一校验及默认值 |
| `internal/wechat` | 签名校验、AES 解密、消息结构体、WeCom API 封装 |
| `internal/readwise` | Readwise Reader API 客户端，仅负责 `POST /api/v3/save/` |
| `internal/kv` | Upstash/Vercel KV REST 客户端，存取游标 |
| `internal/app` | Processor，协调 KV / WeChat / Readwise 并输出结构化日志 |

## 3. Webhook 流程细节
1. **GET 校验**
   - 若存在 `msg_signature` 则视为加密回调；使用 AES Key + CorpID 解密 `echostr`。
   - 否则退回明文流程，直接基于 `signature` 校验。
   - 失败时返回 401/500，成功时以 `text/plain` 回显。
2. **POST 回调**
   - 限制 Body 最大 1 MiB，防止内存滥用。
   - 必须带 `timestamp`/`nonce`，并在加密场景下验证 `msg_signature`。
   - 解密后调用 `Processor.ProcessDecryptedPayload`：
     1. 拉取 access_token；
     2. 读取 KV 游标（可缺省）；
     3. 调用 `sync_msg` 获取消息；
     4. 过滤 `msgtype == link` 的消息并保存到 Readwise；
     5. 若返回 `next_cursor`，写回 KV。

## 4. 安全与鲁棒性
- **签名校验强制启用**：Token 为空时直接拒绝回调。
- **AES Key 校验**：长度必须为 43，初始化时即验证。
- **结构化日志**：标准库 `log.Printf` 采用 `level=... key=value` 格式，便于在 Vercel 上过滤错误类型。
- **错误传播策略**：只要任一关键步骤失败（获取 token、同步、保存游标），Handler 返回 500，使企业微信自动重试，避免数据丢失。
- **KV 缓存可选**：未配置 KV 时流程仍可运行，但会重复消费历史消息。
- **超时控制**：所有外部调用使用带超时的 `http.Client` 和 `context.WithTimeout`。

## 5. 测试与质量保证
- `internal/wechat/wechat_test.go` 覆盖签名与 AES 解密的典型/错误场景。
- 可以在本地运行 `go test ./...`（注意设置 `GOCACHE`）。
- 建议在 CI 中追加对 Handler 的集成测试（可通过 httptest + 假 KV/Readwise 客户端模拟）。

## 6. 常见扩展
- **非链接消息同步**：可在 Processor 中扩展文本解析逻辑，提取 URL 或其它有效载荷。
- **消息去重**：若 KV 可用，可将已处理的 `msgid` 记录在集合类型中（目前仅使用游标保证顺序）。
- **并发优化**：默认串行处理 Readwise 请求，可按需要将链接消息收集后并发发送，注意速率限制。

## 7. 日志参考
所有日志均包含 `route=/api/wx_kf_webhook`，示例：
```
{"time":"...","level":"INFO","msg":"readwise save ok","url":"https://example"}
{"time":"...","level":"WARN","msg":"cursor fetch failed","error":"kv: ..."}
```
在 Vercel Dashboard → Logs 中可使用 JSON 字段筛选。

---
如需更多上下游协议细节，请参考：
- [企业微信开放客服回调文档](https://kf.weixin.qq.com/api/doc/path/94745)
- [Readwise Reader API 文档](https://readwise.io/reader_api)
