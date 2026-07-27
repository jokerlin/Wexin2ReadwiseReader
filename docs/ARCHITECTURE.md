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
4. Processor 使用 Token/OpenKfId 调用 WeCom `sync_msg` 拉取会话消息；将链接消息推送给 Readwise；并使用 KV 协调游标、分布式锁和消息去重。

## 2. 模块职责
| 模块 | 作用 |
| ---- | ---- |
| `api/ping` | 健康检查；无外部依赖 |
| `api/wx_kf_webhook` | HTTP Handler，负责校验、解密、速返 `success` |
| `internal/config` | 装载环境变量、统一校验及默认值 |
| `internal/wechat` | 签名校验、AES 解密、消息结构体、WeCom API 封装 |
| `internal/readwise` | Readwise Reader API 客户端，仅负责 `POST /api/v3/save/` |
| `internal/kv` | Upstash/Vercel KV REST 客户端，存取游标、分布式锁和已处理消息标记 |
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
     1. 为该 OpenKfId 获取带 TTL 的分布式锁；锁忙或获取失败时立即返回可重试的 HTTP 500，不会读取游标、调用 WeChat 或写入游标。
     2. 拉取 access_token。
     3. 读取 KV 游标。
     4. 调用 `sync_msg` 获取消息。
     5. 对链接消息按 `msgid` 查询已处理标记；已处理的相同 `msgid` 跳过 Readwise。相同 URL 搭配新的 `msgid` 仍可再次保存。
     6. 未处理消息依次执行 Readwise `SaveURL`、写入七天 `msgid` 标记、写回 `next_cursor`；任一步失败均不继续后续步骤。
     7. 结束时仅由持锁者释放锁；释放操作会比较 owner 后再删除。释放失败只记录日志，锁的 TTL 会作为后备清理机制。

### KV 键与处理不变量

KV 是 Webhook 安全处理的必需依赖，未配置或不可用时流程失败关闭，以避免重复写入 Readwise。每个 OpenKfId 使用以下键；空 OpenKfId 的 `<suffix>` 固定为 `default`：

| 用途 | 键形状 |
| ---- | ---- |
| 同步游标 | `wechat_kf_cursor:<suffix>` |
| 分布式同步锁 | `wechat_kf_sync_lock:<suffix>` |
| 已处理消息标记 | `wechat_kf_processed:<suffix>:<msgid>` |

消息标记的 TTL 为七天。锁必须在读取游标、获取 token 和同步消息之前获得，确保同一 OpenKfId 的回调串行执行。对于一个新消息，顺序始终是 `SaveURL` → 写入标记 → 推进游标；因此任何 KV、Readwise 或游标错误都会传播为 HTTP 500，交由企业微信重试。

## 4. 安全与鲁棒性
- **签名校验强制启用**：Token 为空时直接拒绝回调。
- **AES Key 校验**：长度必须为 43，初始化时即验证。
- **结构化日志**：标准库 `log.Printf` 采用 `level=... key=value` 格式，便于在 Vercel 上过滤错误类型。
- **错误传播策略**：获取锁、获取 token、同步、KV 读取/写入、Readwise 保存或游标写入任一失败时，Handler 返回 500，使企业微信自动重试，避免数据丢失或重复写入。锁忙同样返回可重试的 500。
- **KV 必需且失败关闭**：KV 保存游标、OpenKfId 级分布式锁和七天 `msgid` 标记；没有 KV 时不处理回调，以避免重复写入 Readwise。
- **超时控制**：所有外部调用使用带超时的 `http.Client` 和 `context.WithTimeout`。

## 5. 测试与质量保证
- `internal/wechat/wechat_test.go` 覆盖签名与 AES 解密的典型/错误场景。
- 可以在本地运行 `go test ./...`（注意设置 `GOCACHE`）。
- 建议在 CI 中追加对 Handler 的集成测试（可通过 httptest + 假 KV/Readwise 客户端模拟）。

## 6. 常见扩展
- **非链接消息同步**：可在 Processor 中扩展文本解析逻辑，提取 URL 或其它有效载荷。
- **消息去重**：已实现基于七天 `msgid` 标记的去重；如需改变保留期限或键空间，请同时评估重试窗口和存储成本。
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
