# Weixin2ReadwiseReader

将企业微信开放客服（WeCom Open KF）的回调消息整理后同步到 Readwise Reader 的 Vercel Go Serverless 项目。

## 功能亮点
- ✅ 支持企业微信客服回调（明文 & 加密），自动完成签名校验与 AES 解密
- ✅ 将回调中的 Token 与 OpenKfId 自动用于拉取会话消息，并将链接型消息保存至 Readwise Reader
- ✅ 使用 Upstash KV（Vercel KV）保存同步游标，避免重复处理
- ✅ 完整的错误处理与 key=value 日志输出，便于排查线上问题
- ✅ 内部模块化设计，新增针对加解密与签名逻辑的单元测试

## 目录结构
```
api/
  ping/               健康检查路由 `/api/ping`
  wx_kf_webhook/      微信客服 Webhook `/api/wx_kf_webhook`
internal/
  app/                业务编排（KV / WeChat / Readwise 协作）
  config/             环境变量加载与校验
  kv/                 Upstash KV 客户端
  readwise/           Readwise Reader API 客户端
  wechat/             签名校验、加解密、消息结构体
  ..._test.go         对核心加解密逻辑的单元测试
```

更多设计细节请见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。


## 环境变量
| 名称 | 是否必需 | 说明 |
| ---- | -------- | ---- |
| `WECHAT_TOKEN` | ✅ | 企业微信客服回调配置的 Token，用于签名校验 |
| `WECHAT_ENCODING_AES_KEY` | ✅ | 43 字符的 EncodingAESKey，用于 AES-256-CBC 解密 |
| `WECHAT_CORPID` | ✅ | 企业 ID，用于解密后尾部校验 |
| `WECHAT_KF_SECRET` | ✅ | 开放客服 Secret，用于换取 access_token |
| `READWISE_TOKEN` | ✅ | Readwise Reader API Token，用于保存链接 |
| `KV_REST_API_URL` | ✅ | Vercel KV REST Endpoint（例如 `https://xxx.upstash.io`） |
| `KV_REST_API_TOKEN` | ✅ | Vercel KV REST Token |
| `HTTP_TIMEOUT` | 可选 | 对外 HTTP 请求超时时间（默认 `5s`） |
| `KV_HTTP_TIMEOUT` | 可选 | KV 请求超时时间（默认 `3s`） |

> **提示**：若缺少 KV 配置，系统仍可运行但不会保存游标；缺少 Readwise Token 时将无法推送链接，会返回错误以触发重试。

## 本地运行
1. 安装并登录 Vercel CLI
   ```bash
   npm i -g vercel
   vercel login
   ```
2. 准备环境变量（示例 `.env.local`）
   ```bash
   WECHAT_TOKEN=xxx
   WECHAT_ENCODING_AES_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   WECHAT_CORPID=wwxxxx
   WECHAT_KF_SECRET=xxxxxxxx
   READWISE_TOKEN=rw_xxxxx
   ```
3. 启动本地开发
   ```bash
   vercel dev
   ```
   - 健康检查：`http://localhost:3000/api/ping`
   - Webhook：`http://localhost:3000/api/wx_kf_webhook`

如需直接运行单元测试，可在仓库根目录执行：
```bash
GOCACHE=$(pwd)/.cache/go-build go test ./...
```
（沙箱环境可能无法写入全局 Go build cache，因此示例中指定了本地缓存路径。）

## 部署
```bash
vercel            # 预览环境
vercel --prod     # 生产环境
```
确保在 Vercel 项目的 Environment Variables 中配置上述所有必需参数。

## 故障排查
- Webhook 返回 401：核对 `WECHAT_TOKEN`、timestamp/nonce 是否按原样传入。
- Webhook 返回 500：通常表示 AES Key 或 Readwise/WeChat 凭证缺失，详见 Vercel 日志中的结构化错误信息。
- 未保存游标：检查 KV URL/Token 是否配置；若无需增量同步可留空。

## 许可证
项目继续沿用原仓库的 [MIT License](LICENSE)。
