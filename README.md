Wexin2ReadwiseReader — Vercel Go Serverless Ping

快速添加了一个基于 Vercel Go Runtime 的测试接口：`/api/ping`。

如何本地运行（需要 Vercel CLI）：

1) 安装并登录
- `npm i -g vercel`
- `vercel login`

2) 本地开发调试
- `vercel dev`
- 浏览器访问 `http://localhost:3000/api/ping`

3) 预览环境部署
- `vercel`
- 访问输出的预览 URL（例如 `https://xxx.vercel.app/api/ping`）

4) 生产环境部署
- `vercel --prod`
- 访问生产域名：`/api/ping`

接口返回示例：

```
{
  "message": "pong",
  "time": "2025-10-04T03:12:34.567Z",
  "method": "GET",
  "path": "/api/ping"
}
```

注意事项：
- Go 版本：当前 `go.mod` 为 `go 1.24.5`。若 Vercel 构建报不支持的 Go 版本，可将其改成 Vercel 支持的稳定版本（如 `1.22`）后重新部署。
- 函数代码位置：`api/ping.go`（默认路径即成为 `/api/ping` 路由）。


微信客服 Webhook（KF）

- 路由：`/api/wx_kf_webhook`
- 文件：`api/wx_kf_webhook.go`
- 功能：
  - GET：用于 URL 校验，返回 `echostr`（如配置了 `WECHAT_TOKEN` 会校验 `signature`）。
  - POST：接收微信客服的事件/消息（JSON 明文模式），将消息原样返回，并将 `create_time` 额外格式化为 `create_time_rfc3339`。

环境变量
- `WECHAT_TOKEN`：可选。用于签名校验（`signature` = sha1(sort(token, timestamp, nonce))）。未设置时，本地开发会跳过校验。

本地调试
- `vercel dev`
- GET 校验示例：
  - `curl "http://localhost:3000/api/wx_kf_webhook?signature=xxx&timestamp=111&nonce=222&echostr=hello"`
- POST 消息示例（明文 JSON）：
  - `curl -X POST -H "Content-Type: application/json" \
    -d '{"event":"user_enter_session","create_time": 1696400000, "open_kfid":"xxx"}' \
    http://localhost:3000/api/wx_kf_webhook`

生产部署
- 预览：`vercel`
- 生产：`vercel --prod`

说明
- 文档参考（需登录/访问）：微信客服回调（kf）：https://kf.weixin.qq.com/api/doc/path/94745
- 若开启安全模式（AES 加密、`msg_signature`），需按文档进行消息解密与签名校验。本实现仅覆盖明文/简单签名场景，方便快速联通调试。
