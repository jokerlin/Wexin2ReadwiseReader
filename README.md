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
  - GET：用于 URL 校验，企业微信/开放客服会带 `msg_signature`，服务端需解密 `echostr` 并按原样以 `text/plain` 返回。
  - POST：收到回调（加密或明文）后，校验并解密（如有），返回 `success`（`text/plain`）。

环境变量
- `WECHAT_TOKEN`：用于签名校验
  - 明文：`signature = sha1(sort(token, timestamp, nonce))`
  - 加密（OpenAPI/企业微信风格）：`msg_signature = sha1(sort(token, timestamp, nonce, encrypt))`
- `WECHAT_ENCODING_AES_KEY`：可选。开启加密回调时必填（43 字符），用于 AES-256-CBC 解密。
- `WECHAT_APPID` 或 `WECHAT_CORPID`：可选。用于解密后尾部校验（AppID/CorpID 不匹配会失败）。

示例配置（你提供的参数）
- `WECHAT_TOKEN=rYi7KLGzsHiTfFXrGpNBpJp`
- `WECHAT_ENCODING_AES_KEY=Fc8L1eW37a7V3t099twOX1DqHLX2WUwgCGTSUrmY5sN`

在 Vercel 设置环境变量：
- Dashboard → Project → Settings → Environment Variables → 添加上述两项（可在 Preview/Production 均设置）。
- 本地 `vercel dev` 时可在根目录创建 `.env.local`：
  ```
  WECHAT_TOKEN=rYi7KLGzsHiTfFXrGpNBpJp
  WECHAT_ENCODING_AES_KEY=Fc8L1eW37a7V3t099twOX1DqHLX2WUwgCGTSUrmY5sN
  ```

本地调试
- `vercel dev`
- GET 校验示例：
  - `curl "http://localhost:3000/api/wx_kf_webhook?signature=xxx&timestamp=111&nonce=222&echostr=hello"`
- POST 消息示例（明文 JSON）：
  - `curl -X POST -H "Content-Type: application/json" \
    -d '{"event":"user_enter_session","create_time": 1696400000, "open_kfid":"xxx"}' \
    http://localhost:3000/api/wx_kf_webhook`

OpenAPI 回调差异（重要）
- 开放客服 OpenAPI/企业微信风格回调与公众号明文回调不同：
  - GET：使用 `msg_signature`，`echostr` 为加密串，需要解密后回显解密后的明文。
  - POST：请求体为 JSON `{ "encrypt": "..." }`，需要校验 `msg_signature` 并解密再处理；服务端统一返回 `success`。
  - 需要配置：`WECHAT_TOKEN`、`WECHAT_ENCODING_AES_KEY`，以及 `WECHAT_APPID` 或 `WECHAT_CORPID` 用于尾部校验。

生产部署
- 预览：`vercel`
- 生产：`vercel --prod`

说明
- 文档参考（需登录/访问）：微信客服回调（kf）：https://kf.weixin.qq.com/api/doc/path/94745
- 已同时支持明文与加密（`msg_signature` + AES）两种回调模式。若你的后台开启的是 OpenAPI 加密回调，请务必配置 AES Key 与 AppID/CorpID。
