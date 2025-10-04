# Wexin2ReadwiseReader
微信转发文章到 Readwise Reader

## 项目结构

```
.
├── api/
│   ├── index.go         # API 首页 - /api/
│   └── ping.go          # 健康检查 - /api/ping
├── handler/
│   └── ping.go          # 本地开发用的处理器（可选）
├── vercel.json          # Vercel 配置文件
├── go.mod               # Go 模块依赖
└── go.sum               # 依赖版本锁定
```

## 功能特性

- ✅ 使用 Vercel Serverless Functions 部署
- ✅ 提供 `/api/ping` 健康检查接口
- ✅ 提供 `/api/` API 信息接口
- ✅ 支持本地开发和 Vercel 部署

## 快速开始

### 安装依赖

```bash
# 安装 Go 依赖
go mod tidy

# 安装 Vercel CLI（如果还没有安装）
npm i -g vercel
```

### 本地开发

使用 Vercel CLI 在本地运行：

```bash
vercel dev
```

服务将在 `http://localhost:3000` 启动

### 测试接口

```bash
# 测试 ping 接口
curl http://localhost:3000/api/ping

# 测试首页接口
curl http://localhost:3000/api/
```

预期响应：

**GET /api/ping**
```json
{
  "message": "pong",
  "status": "ok"
}
```

**GET /api/**
```json
{
  "name": "Wexin2ReadwiseReader API",
  "version": "1.0.0",
  "status": "running",
  "endpoints": [
    "/api/ping - 健康检查"
  ]
}
```

## 部署到 Vercel

### 首次部署

```bash
vercel
```

### 生产部署

```bash
vercel --prod
```

部署后，你的 API 将在 `https://your-project.vercel.app/api/` 可用

## 开发说明

### 添加新的 Serverless Function

在 `api/` 目录下创建新的 `.go` 文件，每个文件会自动成为一个独立的 API 端点：

```go
// api/hello.go
package api

import (
    "encoding/json"
    "net/http"
)

func Hello(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    
    response := map[string]string{
        "message": "Hello World",
    }
    
    json.NewEncoder(w).Encode(response)
}
```

这将创建一个新的端点：`/api/hello`

### 函数命名规则

- 文件名决定 URL 路径：`api/ping.go` → `/api/ping`
- 函数名必须是导出的（首字母大写）
- 函数签名：`func FunctionName(w http.ResponseWriter, r *http.Request)`

## Vercel 配置

项目使用 `vercel.json` 进行配置：

```json
{
  "version": 2,
  "builds": [
    {
      "src": "api/**/*.go",
      "use": "@vercel/go"
    }
  ],
  "routes": [
    {
      "src": "/api/(.*)",
      "dest": "/api/$1"
    }
  ]
}
```

## 参考文档

- [Vercel Go Runtime](https://vercel.com/docs/functions/runtimes/go)
- [Vercel Serverless Functions](https://vercel.com/docs/functions)
