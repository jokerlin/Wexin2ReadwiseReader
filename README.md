# Wexin2ReadwiseReader
微信转发文章到 Readwise Reader

## 项目结构

```
.
├── main.go              # 主入口文件
├── api/
│   └── entrypoint.go    # API 服务启动和路由配置
├── handler/
│   └── ping.go          # Ping 处理器
├── go.mod               # Go 模块依赖
└── go.sum               # 依赖版本锁定
```

## 功能特性

- ✅ 使用 Gin 框架构建 HTTP 服务
- ✅ 提供 `/ping` 健康检查接口
- ✅ 默认监听 8080 端口

## 快速开始

### 安装依赖

```bash
go mod tidy
```

### 启动服务

```bash
go run main.go
```

服务将在 `http://localhost:8080` 启动

### 测试接口

```bash
curl http://localhost:8080/ping
```

预期响应：

```json
{
  "message": "pong",
  "status": "ok"
}
```

## API 接口

### GET /ping

健康检查接口

**响应示例：**

```json
{
  "message": "pong",
  "status": "ok"
}
```

## 开发说明

### 添加新的路由

在 `api/entrypoint.go` 的 `RegisterRoutes` 函数中添加新路由：

```go
func RegisterRoutes(r *gin.Engine) {
    r.GET("/ping", handler.Ping)
    // 添加新路由
    r.GET("/your-route", handler.YourHandler)
}
```

### 创建新的处理器

在 `handler/` 目录下创建新的处理器文件：

```go
package handler

import (
    "net/http"
    "github.com/gin-gonic/gin"
)

func YourHandler(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
        "message": "your response",
    })
}
```

## 生产部署

在生产环境中，建议设置 Gin 为 release 模式：

```bash
export GIN_MODE=release
go run main.go
```

或者在代码中设置：

```go
gin.SetMode(gin.ReleaseMode)
```
