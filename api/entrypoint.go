package api

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/jokerlin/Wexin2ReadwiseReader/handler"
)

// StartServer 启动 HTTP 服务器
func StartServer(port string) error {
	// 创建 Gin 引擎
	r := gin.Default()

	// 注册路由
	RegisterRoutes(r)

	// 启动服务器
	log.Printf("服务器启动在端口 %s", port)
	return r.Run(":" + port)
}

// RegisterRoutes 注册所有路由
func RegisterRoutes(r *gin.Engine) {
	// Ping 接口 - 用于健康检查
	r.GET("/ping", handler.Ping)
}
