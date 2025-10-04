package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Ping 处理 ping 请求，用于健康检查
func Ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
		"status":  "ok",
	})
}
