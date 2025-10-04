package api

import (
	"encoding/json"
	"net/http"
)

// Ping 处理 ping 请求，用于健康检查
func Ping(w http.ResponseWriter, r *http.Request) {
	// 设置响应头
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// 构造响应数据
	response := map[string]string{
		"message": "pong",
		"status":  "ok",
	}

	// 编码并返回 JSON
	json.NewEncoder(w).Encode(response)
}
