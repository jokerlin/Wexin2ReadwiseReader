package api

import (
	"encoding/json"
	"net/http"
)

// Index 处理根路径请求
func Index(w http.ResponseWriter, r *http.Request) {
	// 设置响应头
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// 构造响应数据
	response := map[string]interface{}{
		"name":    "Wexin2ReadwiseReader API",
		"version": "1.0.0",
		"status":  "running",
		"endpoints": []string{
			"/api/ping - 健康检查",
		},
	}

	// 编码并返回 JSON
	json.NewEncoder(w).Encode(response)
}
