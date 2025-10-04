package main

import (
	"log"

	"github.com/jokerlin/Wexin2ReadwiseReader/api"
)

func main() {
	// 启动服务器，监听 8080 端口
	if err := api.StartServer("8080"); err != nil {
		log.Fatal("启动服务器失败:", err)
	}
}
