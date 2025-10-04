package handler

import (
	"net/http"

	"github.com/jokerlin/Wexin2ReadwiseReader/pkg/wxkfwebhook"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	wxkfwebhook.Handler(w, r)
}
