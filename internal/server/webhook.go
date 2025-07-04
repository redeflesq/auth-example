package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
)

func SendWebhook(user_id, old_ip, new_ip string) {

	if old_ip == "" || new_ip == "" || old_ip == new_ip {
		return
	}

	url := os.Getenv("WEBHOOK_URL")

	if url == "" {
		return
	}

	payload := map[string]string{
		"user_id": user_id,
		"old_ip":  old_ip,
		"new_ip":  new_ip,
		"message": "Login attempt from new IP address",
	}

	jsonPayload, _ := json.Marshal(payload)

	http.Post(url, "application/json", bytes.NewBuffer(jsonPayload))
}
