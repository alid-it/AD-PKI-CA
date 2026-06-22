// internal/acme/revoke.go
package acme

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func RevokeVieLaravel(serial, reason string) error {
	payload := map[string]string{
		"serial": serial,
		"reason": reason,
	}

	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", backendURL()+"/api/internal/acme/revoke", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request error: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CA-Token", os.Getenv("CA_TOKEN"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("laravel returned %d", resp.StatusCode)
	}

	return nil
}
