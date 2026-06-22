package ca

import (
	"encoding/json"
	"net/http"
	"os"
)

type SettingsResponse struct {
	CRLURL         string   `json:"crl_url"`
	OCSPURL        string   `json:"ocsp_url"`
	IntermediateID string   `json:"intermediate_id"`
	ValidityDays   int      `json:"validity_days"`
	DNSServers     []string `json:"dns_servers"`
}

func FetchSettings(apiURL string) (SettingsResponse, error) {
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return SettingsResponse{}, err
	}

	req.Header.Set("X-CA-Token", os.Getenv("CA_TOKEN"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return SettingsResponse{}, err
	}
	defer resp.Body.Close()

	var data SettingsResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return SettingsResponse{}, err
	}

	return data, nil
}
