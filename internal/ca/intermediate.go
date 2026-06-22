package ca

import (
	"encoding/json"
	"net/http"
)

type IntermediateResponse struct {
	ID string `json:"id"`
}

func FetchDefaultIntermediate(apiURL string) (string, error) {

	resp, err := http.Get(apiURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var data IntermediateResponse

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return "", err
	}

	return data.ID, nil
}
