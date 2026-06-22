package api

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type setNTPRequest struct {
	NTPServer string `json:"ntp_server"`
}

type setNTPResponse struct {
	OK        bool   `json:"ok"`
	Message   string `json:"message"`
	NTPServer string `json:"ntp_server"`
	Output    string `json:"output,omitempty"`
}

func SetNTPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		writeNTPJSON(w, http.StatusMethodNotAllowed, setNTPResponse{
			OK:      false,
			Message: "Method not allowed",
		})
		return
	}

	var req setNTPRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeNTPJSON(w, http.StatusBadRequest, setNTPResponse{
			OK:      false,
			Message: "Invalid JSON body",
		})
		return
	}

	ntpServer := strings.TrimSpace(req.NTPServer)

	if ntpServer == "" {
		writeNTPJSON(w, http.StatusBadRequest, setNTPResponse{
			OK:      false,
			Message: "NTP server is required",
		})
		return
	}

	if !isValidNTPServer(ntpServer) {
		writeNTPJSON(w, http.StatusBadRequest, setNTPResponse{
			OK:        false,
			Message:   "Invalid NTP server format",
			NTPServer: ntpServer,
		})
		return
	}

	cmd := exec.Command(
		"sudo",
		"/usr/local/sbin/adpki-set-ntp",
		ntpServer,
	)

	done := make(chan error, 1)

	var output []byte

	go func() {
		var err error
		output, err = cmd.CombinedOutput()
		done <- err
	}()

	select {
	case err := <-done:
		cleanOutput := cleanNTPOutput(string(output))

		if err != nil {
			writeNTPJSON(w, http.StatusInternalServerError, setNTPResponse{
				OK:        false,
				Message:   "Failed to set NTP server",
				NTPServer: ntpServer,
				Output:    cleanOutput,
			})
			return
		}

		writeNTPJSON(w, http.StatusOK, setNTPResponse{
			OK:        true,
			Message:   "NTP server configured successfully",
			NTPServer: ntpServer,
			Output:    cleanOutput,
		})

	case <-time.After(15 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}

		writeNTPJSON(w, http.StatusGatewayTimeout, setNTPResponse{
			OK:        false,
			Message:   "Timeout while setting NTP server",
			NTPServer: ntpServer,
		})
	}
}

func isValidNTPServer(server string) bool {
	if len(server) > 255 {
		return false
	}

	// Erlaubt:
	// pool.ntp.org
	// 192.168.10.254
	// ntp01.intern.local
	// IPv6 grundsätzlich mit :
	pattern := regexp.MustCompile(`^[a-zA-Z0-9._:-]+$`)

	return pattern.MatchString(server)
}

func cleanNTPOutput(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}

func writeNTPJSON(w http.ResponseWriter, status int, payload setNTPResponse) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
