package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"syscall"

	"ad-pki-ca/internal/config"
)

type SystemInfo struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Detail    string `json:"detail,omitempty"`
}

func SystemInfoHandler(w http.ResponseWriter, r *http.Request) {

	data := []SystemInfo{
		{
			Component: "Go",
			Version:   runtime.Version(),
		},
	}

	// 🔥 Storage-Info aus /var/lib/adpki
	var stat syscall.Statfs_t
	storagePath := config.BasePath()
	if err := syscall.Statfs(storagePath, &stat); err == nil {
		freeBytes := stat.Bavail * uint64(stat.Bsize)
		totalBytes := stat.Blocks * uint64(stat.Bsize)
		freeGB := float64(freeBytes) / 1024 / 1024 / 1024
		totalGB := float64(totalBytes) / 1024 / 1024 / 1024

		data = append(data, SystemInfo{
			Component: "Storage",
			Version:   "OK",
			Detail:    fmt.Sprintf("%.1f GB frei / %.1f GB gesamt", freeGB, totalGB),
		})
	} else {
		data = append(data, SystemInfo{
			Component: "Storage",
			Version:   "ERROR",
			Detail:    "Pfad nicht lesbar: " + storagePath,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
