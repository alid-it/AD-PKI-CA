package crl

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"ad-pki-ca/internal/config"
)

func StartACMECleanupWorker() {
	go func() {
		for {
			// 🔥 Nächste 02:00 Uhr berechnen
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())
			if now.After(next) {
				next = next.Add(24 * time.Hour)
			}

			log.Printf("[ACME Cleanup] Next run at %s", next.Format("2006-01-02 15:04:05"))
			time.Sleep(time.Until(next))

			log.Println("[ACME Cleanup] Starting cleanup of old ACME files...")
			cleanupACME()
		}
	}()
}

func cleanupACME() {
	base := config.BasePath()
	dirs := []string{
		filepath.Join(base, "acme", "orders"),
		filepath.Join(base, "acme", "authz"),
		filepath.Join(base, "acme", "challenges"),
	}

	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	count := 0

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if info.ModTime().Before(cutoff) {
				path := filepath.Join(dir, entry.Name())
				if err := os.Remove(path); err == nil {
					fmt.Printf("[ACME Cleanup] Deleted: %s\n", entry.Name())
					count++
				}
			}
		}
	}

	log.Printf("[ACME Cleanup] Done — %d files deleted", count)
}
