// internal/acme/storage.go
package acme

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"ad-pki-ca/internal/config"
)

// =====================================================
// 🔥 ACME Storage — JSON Dateien
// Struktur: /var/lib/adpki/acme/{accounts,orders,authz}/
// =====================================================

func acmePath(sub ...string) string {
	parts := append([]string{config.BasePath(), "acme"}, sub...)
	return filepath.Join(parts...)
}

func ensureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// =====================================================
// 🔥 ACCOUNT STORAGE
// =====================================================

func SaveAccount(acc *Account) error {
	if err := ensureDir(acmePath("accounts")); err != nil {
		return err
	}
	return writeJSON(acmePath("accounts", acc.ID+".json"), acc)
}

func LoadAccount(id string) (*Account, error) {
	var acc Account
	if err := readJSON(acmePath("accounts", id+".json"), &acc); err != nil {
		return nil, fmt.Errorf("account not found: %s", id)
	}
	return &acc, nil
}

// =====================================================
// 🔥 ORDER STORAGE
// =====================================================

func SaveOrder(order *Order) error {
	if err := ensureDir(acmePath("orders")); err != nil {
		return err
	}
	return writeJSON(acmePath("orders", order.ID+".json"), order)
}

func LoadOrder(id string) (*Order, error) {
	var order Order
	if err := readJSON(acmePath("orders", id+".json"), &order); err != nil {
		return nil, fmt.Errorf("order not found: %s", id)
	}
	return &order, nil
}

// =====================================================
// 🔥 AUTHORIZATION STORAGE
// =====================================================

func SaveAuthz(authz *Authorization) error {
	if err := ensureDir(acmePath("authz")); err != nil {
		return err
	}
	return writeJSON(acmePath("authz", authz.ID+".json"), authz)
}

func LoadAuthz(id string) (*Authorization, error) {
	var authz Authorization
	if err := readJSON(acmePath("authz", id+".json"), &authz); err != nil {
		return nil, fmt.Errorf("authorization not found: %s", id)
	}
	return &authz, nil
}

// =====================================================
// 🔥 HELPERS
// =====================================================

func writeJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func readJSON(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// =====================================================
// 🔥 STRING FILE HELPERS (für Mappings)
// =====================================================

func writeStringFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

func readStringFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func ListAccounts() ([]*Account, error) {
	dir := acmePath("accounts")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var accounts []*Account
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := entry.Name()[:len(entry.Name())-5]
		acc, err := LoadAccount(id)
		if err != nil {
			continue
		}
		accounts = append(accounts, acc)
	}

	return accounts, nil
}
