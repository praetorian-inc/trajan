//go:build js

package config

import (
	"encoding/json"
	"fmt"
	"syscall/js"
)

type LocalStorage struct {
	key string
}

func NewLocalStorage(key string) *LocalStorage {
	return &LocalStorage{
		key: key,
	}
}

func (s *LocalStorage) Load() (*Config, error) {
	localStorage := js.Global().Get("localStorage")
	if !localStorage.Truthy() {
		return nil, fmt.Errorf("localStorage not available")
	}

	configJSON := localStorage.Call("getItem", s.key)
	if !configJSON.Truthy() || configJSON.IsNull() {
		return DefaultConfig(), nil
	}

	jsonStr := configJSON.String()
	if jsonStr == "" {
		return DefaultConfig(), nil
	}

	config := &Config{}
	if err := json.Unmarshal([]byte(jsonStr), config); err != nil {
		return DefaultConfig(), fmt.Errorf("failed to parse stored config: %w", err)
	}

	return config, nil
}

func (s *LocalStorage) Save(config *Config) error {
	localStorage := js.Global().Get("localStorage")
	if !localStorage.Truthy() {
		return fmt.Errorf("localStorage not available")
	}

	jsonData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	localStorage.Call("setItem", s.key, string(jsonData))

	return nil
}
