//go:build js
// +build js

package config

import (
	"encoding/json"
	"fmt"
	"syscall/js"
)

// Load loads configuration from localStorage
func (s *LocalStorage) Load() (*Config, error) {
	// Access browser localStorage
	localStorage := js.Global().Get("localStorage")
	if !localStorage.Truthy() {
		return nil, fmt.Errorf("localStorage not available")
	}

	// Get configuration JSON from localStorage
	configJSON := localStorage.Call("getItem", s.key)
	if !configJSON.Truthy() || configJSON.IsNull() {
		// No saved configuration, return default
		return DefaultConfig(), nil
	}

	// Parse JSON string
	jsonStr := configJSON.String()
	if jsonStr == "" {
		return DefaultConfig(), nil
	}

	// Unmarshal into Config struct
	config := &Config{}
	if err := json.Unmarshal([]byte(jsonStr), config); err != nil {
		// If parse fails, return default config
		return DefaultConfig(), fmt.Errorf("failed to parse stored config: %w", err)
	}

	return config, nil
}

// Save saves configuration to localStorage
func (s *LocalStorage) Save(config *Config) error {
	// Access browser localStorage
	localStorage := js.Global().Get("localStorage")
	if !localStorage.Truthy() {
		return fmt.Errorf("localStorage not available")
	}

	// Marshal Config to JSON
	jsonData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Save to localStorage
	localStorage.Call("setItem", s.key, string(jsonData))

	return nil
}
