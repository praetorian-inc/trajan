//go:build !js
// +build !js

package config

// Load loads configuration (stub for non-WASM builds)
func (s *LocalStorage) Load() (*Config, error) {
	// For testing on native Go, return default config
	return DefaultConfig(), nil
}

// Save saves configuration (stub for non-WASM builds)
func (s *LocalStorage) Save(config *Config) error {
	// For testing on native Go, do nothing
	return nil
}
