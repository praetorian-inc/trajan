// Package config provides browser-compatible configuration, persisted in
// localStorage rather than a file.
package config

import (
	"errors"
	"fmt"
	"sync"
)

var (
	ErrUnknownConfigKey = errors.New("unknown configuration key")

	ErrInvalidValueType = errors.New("invalid value type for configuration key")
)

type Config struct {
	GitHub GitHubConfig `json:"github"`

	GitLab GitLabConfig `json:"gitlab"`

	Azure AzureConfig `json:"azure"`

	Scan ScanConfig `json:"scan"`

	UI UIConfig `json:"ui"`

	Storage StorageConfig `json:"storage"`

	mu sync.RWMutex
}

type GitHubConfig struct {
	Token string `json:"token"`

	BaseURL string `json:"base_url"`

	RateLimit RateLimitConfig `json:"rate_limit"`
}

type GitLabConfig struct {
	Token string `json:"token"`

	BaseURL string `json:"base_url"`
}

type AzureConfig struct {
	Token string `json:"token"`

	Organization string `json:"organization"`
}

type ScanConfig struct {
	Concurrent int `json:"concurrent"`

	// CacheTTL is in seconds.
	CacheTTL int64 `json:"cache_ttl"`

	IncludeArchived bool `json:"include_archived"`

	OutputFormat string `json:"output_format"`
}

type UIConfig struct {
	// Theme is "light" or "dark".
	Theme string `json:"theme"`

	ShowWelcome bool `json:"show_welcome"`

	AutoSave bool `json:"auto_save"`
}

type StorageConfig struct {
	DatabaseName string `json:"database_name"`

	DatabaseVersion int `json:"database_version"`

	AuditLogging bool `json:"audit_logging"`
}

type RateLimitConfig struct {
	Enabled bool `json:"enabled"`

	RequestsPerHour int `json:"requests_per_hour"`
}

func DefaultConfig() *Config {
	return &Config{
		GitHub: GitHubConfig{
			BaseURL: "https://api.github.com",
			RateLimit: RateLimitConfig{
				Enabled:         true,
				RequestsPerHour: 5000,
			},
		},
		GitLab: GitLabConfig{
			BaseURL: "https://gitlab.com/api/v4",
		},
		Azure: AzureConfig{},
		Scan: ScanConfig{
			Concurrent:      10,
			CacheTTL:        3600, // 1 hour
			IncludeArchived: false,
			OutputFormat:    "json",
		},
		UI: UIConfig{
			Theme:       "light",
			ShowWelcome: true,
			AutoSave:    true,
		},
		Storage: StorageConfig{
			DatabaseName:    "trajan_storage",
			DatabaseVersion: 1,
			AuditLogging:    true,
		},
	}
}

func (c *Config) Get(key string) (interface{}, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	switch key {
	case "github.token":
		return c.GitHub.Token, nil
	case "github.base_url":
		return c.GitHub.BaseURL, nil
	case "github.rate_limit.enabled":
		return c.GitHub.RateLimit.Enabled, nil
	case "github.rate_limit.requests_per_hour":
		return c.GitHub.RateLimit.RequestsPerHour, nil

	case "gitlab.token":
		return c.GitLab.Token, nil
	case "gitlab.base_url":
		return c.GitLab.BaseURL, nil

	case "azure.token":
		return c.Azure.Token, nil
	case "azure.organization":
		return c.Azure.Organization, nil

	case "scan.concurrent":
		return c.Scan.Concurrent, nil
	case "scan.cache_ttl":
		return c.Scan.CacheTTL, nil
	case "scan.include_archived":
		return c.Scan.IncludeArchived, nil
	case "scan.output_format":
		return c.Scan.OutputFormat, nil

	case "ui.theme":
		return c.UI.Theme, nil
	case "ui.show_welcome":
		return c.UI.ShowWelcome, nil
	case "ui.auto_save":
		return c.UI.AutoSave, nil

	case "storage.database_name":
		return c.Storage.DatabaseName, nil
	case "storage.database_version":
		return c.Storage.DatabaseVersion, nil
	case "storage.audit_logging":
		return c.Storage.AuditLogging, nil

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownConfigKey, key)
	}
}

func (c *Config) Set(key string, value interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch key {
	case "github.token":
		if v, ok := value.(string); ok {
			c.GitHub.Token = v
			return nil
		}
		return fmt.Errorf("%w: expected string for github.token", ErrInvalidValueType)
	case "github.base_url":
		if v, ok := value.(string); ok {
			c.GitHub.BaseURL = v
			return nil
		}
		return fmt.Errorf("%w: expected string for github.base_url", ErrInvalidValueType)
	case "github.rate_limit.enabled":
		if v, ok := value.(bool); ok {
			c.GitHub.RateLimit.Enabled = v
			return nil
		}
		return fmt.Errorf("%w: expected bool for github.rate_limit.enabled", ErrInvalidValueType)
	case "github.rate_limit.requests_per_hour":
		if v, ok := value.(int); ok {
			c.GitHub.RateLimit.RequestsPerHour = v
			return nil
		}
		// JSON numbers unmarshal as float64.
		if v, ok := value.(float64); ok {
			c.GitHub.RateLimit.RequestsPerHour = int(v)
			return nil
		}
		return fmt.Errorf("%w: expected int for github.rate_limit.requests_per_hour", ErrInvalidValueType)

	case "gitlab.token":
		if v, ok := value.(string); ok {
			c.GitLab.Token = v
			return nil
		}
		return fmt.Errorf("%w: expected string for gitlab.token", ErrInvalidValueType)
	case "gitlab.base_url":
		if v, ok := value.(string); ok {
			c.GitLab.BaseURL = v
			return nil
		}
		return fmt.Errorf("%w: expected string for gitlab.base_url", ErrInvalidValueType)

	case "azure.token":
		if v, ok := value.(string); ok {
			c.Azure.Token = v
			return nil
		}
		return fmt.Errorf("%w: expected string for azure.token", ErrInvalidValueType)
	case "azure.organization":
		if v, ok := value.(string); ok {
			c.Azure.Organization = v
			return nil
		}
		return fmt.Errorf("%w: expected string for azure.organization", ErrInvalidValueType)

	case "scan.concurrent":
		if v, ok := value.(int); ok {
			c.Scan.Concurrent = v
			return nil
		}
		if v, ok := value.(float64); ok {
			c.Scan.Concurrent = int(v)
			return nil
		}
		return fmt.Errorf("%w: expected int for scan.concurrent", ErrInvalidValueType)
	case "scan.cache_ttl":
		if v, ok := value.(int64); ok {
			c.Scan.CacheTTL = v
			return nil
		}
		if v, ok := value.(float64); ok {
			c.Scan.CacheTTL = int64(v)
			return nil
		}
		return fmt.Errorf("%w: expected int64 for scan.cache_ttl", ErrInvalidValueType)
	case "scan.include_archived":
		if v, ok := value.(bool); ok {
			c.Scan.IncludeArchived = v
			return nil
		}
		return fmt.Errorf("%w: expected bool for scan.include_archived", ErrInvalidValueType)
	case "scan.output_format":
		if v, ok := value.(string); ok {
			c.Scan.OutputFormat = v
			return nil
		}
		return fmt.Errorf("%w: expected string for scan.output_format", ErrInvalidValueType)

	case "ui.theme":
		if v, ok := value.(string); ok {
			c.UI.Theme = v
			return nil
		}
		return fmt.Errorf("%w: expected string for ui.theme", ErrInvalidValueType)
	case "ui.show_welcome":
		if v, ok := value.(bool); ok {
			c.UI.ShowWelcome = v
			return nil
		}
		return fmt.Errorf("%w: expected bool for ui.show_welcome", ErrInvalidValueType)
	case "ui.auto_save":
		if v, ok := value.(bool); ok {
			c.UI.AutoSave = v
			return nil
		}
		return fmt.Errorf("%w: expected bool for ui.auto_save", ErrInvalidValueType)

	case "storage.database_name":
		if v, ok := value.(string); ok {
			c.Storage.DatabaseName = v
			return nil
		}
		return fmt.Errorf("%w: expected string for storage.database_name", ErrInvalidValueType)
	case "storage.database_version":
		if v, ok := value.(int); ok {
			c.Storage.DatabaseVersion = v
			return nil
		}
		if v, ok := value.(float64); ok {
			c.Storage.DatabaseVersion = int(v)
			return nil
		}
		return fmt.Errorf("%w: expected int for storage.database_version", ErrInvalidValueType)
	case "storage.audit_logging":
		if v, ok := value.(bool); ok {
			c.Storage.AuditLogging = v
			return nil
		}
		return fmt.Errorf("%w: expected bool for storage.audit_logging", ErrInvalidValueType)

	default:
		return fmt.Errorf("%w: %s", ErrUnknownConfigKey, key)
	}
}
