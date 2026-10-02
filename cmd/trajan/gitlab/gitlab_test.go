package gitlab

import (
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func TestPersistentFlagsBindToConfig(t *testing.T) {
	cfg := &engine.Config{}
	cmd := newGitLabCmd(cfg)
	if err := cmd.PersistentFlags().Set("url", "https://3.136.153.111"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.PersistentFlags().Set("insecure", "true"); err != nil {
		t.Fatal(err)
	}
	if cfg.BaseURL != "https://3.136.153.111" {
		t.Errorf("cfg.BaseURL = %q, want the value set via --url", cfg.BaseURL)
	}
	if !cfg.Insecure {
		t.Error("cfg.Insecure = false after --insecure=true")
	}
}
