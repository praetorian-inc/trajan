package config

import (
	"testing"
)

// TestConfigSetFloat64ToInt tests converting float64 to int (from JSON)
func TestConfigSetFloat64ToInt(t *testing.T) {
	cfg := DefaultConfig()

	err := cfg.Set("scan.concurrent", float64(25))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	value, err := cfg.Get("scan.concurrent")
	if err != nil {
		t.Fatalf("unexpected error getting value: %v", err)
	}

	if intVal, ok := value.(int); !ok {
		t.Errorf("expected int value, got %T", value)
	} else if intVal != 25 {
		t.Errorf("expected 25, got %d", intVal)
	}
}

// TestConfigConcurrency tests concurrent access to config
func TestConfigConcurrency(t *testing.T) {
	cfg := DefaultConfig()

	// Spawn multiple goroutines reading and writing
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			// Perform multiple operations
			for j := 0; j < 100; j++ {
				_ = cfg.Set("scan.concurrent", n)
				_, _ = cfg.Get("scan.concurrent")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify config is still functional
	_, err := cfg.Get("scan.concurrent")
	if err != nil {
		t.Errorf("config corrupted by concurrent access: %v", err)
	}
}
