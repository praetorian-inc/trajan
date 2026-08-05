package config

import (
	"testing"
)

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

func TestConfigConcurrency(t *testing.T) {
	cfg := DefaultConfig()

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			for j := 0; j < 100; j++ {
				_ = cfg.Set("scan.concurrent", n)
				_, _ = cfg.Get("scan.concurrent")
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	_, err := cfg.Get("scan.concurrent")
	if err != nil {
		t.Errorf("config corrupted by concurrent access: %v", err)
	}
}
