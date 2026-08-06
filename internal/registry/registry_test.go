package registry

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func Reset() {
	ResetPlatforms()
	ResetDetections()
}

type mockPlatform struct {
	name string
}

func (m *mockPlatform) Name() string {
	return m.name
}

func (m *mockPlatform) Init(ctx context.Context, config platforms.Config) error {
	return nil
}

func (m *mockPlatform) Scan(ctx context.Context, target platforms.Target) (*platforms.ScanResult, error) {
	return &platforms.ScanResult{}, nil
}

func TestConcurrentPlatformRegistration(t *testing.T) {
	Reset()

	platformCount := 100
	var wg sync.WaitGroup

	for i := 0; i < platformCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			name := string(rune('a' + (id % 26)))
			RegisterPlatform(name, func() platforms.Platform {
				return &mockPlatform{name: name}
			})
		}(i)
	}

	wg.Wait()

	plats := ListPlatforms()
	if len(plats) == 0 {
		t.Fatal("Expected platforms to be registered, got none")
	}

	for _, name := range plats {
		p, err := GetPlatform(name)
		if err != nil {
			t.Errorf("Failed to get platform %s: %v", name, err)
		}
		if p == nil {
			t.Errorf("Got nil platform for %s", name)
		}
	}
}

func TestGetPlatformReturnsNewInstance(t *testing.T) {
	Reset()

	RegisterPlatform("test", func() platforms.Platform {
		return &mockPlatform{name: "test"}
	})

	p1, err := GetPlatform("test")
	if err != nil {
		t.Fatalf("Failed to get platform: %v", err)
	}

	p2, err := GetPlatform("test")
	if err != nil {
		t.Fatalf("Failed to get platform: %v", err)
	}

	if p1 == p2 {
		t.Error("GetPlatform returned same instance; expected new instance per call (factory pattern)")
	}

	if p1.Name() != "test" {
		t.Errorf("p1.Name() = %s, want test", p1.Name())
	}
	if p2.Name() != "test" {
		t.Errorf("p2.Name() = %s, want test", p2.Name())
	}
}

func TestListPlatformsSorted(t *testing.T) {
	Reset()

	platformNames := []string{"zebra", "apple", "mango", "banana"}
	for _, name := range platformNames {
		RegisterPlatform(name, func() platforms.Platform {
			return &mockPlatform{name: name}
		})
	}

	got := ListPlatforms()

	expected := []string{"apple", "banana", "mango", "zebra"}
	if len(got) != len(expected) {
		t.Fatalf("ListPlatforms() count = %d, want %d", len(got), len(expected))
	}

	for i, name := range expected {
		if got[i] != name {
			t.Errorf("ListPlatforms()[%d] = %s, want %s", i, got[i], name)
		}
	}
}

func TestReset(t *testing.T) {
	RegisterPlatform("github", func() platforms.Platform {
		return &mockPlatform{name: "github"}
	})
	RegisterPlatform("gitlab", func() platforms.Platform {
		return &mockPlatform{name: "gitlab"}
	})

	if len(ListPlatforms()) == 0 {
		t.Fatal("Expected platforms before Reset")
	}

	Reset()

	plats := ListPlatforms()
	if len(plats) != 0 {
		t.Errorf("After Reset(), ListPlatforms() = %d items, want 0", len(plats))
	}

	_, err := GetPlatform("github")
	if err == nil {
		t.Error("After Reset(), GetPlatform() should return error for unknown platform")
	}
}

func TestGetPlatformUnknown(t *testing.T) {
	Reset()

	_, err := GetPlatform("nonexistent")
	if err == nil {
		t.Error("GetPlatform() with unknown name should return error")
	}

	expectedMsg := "unknown platform: nonexistent"
	if err.Error() != expectedMsg {
		t.Errorf("GetPlatform() error = %q, want %q", err.Error(), expectedMsg)
	}
}

func TestConcurrentReadWrite(t *testing.T) {
	Reset()

	RegisterPlatform("initial", func() platforms.Platform {
		return &mockPlatform{name: "initial"}
	})

	done := make(chan bool)
	iterations := 100

	go func() {
		for i := 0; i < iterations; i++ {
			RegisterPlatform("writer", func() platforms.Platform {
				return &mockPlatform{name: "writer"}
			})
			time.Sleep(time.Microsecond)
		}
		done <- true
	}()

	go func() {
		for i := 0; i < iterations; i++ {
			_ = ListPlatforms()
			_, _ = GetPlatform("initial")
			time.Sleep(time.Microsecond)
		}
		done <- true
	}()

	<-done
	<-done

	plats := ListPlatforms()
	if len(plats) == 0 {
		t.Error("After concurrent access, registry should still have platforms")
	}
}

type mockPlugin struct {
	name     string
	platform string
	severity detections.Severity
}

func (m *mockPlugin) Name() string                  { return m.name }
func (m *mockPlugin) Platform() string              { return m.platform }
func (m *mockPlugin) Severity() detections.Severity { return m.severity }
func (m *mockPlugin) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	return nil, nil
}

func TestRegisterDetection_PanicOnDuplicate(t *testing.T) {
	Reset()

	factory := func() detections.Detection {
		return &mockPlugin{name: "test-detection", platform: "github"}
	}

	RegisterDetection("github", "test-detection", factory)

	assert.Panics(t, func() {
		RegisterDetection("github", "test-detection", factory)
	}, "Should panic on duplicate registration")
}
