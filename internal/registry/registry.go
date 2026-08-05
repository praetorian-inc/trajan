package registry

import (
	"fmt"
	"sort"
	"sync"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

var (
	mu               sync.RWMutex
	platformRegistry = make(map[string]platforms.PlatformFactory)
)

func RegisterPlatform(name string, factory platforms.PlatformFactory) {
	mu.Lock()
	defer mu.Unlock()
	platformRegistry[name] = factory
}

func GetPlatform(name string) (platforms.Platform, error) {
	mu.RLock()
	defer mu.RUnlock()
	factory, ok := platformRegistry[name]
	if !ok {
		return nil, fmt.Errorf("unknown platform: %s", name)
	}
	return factory(), nil
}

func ListPlatforms() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(platformRegistry))
	for name := range platformRegistry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// For tests only.
func ResetPlatforms() {
	mu.Lock()
	defer mu.Unlock()
	platformRegistry = make(map[string]platforms.PlatformFactory)
}
