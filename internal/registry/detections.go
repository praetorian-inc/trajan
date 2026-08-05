package registry

import (
	"fmt"
	"sort"
	"sync"

	"github.com/praetorian-inc/trajan/pkg/detections"
)

var (
	detectionMu       sync.RWMutex
	detectionRegistry = make(map[string][]detections.DetectionFactory)
	detectionIDs      = make(map[string]bool)
)

func RegisterDetection(platform, name string, factory detections.DetectionFactory) {
	detectionMu.Lock()
	defer detectionMu.Unlock()

	id := platform + "/" + name
	if detectionIDs[id] {
		panic(fmt.Sprintf("detection: Register called twice for %s", id))
	}
	detectionIDs[id] = true

	detectionRegistry[platform] = append(detectionRegistry[platform], factory)
}

func GetDetections(platform string) []detections.Detection {
	detectionMu.RLock()
	defer detectionMu.RUnlock()
	factories := detectionRegistry[platform]
	result := make([]detections.Detection, 0, len(factories))
	for _, factory := range factories {
		result = append(result, factory())
	}
	return result
}

// Also includes detections registered under the "all" platform (cross-platform).
func GetDetectionsForPlatform(platform string) []detections.Detection {
	detectionMu.RLock()
	defer detectionMu.RUnlock()

	platformDets := make([]detections.Detection, 0)
	for _, factory := range detectionRegistry[platform] {
		platformDets = append(platformDets, factory())
	}

	for _, factory := range detectionRegistry["all"] {
		platformDets = append(platformDets, factory())
	}

	return platformDets
}

func ListDetectionPlatforms() []string {
	detectionMu.RLock()
	defer detectionMu.RUnlock()
	names := make([]string, 0, len(detectionRegistry))
	for name := range detectionRegistry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// For tests only.
func ResetDetections() {
	detectionMu.Lock()
	defer detectionMu.Unlock()
	detectionRegistry = make(map[string][]detections.DetectionFactory)
	detectionIDs = make(map[string]bool)
}
