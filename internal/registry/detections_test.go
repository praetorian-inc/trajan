package registry

import (
	"testing"

	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestRegisterDetection(t *testing.T) {
	ResetDetections()

	called := false
	RegisterDetection("github", "test", func() detections.Detection {
		called = true
		return nil
	})

	dets := GetDetections("github")
	if len(dets) != 1 {
		t.Errorf("GetDetections() returned %d detections, want 1", len(dets))
	}
	if !called {
		t.Error("Factory was not called")
	}
}

func TestGetDetectionsForPlatform(t *testing.T) {
	ResetDetections()

	RegisterDetection("github", "github-specific", func() detections.Detection { return nil })

	RegisterDetection("all", "cross-platform", func() detections.Detection { return nil })

	dets := GetDetectionsForPlatform("github")
	if len(dets) != 2 {
		t.Errorf("GetDetectionsForPlatform() returned %d, want 2", len(dets))
	}

	RegisterDetection("gitlab", "gitlab-specific", func() detections.Detection { return nil })
	dets = GetDetectionsForPlatform("gitlab")
	if len(dets) != 2 {
		t.Errorf("GetDetectionsForPlatform() returned %d, want 2 (gitlab-specific + cross-platform)", len(dets))
	}

	dets = GetDetectionsForPlatform("bitbucket")
	if len(dets) != 1 {
		t.Errorf("GetDetectionsForPlatform() returned %d, want 1 (cross-platform only)", len(dets))
	}
}
