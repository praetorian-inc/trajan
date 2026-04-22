package local

import (
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func init() {
	registry.RegisterPlatform(platforms.PlatformLocal, func() platforms.Platform {
		return NewPlatform()
	})
}
