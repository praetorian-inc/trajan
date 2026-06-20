package github

import (
	"testing"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestResolveScanTarget_AppTokenNoFlags(t *testing.T) {
	target, err := resolveScanTarget("", "", "", "ghs_test")
	if err != nil {
		t.Fatalf("resolveScanTarget() error = %v", err)
	}
	if target.Type != platforms.TargetUser || target.Value != "" {
		t.Errorf("target = %+v, want all-accessible (TargetUser,\"\")", target)
	}
}

func TestResolveScanTarget_UserTokenNoFlags(t *testing.T) {
	if _, err := resolveScanTarget("", "", "", "ghp_test"); err == nil {
		t.Error("expected error for user token with no target flags")
	}
}
