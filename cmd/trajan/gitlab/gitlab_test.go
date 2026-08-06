package gitlab

import (
	"testing"

	"github.com/praetorian-inc/trajan/internal/gitlab"
)

// The CLI's --url / --insecure persistent flags must bind into the frozen
// gitlab.FlagURL / FlagInsecure globals — that binding is the only channel by
// which Collect/WhoAmI (whose signatures exclude these) learn the endpoint.
func TestPersistentFlagsBindToGitlabGlobals(t *testing.T) {
	origURL, origInsecure := gitlab.FlagURL, gitlab.FlagInsecure
	defer func() { gitlab.FlagURL, gitlab.FlagInsecure = origURL, origInsecure }()

	cmd := newGitLabCmd()
	if err := cmd.PersistentFlags().Set("url", "https://3.136.153.111"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.PersistentFlags().Set("insecure", "true"); err != nil {
		t.Fatal(err)
	}
	if gitlab.FlagURL != "https://3.136.153.111" {
		t.Errorf("FlagURL = %q, want the value set via --url", gitlab.FlagURL)
	}
	if !gitlab.FlagInsecure {
		t.Error("FlagInsecure = false after --insecure=true")
	}
}
