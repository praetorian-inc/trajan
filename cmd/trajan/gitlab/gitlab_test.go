package gitlab

import (
	"slices"
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

func TestCommandTree(t *testing.T) {
	cmd := newGitLabCmd()
	if !slices.Contains(cmd.Aliases, "gl") {
		t.Errorf("aliases = %v, want to include gl", cmd.Aliases)
	}
	want := []string{"whoami", "collect", "normalize", "scan", "report", "push", "analyze", "attack", "run"}
	got := map[string]bool{}
	for _, c := range cmd.Commands() {
		got[c.Name()] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("subcommand %q missing from tree", w)
		}
	}
}
