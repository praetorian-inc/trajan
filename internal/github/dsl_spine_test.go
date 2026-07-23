package github

import (
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine/detect"
)

func gatePtr(s string) *string { return &s }

func TestClassifyGateNone(t *testing.T) {
	if g := classifyGate(nil); g.GateStrength != "none" {
		t.Errorf("nil if: -> %q, want none", g.GateStrength)
	}
	if g := classifyGate(gatePtr("")); g.GateStrength != "none" {
		t.Errorf("empty if: -> %q, want none", g.GateStrength)
	}
	if g := classifyGate(gatePtr("true")); g.GateStrength != "none" {
		t.Errorf("if: true -> %q, want none", g.GateStrength)
	}
	if g := classifyGate(gatePtr("${{ true }}")); g.GateStrength != "none" {
		t.Errorf("if: ${{ true }} -> %q, want none", g.GateStrength)
	}
}

func TestClassifyGateStrengthByBranch(t *testing.T) {
	cases := []struct {
		name     string
		expr     string
		strength string
		flag     func(GateClassifiers) bool
	}{
		{
			"pseudo conclusion", "github.event.workflow_run.conclusion == 'success'", "pseudo",
			func(c GateClassifiers) bool { return c.IsPseudoGateConclusion },
		},
		{
			"label contains", "contains(github.event.pull_request.labels.*.name, 'safe')", "weak",
			func(c GateClassifiers) bool { return c.IsLabelGate },
		},
		{
			"label name", "github.event.label.name == 'run-ci'", "weak",
			func(c GateClassifiers) bool { return c.IsLabelGate },
		},
		{
			"author association", "github.event.comment.author_association == 'OWNER'", "weak",
			func(c GateClassifiers) bool { return c.IsAuthorAssocGate },
		},
		{
			"strong actor eq", "github.actor == 'octocat'", "strong",
			func(c GateClassifiers) bool {
				return !c.IsLabelGate && !c.IsAuthorAssocGate && !c.IsPseudoGateConclusion
			},
		},
		{
			"strong fromJSON", "contains(fromJSON('[\"a\"]'), github.actor)", "strong",
			func(c GateClassifiers) bool { return true },
		},
		{
			"strong repo owner", "github.repository_owner == 'acme'", "strong",
			func(c GateClassifiers) bool { return true },
		},
		{
			"weak default", "github.ref == 'refs/heads/main'", "weak",
			func(c GateClassifiers) bool { return !c.IsLabelGate && !c.IsAuthorAssocGate },
		},
	}
	for _, c := range cases {
		g := classifyGate(gatePtr(c.expr))
		if g.GateStrength != c.strength {
			t.Errorf("%s: %q -> %q, want %q", c.name, c.expr, g.GateStrength, c.strength)
		}
		if !c.flag(g.GateClassifiers) {
			t.Errorf("%s: classifier flags wrong for %q: %+v", c.name, c.expr, g.GateClassifiers)
		}
	}
}

// Ordering: pseudo beats label beats author_assoc beats strong (first branch wins).
func TestClassifyGateBranchPrecedence(t *testing.T) {
	both := "github.event.workflow_run.conclusion == 'success' && github.event.comment.author_association == 'OWNER'"
	g := classifyGate(gatePtr(both))
	if g.GateStrength != "pseudo" {
		t.Errorf("conclusion+author_assoc -> %q, want pseudo (first branch wins)", g.GateStrength)
	}
	if !g.GateClassifiers.IsPseudoGateConclusion || g.GateClassifiers.IsAuthorAssocGate {
		t.Errorf("only the pseudo flag should be set: %+v", g.GateClassifiers)
	}
	labelAndActor := "github.event.label.name == 'ok' && github.actor == 'octocat'"
	g2 := classifyGate(gatePtr(labelAndActor))
	if g2.GateStrength != "weak" || !g2.GateClassifiers.IsLabelGate {
		t.Errorf("label+actor -> %q (label=%v), want weak/label", g2.GateStrength, g2.GateClassifiers.IsLabelGate)
	}
}

// The strong-branch needle is case-sensitive and assumes exactly one space before ==.
func TestClassifyGateStrongCaseSensitivity(t *testing.T) {
	// Two spaces before == means the "github.repository_owner ==" needle misses.
	g := classifyGate(gatePtr("github.repository_owner  == 'acme'"))
	if g.GateStrength != "weak" {
		t.Errorf("double-space repo_owner -> %q, want weak (needle needs single space)", g.GateStrength)
	}
	expr := "github.actor == 'x'"
	if got := classifyGate(gatePtr(expr)); got.Raw == nil || *got.Raw != expr {
		t.Errorf("Raw not preserved: %+v", got.Raw)
	}
}

func loadSpineRule(t *testing.T) *detect.Rule {
	t.Helper()
	rules, err := detect.LoadRules("github")
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	for i := range rules {
		if rules[i].ID == "cat-01/prt-checkout-execute" {
			return &rules[i]
		}
	}
	t.Fatalf("spine rule cat-01/prt-checkout-execute not found among %d rules", len(rules))
	return nil
}

func prtJob() map[string]any {
	return map[string]any{
		"_id":                       "fr-01__ci__build",
		"triggers":                  []any{"pull_request_target"},
		"has_checkout_of_pr_ref":    true,
		"executes_checked_out_code": true,
		"if_conditions_summary":     map[string]any{"gate_strength": "weak"},
	}
}

func TestSpineRuleFiresOnPrtCheckoutExecute(t *testing.T) {
	rule := loadSpineRule(t)
	if rule.SubjectKind() != "job" {
		t.Fatalf("spine subject kind = %q, want job", rule.SubjectKind())
	}
	matched := detect.EvaluateRule(rule, []map[string]any{prtJob()}, func(err error) {
		t.Errorf("unexpected eval error: %v", err)
	})
	if len(matched) != 1 {
		t.Fatalf("spine should fire on a PRT-checkout-execute job, got %d matches", len(matched))
	}
	j := prtJob()
	j["triggers"] = []any{"issue_comment"}
	if got := detect.EvaluateRule(rule, []map[string]any{j}, nil); len(got) != 1 {
		t.Errorf("spine should fire on issue_comment + checkout + execute, got %d", len(got))
	}
}

func TestSpineRuleSilentOnBenignVariants(t *testing.T) {
	rule := loadSpineRule(t)

	type variant struct {
		name string
		mut  func(map[string]any)
	}
	variants := []variant{
		{
			"strong gate", func(j map[string]any) {
				j["if_conditions_summary"] = map[string]any{"gate_strength": "strong"}
			},
		},
		{
			"no pr-ref checkout", func(j map[string]any) {
				j["has_checkout_of_pr_ref"] = false
			},
		},
		{
			"no execution", func(j map[string]any) {
				j["executes_checked_out_code"] = false
			},
		},
		{
			"push trigger only", func(j map[string]any) {
				j["triggers"] = []any{"push"}
			},
		},
	}
	for _, v := range variants {
		j := prtJob()
		v.mut(j)
		matched := detect.EvaluateRule(rule, []map[string]any{j}, func(err error) {
			t.Errorf("[%s] unexpected eval error: %v", v.name, err)
		})
		if len(matched) != 0 {
			t.Errorf("[%s] spine should stay silent, got %d matches", v.name, len(matched))
		}
	}
}

// A missing gate_strength is not "strong", so none_of passes and the rule fires.
func TestSpineRuleFiresWhenGateFieldMissing(t *testing.T) {
	rule := loadSpineRule(t)
	j := prtJob()
	delete(j, "if_conditions_summary")
	if got := detect.EvaluateRule(rule, []map[string]any{j}, nil); len(got) != 1 {
		t.Errorf("missing gate field should not suppress the spine, got %d matches", len(got))
	}
}
