package github

import (
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine/detect"
)

func loadSpineRule(t *testing.T) *detect.Rule {
	t.Helper()
	rules, err := detect.LoadRules("github", nil)
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
