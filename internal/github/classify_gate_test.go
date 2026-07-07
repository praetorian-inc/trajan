package github

import "testing"

type gateWant struct {
	strength    string
	pseudoConc  bool
	label       bool
	authorAssoc bool
}

func checkGate(t *testing.T, ifExpr *string, w gateWant) {
	t.Helper()
	got := classifyGate(ifExpr)
	if got.GateStrength != w.strength {
		t.Errorf("classifyGate(%s) strength = %q, want %q", quoteGate(ifExpr), got.GateStrength, w.strength)
	}
	gc := got.GateClassifiers
	if gc.IsPseudoGateConclusion != w.pseudoConc || gc.IsLabelGate != w.label || gc.IsAuthorAssocGate != w.authorAssoc {
		t.Errorf("classifyGate(%s) classifiers = {pseudo:%v label:%v authorAssoc:%v}, want {pseudo:%v label:%v authorAssoc:%v}",
			quoteGate(ifExpr), gc.IsPseudoGateConclusion, gc.IsLabelGate, gc.IsAuthorAssocGate,
			w.pseudoConc, w.label, w.authorAssoc)
	}
	if (got.Raw == nil) != (ifExpr == nil) {
		t.Errorf("classifyGate Raw nil-ness mismatch: got %v want %v", got.Raw, ifExpr)
	}
	if got.Raw != nil && ifExpr != nil && *got.Raw != *ifExpr {
		t.Errorf("classifyGate Raw = %q, want %q (must NOT be trimmed/lowercased)", *got.Raw, *ifExpr)
	}
}

func quoteGate(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return "\"" + *p + "\""
}

func TestGateNone(t *testing.T) {
	checkGate(t, nil, gateWant{strength: "none"})
	checkGate(t, ptr(""), gateWant{strength: "none"})
	checkGate(t, ptr("true"), gateWant{strength: "none"})
	checkGate(t, ptr("  true  "), gateWant{strength: "none"})
	checkGate(t, ptr("TRUE"), gateWant{strength: "none"})
	checkGate(t, ptr("${{ true }}"), gateWant{strength: "none"})
	checkGate(t, ptr("${{ TRUE }}"), gateWant{strength: "none"})
}

func TestGatePseudoConclusion(t *testing.T) {
	checkGate(t, ptr("github.event.workflow_run.conclusion == 'success'"),
		gateWant{strength: "pseudo", pseudoConc: true})
	checkGate(t, ptr("workflow_run.conclusion == 'success'"),
		gateWant{strength: "pseudo", pseudoConc: true})
	checkGate(t, ptr("github.event.Workflow_Run.Conclusion == 'success'"),
		gateWant{strength: "pseudo", pseudoConc: true})
}

func TestGatePseudoBeatsStrongAndAuthorAssoc(t *testing.T) {
	// pseudo outranks the strong actor==repository_owner check ANDed alongside it.
	expr := "github.event.workflow_run.conclusion == 'success' && " +
		"github.event.workflow_run.actor.login == github.repository_owner"
	checkGate(t, ptr(expr), gateWant{strength: "pseudo", pseudoConc: true})

	expr2 := "github.event.workflow_run.conclusion == 'success' && github.event.pull_request.author_association == 'MEMBER'"
	checkGate(t, ptr(expr2), gateWant{strength: "pseudo", pseudoConc: true})
}

func TestGateLabel(t *testing.T) {
	checkGate(t, ptr("contains(github.event.pull_request.labels.*.name, 'safe-to-test')"),
		gateWant{strength: "weak", label: true})
	checkGate(t, ptr("github.event.label.name == 'approved'"),
		gateWant{strength: "weak", label: true})
	checkGate(t, ptr("github.event.pull_request.labels[0].name == 'ok'"),
		gateWant{strength: "weak", label: true})
	checkGate(t, ptr("contains ( github.event.pull_request.labels.*.name , 'x')"),
		gateWant{strength: "weak", label: true})
	checkGate(t, ptr("contains(github.event.pull_request.LABELS.*.name, 'x')"),
		gateWant{strength: "weak", label: true})
}

func TestGateAuthorAssociation(t *testing.T) {
	checkGate(t, ptr("github.event.pull_request.author_association == 'MEMBER'"),
		gateWant{strength: "weak", authorAssoc: true})
	checkGate(t, ptr("github.event.comment.AUTHOR_ASSOCIATION == 'OWNER'"),
		gateWant{strength: "weak", authorAssoc: true})
}

func TestGateAuthorAssocBeatsStrongFromJSON(t *testing.T) {
	// fromJSON( here would match the strong regex, but author_assoc is tested
	// first, so this must classify weak (reordering would suppress a real bypass).
	expr := `contains(fromJSON('["OWNER","MEMBER","COLLABORATOR","CONTRIBUTOR","FIRST_TIME_CONTRIBUTOR"]'), github.event.pull_request.author_association)`
	checkGate(t, ptr(expr), gateWant{strength: "weak", authorAssoc: true})
}

func TestGateLabelBeatsAuthorAssoc(t *testing.T) {
	// label predicate + author_association substring in one expr: label wins.
	expr := "contains(github.event.pull_request.labels.*.name, 'ok') && github.event.pull_request.author_association == 'MEMBER'"
	checkGate(t, ptr(expr), gateWant{strength: "weak", label: true})
}

func TestGateStrong(t *testing.T) {
	checkGate(t, ptr("github.actor == 'trusted-bot'"),
		gateWant{strength: "strong"})
	checkGate(t, ptr(`github.actor=="dependabot[bot]"`),
		gateWant{strength: "strong"})
	checkGate(t, ptr("github.actor   ==   'release-manager'"),
		gateWant{strength: "strong"})
	checkGate(t, ptr(`contains(fromJSON('["alice","bob"]'), github.actor)`),
		gateWant{strength: "strong"})
	checkGate(t, ptr("github.repository_owner == 'acme'"),
		gateWant{strength: "strong"})
}

func TestGateStrongIsCaseSensitive(t *testing.T) {
	// Strong patterns match the original-case expr, so uppercased forms fall to weak.
	checkGate(t, ptr("github.ACTOR == 'trusted-bot'"),
		gateWant{strength: "weak"})
	checkGate(t, ptr("GITHUB.REPOSITORY_OWNER == 'acme'"),
		gateWant{strength: "weak"})
}

func TestGateStrongActorRequiresQuotedLiteral(t *testing.T) {
	// actor compared to another context (no quoted literal) is not an allowlist.
	checkGate(t, ptr("github.actor == github.repository_owner"),
		gateWant{strength: "weak"})
	// Empty literal '' has no inner char for the regex's [^'"]+.
	checkGate(t, ptr("github.actor == ''"),
		gateWant{strength: "weak"})
}

func TestGateStrongRepositoryOwnerSpacingExact(t *testing.T) {
	// repository_owner is a plain substring with exactly one space before ==,
	// so any other spacing misses it and falls to weak.
	checkGate(t, ptr("github.repository_owner  == 'acme'"),
		gateWant{strength: "weak"})
	checkGate(t, ptr("github.repository_owner== 'acme'"),
		gateWant{strength: "weak"})
}

func TestGateWeakDefault(t *testing.T) {
	checkGate(t, ptr("github.event_name == 'push'"),
		gateWant{strength: "weak"})
	checkGate(t, ptr("startsWith(github.event.comment.body, '/deploy')"),
		gateWant{strength: "weak"})
	checkGate(t, ptr("${{ github.ref == 'refs/heads/main' }}"),
		gateWant{strength: "weak"})
	// "false" is not a recognized none form (only true / ${{ true }}).
	checkGate(t, ptr("false"),
		gateWant{strength: "weak"})
}
