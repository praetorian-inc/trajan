package detect

import "github.com/praetorian-inc/trajan/internal/finding"

// Provider supplies the per-platform specifics the shared detection engine needs.
// The engine (rule DSL, getPath, evaluation, finding construction) is generic;
// each platform (github, ado, …) contributes a Provider so one engine serves all.
type Provider struct {
	// Name is the finding.Provider label ("github" | "ado" | …).
	Name string
	// RuleSubtree is the detection-rules/<subtree> the rule loader walks.
	RuleSubtree string
	// SubjectDirs maps a rule subject kind to its 10-normalize record directory
	// (e.g. github "job" -> "jobs"; ado "pipeline" -> "pipelines").
	SubjectDirs map[string]string
	// Display renders the finding's subject label; nil falls back to subject._id.
	Display func(kind string, subject map[string]any) string
	// Code embeds the source snippet a finding points at; nil emits no code.
	Code func(runDir string, subject map[string]any) *finding.Code
	// Repo / File extract those finding fields; nil leaves them empty.
	Repo func(subject map[string]any) string
	File func(subject map[string]any) string
	// SubjectKey returns a stable, unique identity string for a subject, used to
	// name the finding file. nil falls back to SubjectHash (_id/repo/json). A
	// platform whose subjects lack a natural _id (e.g. ADO's derived-edge records)
	// supplies this so distinct subjects don't collide to one finding.
	SubjectKey func(subject map[string]any) string
}

func (p Provider) subjectHash(subject map[string]any) string {
	if p.SubjectKey != nil {
		return hash12(p.SubjectKey(subject))
	}
	return SubjectHash(subject)
}

func (p Provider) display(kind string, subject map[string]any) string {
	if p.Display != nil {
		return p.Display(kind, subject)
	}
	return StringField(subject, "_id")
}

func (p Provider) code(runDir string, subject map[string]any) *finding.Code {
	if p.Code != nil {
		return p.Code(runDir, subject)
	}
	return nil
}

func (p Provider) repo(subject map[string]any) string {
	if p.Repo != nil {
		return p.Repo(subject)
	}
	return ""
}

func (p Provider) file(subject map[string]any) string {
	if p.File != nil {
		return p.File(subject)
	}
	return ""
}
