package detect

import "github.com/praetorian-inc/trajan/internal/finding"

// Every func field is optional; the accessors below define the nil behavior.
type Provider struct {
	Name        string
	RuleSubtree string
	// Rule subject kind -> 10-normalize record directory (ado "pipeline" -> "pipelines").
	SubjectDirs map[string]string
	Display     func(kind string, subject map[string]any) string
	Code        func(runDir string, subject map[string]any) *finding.Code
	Repo        func(subject map[string]any) string
	File        func(subject map[string]any) string
	// Names the finding file. A platform whose subjects lack a natural _id (ADO's
	// derived-edge records) supplies this so distinct subjects don't collide.
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
