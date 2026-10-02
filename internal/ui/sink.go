package ui

type Sink interface {
	Item(string)
	Note(string)
	Error(msg, remedy string)
	Severities(map[string]int)
	Head(subject string, fields ...[2]string)
	Section(string)
	PhaseHeader(string)
	Step(StepLine)
	Row(RowLine)
	Outcome(subject string, counts []Count, trailer string)
}

var _ Sink = (*Printer)(nil)

type discard struct{}

func (discard) Item(string)                     {}
func (discard) Note(string)                     {}
func (discard) Error(string, string)            {}
func (discard) Severities(map[string]int)       {}
func (discard) Head(string, ...[2]string)       {}
func (discard) Section(string)                  {}
func (discard) PhaseHeader(string)              {}
func (discard) Step(StepLine)                   {}
func (discard) Row(RowLine)                     {}
func (discard) Outcome(string, []Count, string) {}

var Discard Sink = discard{}

func Std() Sink { return std }
