package attack

import (
	"encoding/json"
	"slices"
	"testing"
)

// A runner record as the self-hosted-runner schema documents it: ephemeral is an
// optional boolean, and every label carries a type that is read-only when
// configuration applied it and custom when an operator did.
const registeredRunner = `{
  "id": 23,
  "name": "build-01",
  "os": "linux",
  "status": "online",
  "busy": false,
  "ephemeral": false,
  "runner_group_id": 1,
  "labels": [
    {"id": 1, "name": "self-hosted", "type": "read-only"},
    {"id": 2, "name": "X64", "type": "read-only"},
    {"id": 3, "name": "Linux", "type": "read-only"},
    {"id": 4, "name": "gpu-prod", "type": "custom"}
  ]
}`

// "A non-ephemeral self-hosted runner is reachable from a low-trust context" is
// one of the highest-value findings here, and the API reports the fact directly.
// The field is optional, though, so a runner that reports none is unmeasured: false
// would answer "this runner keeps its state for the next job" for every runner
// nobody classified.
func TestRunnerEphemeralityIsReadWhenReportedAndUnmeasuredWhenNot(t *testing.T) {
	for _, tc := range []struct {
		name             string
		body             string
		known, ephemeral bool
	}{
		{"registered persistent", registeredRunner, true, false},
		{"registered ephemeral", `{"id":24,"name":"eph-01","ephemeral":true,"labels":[]}`, true, true},
		{"the field is absent", `{"id":25,"name":"old-01","labels":[]}`, false, false},
		{"the field is null", `{"id":26,"name":"odd-01","ephemeral":null,"labels":[]}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body runnerBody
			if err := json.Unmarshal([]byte(tc.body), &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			got := body.entry().Ephemeral
			if got.Known != tc.known || got.Value != tc.ephemeral {
				t.Fatalf("ephemeral = %+v, want established %t ephemeral %t", got, tc.known, tc.ephemeral)
			}
			if !got.Known && got.Reason == "" {
				t.Error("an unestablished reading must say why it could not be made")
			}
		})
	}
}

// Which labels a runs-on can target is what a targeting weakness turns on, and
// every self-hosted runner carries self-hosted plus its os and arch whether anybody
// chose them or not. An inventory that cannot tell those from gpu-prod cannot say
// what the operator exposed.
func TestRunnerLabelsSeparateWhatAnOperatorAssigned(t *testing.T) {
	var body runnerBody
	if err := json.Unmarshal([]byte(registeredRunner), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	entry := body.entry()

	if want := []string{"self-hosted", "X64", "Linux", "gpu-prod"}; !slices.Equal(entry.Labels, want) {
		t.Errorf("labels = %v, want every label the runner reports %v", entry.Labels, want)
	}
	if want := []string{"gpu-prod"}; !slices.Equal(entry.CustomLabels, want) {
		t.Errorf("custom labels = %v, want only the operator-assigned %v", entry.CustomLabels, want)
	}
	if got := body.untypedLabels(); got != 0 {
		t.Errorf("every label here carries a type, so none is unclassifiable; got %d", got)
	}
}

// A label with no type at all cannot be attributed to an operator, so it must not
// land in custom_labels — the inventory says how many it could not classify instead.
func TestUntypedLabelsAreNotCountedAsOperatorAssigned(t *testing.T) {
	var body runnerBody
	if err := json.Unmarshal([]byte(`{"id":27,"name":"ghes-01","labels":[{"name":"self-hosted"},{"name":"gpu-prod"}]}`), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := body.entry().CustomLabels; len(got) != 0 {
		t.Errorf("no label declared a type, so none is known to be operator-assigned; got %v", got)
	}
	if got := body.untypedLabels(); got != 2 {
		t.Errorf("unclassifiable labels = %d, want 2", got)
	}
}

// The inventory-wide reading is what a when: gates on. One runner reported as not
// ephemeral settles it; a negative needs every runner to have reported the field,
// or the gate would read a fleet nobody classified as one that keeps nothing.
func TestAnyPersistentNeedsEveryRunnerReadForANegative(t *testing.T) {
	persistent := Runner{Name: "build-01", Ephemeral: Measured(false)}
	ephemeral := Runner{Name: "eph-01", Ephemeral: Measured(true)}
	silent := Runner{Name: "old-01", Ephemeral: Unmeasured("no ephemeral field")}

	for _, tc := range []struct {
		name               string
		runners            []Runner
		known, anyPersists bool
	}{
		{"one persistent runner among ephemeral ones", []Runner{ephemeral, persistent}, true, true},
		{"a persistent runner settles it even beside an unclassified one", []Runner{silent, persistent}, true, true},
		{"every runner reported itself ephemeral", []Runner{ephemeral, ephemeral}, true, false},
		{"one runner reported nothing and none is persistent", []Runner{ephemeral, silent}, false, false},
		{"no runners at all", nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := anyPersistent(tc.runners)
			if got.Known != tc.known || got.Value != tc.anyPersists {
				t.Fatalf("any_persistent = %+v, want established %t persistent %t", got, tc.known, tc.anyPersists)
			}
			if !got.Known && got.Reason == "" {
				t.Error("an unestablished reading must say why it could not be made")
			}
		})
	}
}
