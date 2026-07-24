package ado

import "testing"

// A $[ variables ] compile-keyword redirect is a real attack path only when the variable
// is confirmed queue-settable. Declared-settable is settable regardless of the limit;
// otherwise it needs the limit observed off; unobserved settings must fail closed so we
// never assert a redirect a compensating control might silently block.
func TestRuntimeVarRedirectReachable(t *testing.T) {
	rv := func(declaredSettable bool) map[string]any {
		return map[string]any{"is_declared_settable": declaredSettable}
	}
	cases := []struct {
		name string
		ps   map[string]any
		meta pipeInfo
		want bool
	}{
		{"declared settable is reachable even under the limit", rv(true), pipeInfo{enforceSettable: true, settingsObserved: true}, true},
		{"declared settable is reachable even when unobserved", rv(true), pipeInfo{settingsObserved: false}, true},
		{"not declared, limit observed off -> reachable", rv(false), pipeInfo{enforceSettable: false, settingsObserved: true}, true},
		{"not declared, limit observed on -> blocked", rv(false), pipeInfo{enforceSettable: true, settingsObserved: true}, false},
		{"not declared, settings unobserved -> fail closed", rv(false), pipeInfo{enforceSettable: false, settingsObserved: false}, false},
	}
	for _, c := range cases {
		if got := runtimeVarRedirectReachable(c.ps, c.meta); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
