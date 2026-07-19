package detect

import (
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// loadRecords reads every JSON record in a normalized directory as a generic map.
// A malformed record is a normalize-contract violation and aborts the phase.
func loadRecords(prior engine.PriorPhase, dir string) ([]map[string]any, error) {
	files, err := prior.IterJSON(dir)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(files))
	for _, f := range files {
		var rec map[string]any
		if err := json.Unmarshal(f.Data, &rec); err != nil {
			return nil, fmt.Errorf("%s: %w", f.Rel, err)
		}
		out = append(out, rec)
	}
	return out, nil
}
