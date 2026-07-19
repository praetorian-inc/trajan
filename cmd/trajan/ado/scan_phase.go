package ado

import (
	"github.com/spf13/cobra"

	adopkg "github.com/praetorian-inc/trajan/internal/ado"
)

var (
	phasedScanPath    string
	phasedScanOrgOnly bool
)

// newPhasedScanCmd is the phased-pipeline scan: it evaluates the ADO detection
// rule corpus over a normalized run (10-normalize) and writes findings to
// 20-scan, via the shared detection engine.
func newPhasedScanCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "scan",
		Short: "Evaluate ADO detection rules over a normalized run",
		Long: `Run the phased detection engine over a normalized run directory.

Reads the 10-normalize records produced by 'ado normalize', evaluates the
embedded ADO detection-rule corpus, and writes findings to 20-scan.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return adopkg.Scan(cmd.Context(), phasedScanPath, adopkg.ScanOptions{OrgOnly: phasedScanOrgOnly})
		},
	}
	c.Flags().StringVar(&phasedScanPath, "path", "", "normalized run directory to scan")
	c.Flags().BoolVar(&phasedScanOrgOnly, "org-detections-only", false, "run only org-subject rules")
	_ = c.MarkFlagRequired("path")
	return c
}
