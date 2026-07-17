package ado

import (
	"github.com/spf13/cobra"

	adocollect "github.com/praetorian-inc/trajan/internal/ado"
	"github.com/praetorian-inc/trajan/internal/engine"
)

// newCollectCmd wires the new-stack Azure DevOps collector (internal/ado) into
// the ado command tree. Locator is "<org>", "<org>/<project>", or
// "<org>/<project>/<repo>"; empty falls back to the ORG_NAME env var.
func newCollectCmd() *cobra.Command {
	cfg := &engine.Config{}
	c := &cobra.Command{
		Use:   "collect [locator]",
		Short: "Collect raw Azure DevOps configuration for an org/project (phased pipeline)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			locator := ""
			if len(args) > 0 {
				locator = args[0]
			}
			_, err := adocollect.Collect(cmd.Context(), cfg, locator)
			return err
		},
	}
	c.Flags().IntVar(&cfg.Concurrency, "concurrency", 8, "max concurrent API workers")
	c.Flags().StringVar(&cfg.OutputDir, "output-dir", "./trajan-out", "run output directory")
	return c
}
