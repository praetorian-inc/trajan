package ado

import (
	"github.com/spf13/cobra"

	adocollect "github.com/praetorian-inc/trajan/internal/ado"
	"github.com/praetorian-inc/trajan/internal/engine"
)

// newNormalizeCmd wires the ADO normalize phase (structural node/edge records
// from the collected raw JSON) into the ado command tree.
func newNormalizeCmd() *cobra.Command {
	cfg := &engine.Config{}
	var path string
	c := &cobra.Command{
		Use:   "normalize",
		Short: "Normalize collected Azure DevOps data into structural node/edge records",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "ado", path)
			if err != nil {
				return err
			}
			return adocollect.Normalize(cmd.Context(), runDir)
		},
	}
	c.Flags().StringVar(&cfg.OutputDir, "output-dir", "./trajan-out", "run output directory")
	c.Flags().StringVarP(&path, "path", "p", "", "run directory (default: latest ado run)")
	return c
}
