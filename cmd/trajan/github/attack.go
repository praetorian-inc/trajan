package github

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/attack"
	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/ui"
)

func newAttackCmd(cfg *engine.Config) *cobra.Command {
	attackCmd := &cobra.Command{
		Use:   "attack",
		Short: "Author, validate and run authorized verification chains",
	}

	var catalogJSON bool
	catalog := &cobra.Command{
		Use:   "catalog",
		Short: "List the primitive registry (the prompt source for plan authoring)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if catalogJSON {
				b, err := json.MarshalIndent(attack.CatalogViews(), "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return nil
			}
			for _, v := range attack.CatalogViews() {
				printCatalogEntry(cmd, v)
			}
			return nil
		},
	}
	catalog.Flags().BoolVar(&catalogJSON, "json", false, "emit the full registry as JSON")

	planCmd := &cobra.Command{Use: "plan", Short: "Work with attack plans"}

	var validateSetFile string
	var validateSetValues []string
	planValidate := &cobra.Command{
		Use:   "validate <plan|template-id>",
		Short: "Validate a plan file or embedded template offline, reporting every error at once",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadPlanWithInputs(args[0], validateSetValues, validateSetFile)
			if err != nil {
				return err
			}
			var hardErrors int
			for _, e := range attack.Validate(p) {
				if attack.IsWarning(e) {
					ui.Item("warning: " + e.Error())
					continue
				}
				hardErrors++
				ui.Item("error: " + e.Error())
			}
			if hardErrors > 0 {
				return fmt.Errorf("plan %q: %d validation error(s)", p.ID, hardErrors)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: valid\n", p.ID)
			return nil
		},
	}
	planValidate.Flags().StringArrayVar(&validateSetValues, "set", nil, "set an input: --set key=value (repeatable)")
	planValidate.Flags().StringVar(&validateSetFile, "set-file", "", "YAML file of input values")

	planList := &cobra.Command{
		Use:   "list",
		Short: "List the embedded plan templates",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ids, err := attack.ListTemplates()
			if err != nil {
				return err
			}
			for _, id := range ids {
				fmt.Fprintln(cmd.OutOrStdout(), id)
			}
			return nil
		},
	}

	var runPath, setFile, until string
	var setValues []string
	var dryRun, execute, keepCipher bool
	var stepDelay time.Duration
	run := &cobra.Command{
		Use:   "run <plan|template-id>",
		Short: "Run a plan. Dry run unless --execute is passed",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRun && execute {
				return fmt.Errorf("--dry-run and --execute are mutually exclusive")
			}
			p, err := loadPlanWithInputs(args[0], setValues, setFile)
			if err != nil {
				return err
			}
			_, err = attack.Run(cmd.Context(), cfg, p, attack.RunOptions{
				RunDir: runPath, Execute: execute,
				Until: until, StepDelay: stepDelay, KeepCipher: keepCipher,
			})
			return err
		},
	}
	run.Flags().StringVarP(&runPath, "path", "p", "", "attach to an existing run directory (default: mint one)")
	run.Flags().StringArrayVar(&setValues, "set", nil, "set an input: --set key=value (repeatable)")
	run.Flags().StringVar(&setFile, "set-file", "", "YAML file of input values")
	run.Flags().BoolVar(&dryRun, "dry-run", false, "render every mutation without sending one (the default)")
	run.Flags().BoolVar(&execute, "execute", false, "issue mutations against the target; passing it is the authorization assertion")
	run.Flags().StringVar(&until, "until", "", "run up to and including this step id, then stop; cleanup is left for the resume")
	run.Flags().DurationVar(&stepDelay, "step-delay", 0, "sleep between steps to absorb read-after-write propagation lag")
	run.Flags().BoolVar(&keepCipher, "keep-cipher", false, "keep the harvest's persisted ciphertext after a successful decrypt instead of discarding it")
	run.Flags().StringVar(&cfg.Token, "token", "", "API token (prefer TRAJAN_GH_TOKEN/GH_TOKEN/GITHUB_TOKEN env; this flag is an escape hatch)")

	var resumePath, resumeUntil string
	var resumeKeepCipher bool
	var resumeDelay time.Duration
	resume := &cobra.Command{
		Use:   "resume [<plan-id>]",
		Short: "Resume a run: completed steps are skipped and a killed watch resumes the watch",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "gh", resumePath)
			if err != nil {
				return err
			}
			opts := attack.RunOptions{RunDir: runDir, Until: resumeUntil, StepDelay: resumeDelay, KeepCipher: resumeKeepCipher}
			if len(args) == 1 {
				opts.PlanID = args[0]
			}
			_, err = attack.Resume(cmd.Context(), cfg, opts)
			return err
		},
	}
	resume.Flags().StringVarP(&resumePath, "path", "p", "", "run directory to resume (default: latest)")
	resume.Flags().StringVar(&resumeUntil, "until", "", "resume up to and including this step id, then stop again")
	resume.Flags().DurationVar(&resumeDelay, "step-delay", 0, "sleep between steps to absorb read-after-write propagation lag")
	resume.Flags().BoolVar(&resumeKeepCipher, "keep-cipher", false, "keep the harvest's persisted ciphertext after a successful decrypt instead of discarding it")
	resume.Flags().StringVar(&cfg.Token, "token", "", "API token (prefer TRAJAN_GH_TOKEN/GH_TOKEN/GITHUB_TOKEN env; this flag is an escape hatch)")

	var cleanupPath string
	var cleanupDryRun bool
	cleanup := &cobra.Command{
		Use:   "cleanup [<plan-id>]",
		Short: "Replay a run's recorded inverses and report what was and was not undone",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "gh", cleanupPath)
			if err != nil {
				return err
			}
			var planID string
			if len(args) == 1 {
				planID = args[0]
			}
			report, err := attack.Cleanup(cmd.Context(), attack.CleanupOptions{
				RunDir: runDir, PlanID: planID, DryRun: cleanupDryRun, Token: cfg.Token,
			})
			if report != nil {
				printCleanup(cmd, report)
			}
			return err
		},
	}
	cleanup.Flags().StringVarP(&cleanupPath, "path", "p", "", "run directory to clean up (default: latest)")
	cleanup.Flags().BoolVar(&cleanupDryRun, "dry-run", false, "list the inverses without issuing them")
	cleanup.Flags().StringVar(&cfg.Token, "token", "", "API token (prefer TRAJAN_GH_TOKEN/GH_TOKEN/GITHUB_TOKEN env; this flag is an escape hatch)")

	planCmd.AddCommand(planValidate, planList)
	attackCmd.AddCommand(catalog, planCmd, run, resume, cleanup, newIdentityCmd())
	return attackCmd
}

func printCleanup(_ *cobra.Command, r *attack.CleanupReport) {
	ui.Head(r.Plan, [2]string{"mode", r.Mode})
	// reversed is counted and not itemized: a resource that is as it was needs no
	// line. The three buckets below are what the operator still has to act on.
	for _, section := range []struct {
		label string
		items []attack.CleanupItem
	}{
		{"partial", r.Partial},
		{"irreversible", r.Irreversible},
		{"failed", r.Failed},
	} {
		if len(section.items) > 0 {
			ui.Section(section.label)
		}
		for _, it := range section.items {
			ui.Item(strings.TrimSpace(strings.Join([]string{
				it.Step, strings.TrimSpace(it.Method + " " + it.Path), it.Detail, it.Error,
			}, " ")))
		}
	}
	ui.Outcome("cleanup complete", []ui.Count{
		{Label: "failed", N: len(r.Failed)},
		{Label: "irreversible", N: len(r.Irreversible)},
		{Label: "partial", N: len(r.Partial)},
		{Label: "reversed", N: len(r.Reversed)},
	}, "")
	ui.Note(r.PlanDir)
}

func newIdentityCmd() *cobra.Command {
	identityCmd := &cobra.Command{Use: "identity", Short: "Manage the credential store (~/.trajan/identities.json)"}

	var kind, tokenEnv, note string
	add := &cobra.Command{
		Use:   "add <name>",
		Short: "Add or replace an identity; the secret is read from stdin or --token-env, never argv",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !attack.ValidIdentityKind(kind) {
				return fmt.Errorf("--kind %q must be one of %s", kind, strings.Join(attack.IdentityKinds(), "|"))
			}
			token, err := readSecret(cmd, tokenEnv)
			if err != nil {
				return err
			}
			st, err := attack.LoadIdentityStore()
			if err != nil {
				return err
			}
			st.Put(attack.StoredIdentity{
				Name:    args[0],
				Kind:    kind,
				Token:   token,
				Note:    note,
				AddedAt: engine.IsoformatUTC(time.Now()),
			})
			if err := st.Save(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "stored %s (%s) in %s\n", args[0], kind, st.Path())
			return nil
		},
	}
	add.Flags().StringVar(&kind, "kind", "pat", strings.Join(attack.IdentityKinds(), "|"))
	add.Flags().StringVar(&tokenEnv, "token-env", "", "read the secret from this environment variable instead of stdin")
	add.Flags().StringVar(&note, "note", "", "free-text note")

	list := &cobra.Command{
		Use:   "list",
		Short: "List stored identities (never their secrets)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := attack.LoadIdentityStore()
			if err != nil {
				return err
			}
			if len(st.Identities) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "no identities in %s\n", st.Path())
				return nil
			}
			for _, si := range st.Identities {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\n", si.Name, si.Kind, si.AddedAt, si.Note)
			}
			return nil
		},
	}

	rm := &cobra.Command{
		Use:   "rm <name>",
		Short: "Remove an identity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := attack.LoadIdentityStore()
			if err != nil {
				return err
			}
			if !st.Remove(args[0]) {
				return fmt.Errorf("no identity named %q", args[0])
			}
			if err := st.Save(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", args[0])
			return nil
		},
	}

	identityCmd.AddCommand(add, list, rm)
	return identityCmd
}

// readSecret takes the secret from an environment variable or stdin. It is never
// an argument: argv is world-readable on a shared host and lands in shell history.
func readSecret(cmd *cobra.Command, tokenEnv string) (string, error) {
	if tokenEnv != "" {
		v := strings.TrimSpace(os.Getenv(tokenEnv))
		if v == "" {
			return "", fmt.Errorf("environment variable %s is empty", tokenEnv)
		}
		return v, nil
	}
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprint(cmd.ErrOrStderr(), "token: ")
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("no secret on stdin (pipe it, or pass --token-env)")
	}
	return v, nil
}

// Validation and running resolve inputs identically, so a plan that validates
// clean is one the same arguments would run.
func loadPlanWithInputs(ref string, setValues []string, setFile string) (*attack.Plan, error) {
	p, err := attack.LoadPlan(ref)
	if err != nil {
		return nil, err
	}
	if p.SetValues, err = parseSetValues(setValues); err != nil {
		return nil, err
	}
	if setFile != "" {
		if p.SetFileValues, err = attack.LoadValues(setFile); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func parseSetValues(pairs []string) (map[string]string, error) {
	out := map[string]string{}
	for _, kv := range pairs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--set %q must be key=value", kv)
		}
		out[k] = v
	}
	return out, nil
}

func printCatalogEntry(cmd *cobra.Command, v attack.CatalogView) {
	mut := ""
	if v.Mutating {
		mut = " [mutating]"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s → %s%s\n", v.Name, v.Produces, mut)
	fmt.Fprintf(cmd.OutOrStdout(), "    %s\n", v.Summary)
	if len(v.OneOf) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "    bind exactly one of: %s\n", strings.Join(v.OneOf, ", "))
	}
	if v.AppOnly {
		fmt.Fprintln(cmd.OutOrStdout(), "    only a GitHub App installation token can issue this; a PAT is refused offline")
	}
	for _, in := range v.Inputs {
		if in.Kind == "port" {
			req := ""
			if in.Required {
				req = " (required)"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "    port  %s: %s%s ← %v\n", in.Name, in.Iface, req, in.SatisfiedBy)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "    field %s: %s\n", in.Name, in.Type)
		}
	}
}
