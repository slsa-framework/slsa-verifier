package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"
)

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func envWarnings() {
	if options.TestingEnabled() {
		fmt.Fprintf(os.Stderr, "WARNING: Insecure SLSA_VERIFIER_TESTING is enabled.\n")
	}
}

func rootCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "slsa-verifier",
		Short: "Verify SLSA provenance for Github Actions",
		Long: `Verify SLSA provenance for Github Actions.
For more information on SLSA, visit https://slsa.dev`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("expected command")
		},
	}
	c.AddCommand(version.Version())
	c.AddCommand(verifyArtifactCmd())
	c.AddCommand(verifyImageCmd())
	c.AddCommand(verifyNpmPackageCmd())
	// We print our own errors and usage in the check function.
	c.SilenceErrors = true
	return c
}

func main() {
	envWarnings()
	check(rootCmd().Execute())
}
