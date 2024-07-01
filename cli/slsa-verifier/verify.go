// Copyright 2022 SLSA Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier/verify"
	"github.com/spf13/cobra"
)

const (
	SUCCESS = "PASSED: SLSA verification passed"
	FAILURE = "FAILED: SLSA verification failed"
)

func verifyArtifactCmd() *cobra.Command {
	o := &verify.VerifyOptions{}

	cmd := &cobra.Command{
		Use: "verify-artifact [flags] artifact [artifact..]",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("expects at least one artifact")
			}
			return nil
		},
		Short: "Verifies SLSA provenance on artifact blobs given as arguments (assuming same provenance)",
		Run: func(cmd *cobra.Command, args []string) {
			v := verify.VerifyArtifactCommand{
				ProvenancePath:      o.ProvenancePath,
				SourceURI:           o.SourceURI,
				PrintProvenance:     o.PrintProvenance,
				BuildWorkflowInputs: o.BuildWorkflowInputs.AsMap(),
			}
			if cmd.Flags().Changed("source-branch") {
				v.SourceBranch = &o.SourceBranch
			}
			if cmd.Flags().Changed("source-tag") {
				v.SourceTag = &o.SourceTag
			}
			if cmd.Flags().Changed("source-versioned-tag") {
				v.SourceVersionTag = &o.SourceVersionTag
			}
			if cmd.Flags().Changed("builder-id") {
				v.BuilderID = &o.BuilderID
			}

			if _, err := v.Exec(cmd.Context(), args); err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", FAILURE, err)
				os.Exit(1)
			} else {
				fmt.Fprintf(os.Stderr, "%s\n", SUCCESS)
			}
		},
	}

	o.AddFlags(cmd)
	// --provenance-path must be supplied when verifying an artifact.
	cmd.MarkFlagRequired("provenance-path")
	return cmd
}

func verifyImageCmd() *cobra.Command {
	o := &verify.VerifyOptions{}

	cmd := &cobra.Command{
		Use: "verify-image [flags] image",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("expects a single path to an image")
			}
			return nil
		},
		Short: "Verifies SLSA provenance on a container image",
		Run: func(cmd *cobra.Command, args []string) {
			v := verify.VerifyImageCommand{
				SourceURI:           o.SourceURI,
				PrintProvenance:     o.PrintProvenance,
				BuildWorkflowInputs: o.BuildWorkflowInputs.AsMap(),
			}
			if cmd.Flags().Changed("provenance-path") {
				v.ProvenancePath = &o.ProvenancePath
			}
			if cmd.Flags().Changed("provenance-repository") {
				v.ProvenanceRepository = &o.ProvenanceRepository
			}
			if cmd.Flags().Changed("source-branch") {
				v.SourceBranch = &o.SourceBranch
			}
			if cmd.Flags().Changed("source-tag") {
				v.SourceTag = &o.SourceTag
			}
			if cmd.Flags().Changed("source-versioned-tag") {
				v.SourceVersionTag = &o.SourceVersionTag
			}
			if cmd.Flags().Changed("builder-id") {
				v.BuilderID = &o.BuilderID
			}

			if _, err := v.Exec(cmd.Context(), args); err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", FAILURE, err)
				os.Exit(1)
			} else {
				fmt.Fprintf(os.Stderr, "%s\n", SUCCESS)
			}
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func verifyNpmPackageCmd() *cobra.Command {
	o := &verify.VerifyNpmOptions{}

	cmd := &cobra.Command{
		Use: "verify-npm-package [flags] tarball",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("expects a single path to an image")
			}
			return nil
		},
		Short: "Verifies SLSA provenance for an npm package tarball [experimental]",
		Run: func(cmd *cobra.Command, args []string) {
			v := verify.VerifyNpmPackageCommand{
				SourceURI:           o.SourceURI,
				PrintProvenance:     o.PrintProvenance,
				BuildWorkflowInputs: o.BuildWorkflowInputs.AsMap(),
			}
			if cmd.Flags().Changed("attestations-path") {
				v.AttestationsPath = o.AttestationsPath
			}
			if cmd.Flags().Changed("package-name") {
				v.PackageName = &o.PackageName
			}
			if cmd.Flags().Changed("package-version") {
				v.PackageVersion = &o.PackageVersion
			}
			if cmd.Flags().Changed("source-branch") {
				fmt.Fprintf(os.Stderr, "%s: --source-branch not supported\n", FAILURE)
				os.Exit(1)
			}
			if cmd.Flags().Changed("source-tag") {
				fmt.Fprintf(os.Stderr, "%s: --source-tag not supported\n", FAILURE)
				os.Exit(1)
			}
			if cmd.Flags().Changed("source-versioned-tag") {
				fmt.Fprintf(os.Stderr, "%s: --source-versioned-tag not supported\n", FAILURE)
				os.Exit(1)
			}
			if cmd.Flags().Changed("print-provenance") {
				fmt.Fprintf(os.Stderr, "%s: --print-provenance not supported\n", FAILURE)
				os.Exit(1)
			}
			if cmd.Flags().Changed("builder-id") {
				v.BuilderID = &o.BuilderID
			}

			if _, err := v.Exec(cmd.Context(), args); err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", FAILURE, err)
				os.Exit(1)
			} else {
				fmt.Fprintf(os.Stderr, "%s\n", SUCCESS)
			}
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func verifyVSACmd() *cobra.Command {
	o := &verify.VerifyVSAOptions{}

	cmd := &cobra.Command{
		Use:   "verify-vsa [flags] subject-digest [subject-digest...]",
		Args:  cobra.NoArgs,
		Short: "Verifies SLSA VSAs for the given subject-digests",
		Run: func(cmd *cobra.Command, args []string) {
			v := verify.VerifyVSACommand{
				SubjectDigests:   &o.SubjectDigests,
				AttestationPath:  &o.AttestationPath,
				VerifierID:       &o.VerifierID,
				ResourceURI:      &o.ResourceURI,
				VerifiedLevels:   &o.VerifiedLevels,
				PrintAttestation: o.PrintAttestation,
				PublicKeyPath:    &o.PublicKeyPath,
				PublicKeyID:      &o.PublicKeyID,
			}
			if err := v.Exec(cmd.Context()); err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", FAILURE, err)
				os.Exit(1)
			} else {
				fmt.Fprintf(os.Stderr, "%s\n", SUCCESS)
			}
		},
	}

	o.AddFlags(cmd)
	return cmd
}
