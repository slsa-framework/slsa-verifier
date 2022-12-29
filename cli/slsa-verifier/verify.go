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
	SUCCESS = "PASSED: Verified SLSA provenance"
	FAILURE = "FAILED: SLSA verification failed"
)

func verifyArtifactCmd() *cobra.Command {
	o := &verify.VerifyOptions{}

	cmd := &cobra.Command{
		Use:   "verify-artifact [flags] artifact [artifact..]",
		Short: "Verifies SLSA provenance on artifact blobs given as arguments (assuming same provenance)",
		RunE: func(cmd *cobra.Command, args []string) error {
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
				return err
			}

			fmt.Fprintf(os.Stderr, "%s\n", SUCCESS)
			return nil
		},
	}

	o.AddFlags(cmd)
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
		RunE: func(cmd *cobra.Command, args []string) error {
			v := verify.VerifyImageCommand{
				SourceURI:           o.SourceURI,
				PrintProvenance:     o.PrintProvenance,
				BuildWorkflowInputs: o.BuildWorkflowInputs.AsMap(),
			}
			if cmd.Flags().Changed("provenance-path") {
				v.ProvenancePath = &o.ProvenancePath
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
				return err
			}

			fmt.Fprintf(os.Stderr, "%s\n", SUCCESS)
			return nil
		},
	}

	o.AddFlags(cmd)
	return cmd
}
