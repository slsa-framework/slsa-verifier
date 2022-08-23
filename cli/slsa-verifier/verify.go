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

	"github.com/slsa-framework/slsa-verifier/cli/slsa-verifier/verify"
	"github.com/spf13/cobra"
)

func verifyArtifactCmd() *cobra.Command {
	o := &verify.VerifyOptions{}

	cmd := &cobra.Command{
		Use: "verify-artifact",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("requires a path to an artifact")
			}
			return nil
		},
		Short: "Verifies SLSA provenance on an artifact blob",
		RunE: func(cmd *cobra.Command, args []string) error {
			v := verify.VerifyArtifactCommand{
				ProvenancePath:  o.ProvenancePath,
				Source:          o.Source,
				PrintProvenance: o.PrintProvenance,
				Inputs:          o.Inputs.AsMap(),
			}
			if cmd.Flags().Changed("branch") {
				v.Tag = &o.Branch
			}
			if cmd.Flags().Changed("tag") {
				v.Tag = &o.Tag
			}
			if cmd.Flags().Changed("versioned-tag") {
				v.VersionTag = &o.VersionTag
			}
			if cmd.Flags().Changed("builder-id") {
				if !ExperimentalEnabled() {
					return fmt.Errorf("builder-id only supported with experimental flag")
				}
				v.BuilderID = &o.BuilderID
			}

			return v.Exec(cmd.Context(), args)
		},
	}

	o.AddFlags(cmd)
	cmd.MarkFlagRequired("provenance-path")
	return cmd
}

func verifyImageCmd() *cobra.Command {
	o := &verify.VerifyOptions{}

	cmd := &cobra.Command{
		Use: "verify-image",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("requires a path to an image")
			}
			return nil
		},
		Short: "Verifies SLSA provenance on a container image",
		RunE: func(cmd *cobra.Command, args []string) error {
			v := verify.VerifyImageCommand{
				Source:          o.Source,
				PrintProvenance: o.PrintProvenance,
				Inputs:          o.Inputs.AsMap(),
			}
			if cmd.Flags().Changed("provenance-path") {
				v.ProvenancePath = &o.ProvenancePath
			}
			if cmd.Flags().Changed("branch") {
				v.Tag = &o.Branch
			}
			if cmd.Flags().Changed("tag") {
				v.Tag = &o.Tag
			}
			if cmd.Flags().Changed("versioned-tag") {
				v.VersionTag = &o.VersionTag
			}
			if cmd.Flags().Changed("builder-id") {
				if !ExperimentalEnabled() {
					return fmt.Errorf("builder-id only supported with experimental flag")
				}
				v.BuilderID = &o.BuilderID
			}

			return v.Exec(cmd.Context(), args)
		},
	}

	o.AddFlags(cmd)
	return cmd
}
