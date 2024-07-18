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

package verify

import (
	"fmt"
	"strings"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/spf13/cobra"
)

type Interface interface {
	// AddFlags adds this options' flags to the cobra command.
	AddFlags(cmd *cobra.Command)
}

// VerifyOptions is the top-level options for all `verify` commands.
type VerifyOptions struct {
	/* Source requirements */
	SourceURI        string
	SourceBranch     string
	SourceTag        string
	SourceVersionTag string
	/* Builder Requirements */
	BuildWorkflowInputs workflowInputs
	BuilderID           string
	/* Other */
	ProvenancePath       string
	ProvenanceRepository string
	PrintProvenance      bool
}

var _ Interface = (*VerifyOptions)(nil)

// AddFlags implements Interface.
func (o *VerifyOptions) AddFlags(cmd *cobra.Command) {
	/* Builder options */
	cmd.Flags().Var(&o.BuildWorkflowInputs, "build-workflow-input",
		"[optional] a workflow input provided by a user at trigger time in the format 'key=value'. (Only for 'workflow_dispatch' events on GitHub Actions).")

	cmd.Flags().StringVar(&o.BuilderID, "builder-id", "", "[optional] the unique builder ID who created the provenance")

	/* Source options */
	cmd.Flags().StringVar(&o.SourceURI, "source-uri", "",
		"expected source repository that should have produced the binary, e.g. github.com/some/repo")

	cmd.Flags().StringVar(&o.SourceBranch, "source-branch", "", "[optional] expected branch the binary was compiled from")

	cmd.Flags().StringVar(&o.SourceTag, "source-tag", "", "[optional] expected tag the binary was compiled from")

	cmd.Flags().StringVar(&o.SourceVersionTag, "source-versioned-tag", "",
		"[optional] expected version the binary was compiled from. Uses semantic version to match the tag")

	/* Other options */
	cmd.Flags().StringVar(&o.ProvenancePath, "provenance-path", "",
		"path to a provenance file")

	cmd.Flags().StringVar(&o.ProvenanceRepository, "provenance-repository", "",
		"image repository for provenance with format: <registry>/<repository>")

	cmd.Flags().BoolVar(&o.PrintProvenance, "print-provenance", false,
		"[optional] print the verified provenance to stdout")

	cmd.MarkFlagRequired("source-uri")
	cmd.MarkFlagsMutuallyExclusive("source-versioned-tag", "source-tag")
}

// VerifyNpmOptions is the top-level options for the `verifyNpmPackage` command.
type VerifyNpmOptions struct {
	VerifyOptions
	/* Other */
	AttestationsPath string
	PackageName      string
	PackageVersion   string
}

var _ Interface = (*VerifyNpmOptions)(nil)

// AddFlags implements Interface.
func (o *VerifyNpmOptions) AddFlags(cmd *cobra.Command) {
	/* Builder options */
	cmd.Flags().Var(&o.BuildWorkflowInputs, "build-workflow-input",
		"[optional] a workflow input provided by a user at trigger time in the format 'key=value'. (Only for 'workflow_dispatch' events on GitHub Actions).")

	cmd.Flags().StringVar(&o.BuilderID, "builder-id", "", "[optional] the unique builder ID who created the provenance")

	/* Source options */
	cmd.Flags().StringVar(&o.SourceURI, "source-uri", "",
		"expected source repository that should have produced the binary, e.g. github.com/some/repo")

	cmd.Flags().StringVar(&o.SourceBranch, "source-branch", "", "[optional] expected branch the binary was compiled from")

	cmd.Flags().StringVar(&o.SourceTag, "source-tag", "", "[optional] expected tag the binary was compiled from")

	cmd.Flags().StringVar(&o.SourceVersionTag, "source-versioned-tag", "",
		"[optional] expected version the binary was compiled from. Uses semantic version to match the tag")

	cmd.Flags().StringVar(&o.AttestationsPath, "attestations-path", "",
		"path to a file containing the attestations")

	cmd.Flags().StringVar(&o.PackageName, "package-name", "",
		"the package name")

	cmd.Flags().StringVar(&o.PackageVersion, "package-version", "",
		"the package version")

	cmd.Flags().BoolVar(&o.PrintProvenance, "print-provenance", false,
		"[optional] print the verified provenance to stdout")

	cmd.MarkFlagRequired("source-uri")
	cmd.MarkFlagRequired("builder-id")
	cmd.MarkFlagRequired("package-name")
	cmd.MarkFlagRequired("package-version")
	cmd.MarkFlagsMutuallyExclusive("source-versioned-tag", "source-tag")
}

// VerifyVSAOptions is the top-level options for the `verifyVSA` command.
type VerifyVSAOptions struct {
	SubjectDigests   []string
	AttestationPath  string
	VerifierID       string
	ResourceURI      string
	VerifiedLevels   []string
	PublicKeyPath    string
	PublicKeyID      string
	PrintAttestation bool
}

var _ Interface = (*VerifyVSAOptions)(nil)

// AddFlags implements Interface.
func (o *VerifyVSAOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringArrayVar(&o.SubjectDigests, "subject-digest", []string{},
		"the digests to be verified. Pass multiple digests by repeating the flag. e.g. --subject-digest <digest type>:<digest value> --subject-digest <digest type>:<digest value>")

	cmd.Flags().StringVar(&o.AttestationPath, "attestation-path", "",
		"path to a file containing the attestation")

	cmd.Flags().StringVar(&o.VerifierID, "verifier-id", "",
		"the unique verifier ID who created the attestation")

	cmd.Flags().StringVar(&o.ResourceURI, "resource-uri", "",
		"the resource URI to be verified")

	cmd.Flags().StringArrayVar(&o.VerifiedLevels, "verified-level", []string{},
		"[optional] the levels of verification to be performed. Pass multiple digests by repeating the flag, e.g., --verified-level SLSA_BUILD_LEVEL_2 --verified-level FEDRAMP_LOW'")

	cmd.Flags().BoolVar(&o.PrintAttestation, "print-attestation", false,
		"[optional] print the contents of attestation to stdout")

	cmd.Flags().StringVar(&o.PublicKeyPath, "public-key-path", "",
		"path to a public key file")

	cmd.Flags().StringVar(&o.PublicKeyID, "public-key-id", "",
		"[optional] the ID of the public key, defaults to the SHA256 digest of the base64-encoded public key")

	cmd.MarkFlagRequired("subject-digests")
	cmd.MarkFlagRequired("attestation-path")
	cmd.MarkFlagRequired("verifier-id")
	cmd.MarkFlagRequired("resource-uri")
	cmd.MarkFlagRequired("public-key-path")
	// public-key-id" and "public-key-signing-hash-algo" are optional since they have useful defaults
}

type workflowInputs struct {
	kv map[string]string
}

func (i *workflowInputs) Type() string {
	return fmt.Sprintf("%v", i.kv)
}

func (i *workflowInputs) String() string {
	return fmt.Sprintf("%v", i.kv)
}

func (i *workflowInputs) Set(value string) error {
	l := strings.Split(value, "=")
	if len(l) != 2 {
		return fmt.Errorf("%w: expected 'key=value' format, got '%s'", serrors.ErrorInvalidFormat, value)
	}
	if i.kv == nil {
		i.kv = make(map[string]string)
	}
	i.kv[l[0]] = l[1]
	return nil
}

func (i *workflowInputs) AsMap() map[string]string {
	return i.kv
}
