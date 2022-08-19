package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	serrors "github.com/slsa-framework/slsa-verifier/errors"
	"github.com/slsa-framework/slsa-verifier/options"
	"github.com/slsa-framework/slsa-verifier/verifiers"
	"github.com/slsa-framework/slsa-verifier/verifiers/container"
)

type workflowInputs struct {
	kv map[string]string
}

var (
	provenancePath  string
	builderID       string
	artifactPath    string
	artifactImage   string
	source          string
	branch          string
	tag             string
	versiontag      string
	inputs          workflowInputs
	printProvenance bool
)

func experimentalEnabled() bool {
	return os.Getenv("SLSA_VERIFIER_EXPERIMENTAL") == "1"
}

func (i *workflowInputs) String() string {
	return fmt.Sprintf("%v", i.kv)
}

func (i *workflowInputs) Set(value string) error {
	l := strings.Split(value, "=")
	if len(l) != 2 {
		return fmt.Errorf("%w: expected 'key=value' format, got '%s'", serrors.ErrorInvalidFormat, value)
	}
	i.kv[l[0]] = l[1]
	return nil
}

func (i *workflowInputs) AsMap() map[string]string {
	return i.kv
}

func main() {
	if experimentalEnabled() {
		flag.StringVar(&builderID, "builder-id", "", "EXPERIMENTAL: the unique builder ID who created the provenance")
	}
	flag.StringVar(&provenancePath, "provenance", "", "path to a provenance file")
	flag.StringVar(&artifactPath, "artifact-path", "", "path to an artifact to verify")
	flag.StringVar(&artifactImage, "artifact-image", "", "name of the OCI image to verify")
	flag.StringVar(&source, "source", "",
		"expected source repository that should have produced the binary, e.g. github.com/some/repo")
	flag.StringVar(&branch, "branch", "", "[optional] expected branch the binary was compiled from")
	flag.StringVar(&tag, "tag", "", "[optional] expected tag the binary was compiled from")
	flag.StringVar(&versiontag, "versioned-tag", "",
		"[optional] expected version the binary was compiled from. Uses semantic version to match the tag")
	flag.BoolVar(&printProvenance, "print-provenance", false,
		"print the verified provenance to std out")
	inputs.kv = make(map[string]string)
	flag.Var(&inputs, "workflow-input",
		"[optional] a workflow input provided by a user at trigger time in the format 'key=value'. (Only for 'workflow_dispatch' events).")
	flag.Parse()

	if (provenancePath == "" || artifactPath == "") && artifactImage == "" {
		fmt.Fprintf(os.Stderr, "either 'provenance' and 'artifact-path' or 'artifact-image' must be specified\n")
		flag.Usage()
		os.Exit(1)
	}

	if artifactImage != "" && (provenancePath != "" || artifactPath != "") {
		fmt.Fprintf(os.Stderr, "'provenance' and 'artifact-path' should not be specified when 'artifact-image' is provided\n")
		flag.Usage()
		os.Exit(1)
	}

	if source == "" {
		flag.Usage()
		os.Exit(1)
	}

	var pbuilderID, pbranch, ptag, pversiontag *string

	// Note: nil tag, version-tag and builder-id means we ignore them during verification.
	if isFlagPassed("tag") {
		ptag = &tag
	}
	if isFlagPassed("versioned-tag") {
		pversiontag = &versiontag
	}
	if experimentalEnabled() && isFlagPassed("builder-id") {
		pbuilderID = &builderID
	}
	if isFlagPassed("branch") {
		pbranch = &branch
	}

	if ptag != nil && pversiontag != nil {
		fmt.Fprintf(os.Stderr, "'version' and 'tag' options cannot be used together\n")
		os.Exit(1)
	}

	verifiedProvenance, _, err := runVerify(artifactImage, artifactPath, provenancePath, source,
		pbranch, pbuilderID, ptag, pversiontag, inputs.AsMap())
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAILED: SLSA verification failed: %v\n", err)
		os.Exit(2)
	}

	fmt.Fprintf(os.Stderr, "PASSED: Verified SLSA provenance\n")
	if printProvenance {
		fmt.Fprintf(os.Stdout, "%s\n", string(verifiedProvenance))
	}
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func runVerify(artifactImage, artifactPath, provenancePath, source string,
	branch, builderID, ptag, pversiontag *string, inputs map[string]string,
) ([]byte, string, error) {
	ctx := context.Background()

	// Artifact hash retrieval depends on the artifact type.
	artifactHash, err := getArtifactHash(artifactImage, artifactPath)
	if err != nil {
		return nil, "", err
	}

	provenanceOpts := &options.ProvenanceOpts{
		ExpectedSourceURI:      source,
		ExpectedBranch:         branch,
		ExpectedDigest:         artifactHash,
		ExpectedVersionedTag:   pversiontag,
		ExpectedTag:            ptag,
		ExpectedWorkflowInputs: inputs,
	}

	builderOpts := &options.BuilderOpts{
		ExpectedID: builderID,
	}

	var provenance []byte
	if provenancePath != "" {
		provenance, err = os.ReadFile(provenancePath)
		if err != nil {
			return nil, "", err
		}
	}

	return verifiers.Verify(ctx, artifactImage, provenance, artifactHash, provenanceOpts, builderOpts)
}

func getArtifactHash(artifactImage, artifactPath string) (string, error) {
	if artifactPath != "" {
		f, err := os.Open(artifactPath)
		if err != nil {
			return "", err
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return "", err
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	}
	// Retrieve image digest
	return container.GetImageDigest(artifactImage)
}
