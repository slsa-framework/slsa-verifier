package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/slsa-framework/slsa-verifier/container"
	"github.com/slsa-framework/slsa-verifier/options"
	"github.com/slsa-framework/slsa-verifier/verifiers"
)

var (
	provenancePath    string
	builderID         string
	artifactPath      string
	artifactReference string
	source            string
	branch            string
	tag               string
	versiontag        string
	printProvenance   bool
)

func main() {
	flag.StringVar(&builderID, "builder-id", "", "EXPERIMENTAL: the unique builder ID who created the provenance")
	flag.StringVar(&provenancePath, "provenance", "", "path to a provenance file")
	flag.StringVar(&artifactPath, "artifact-path", "", "path to an artifact to verify")
	flag.StringVar(&artifactReference, "artifact-reference", "", "reference to an OCI image to verify")
	flag.StringVar(&source, "source", "",
		"expected source repository that should have produced the binary, e.g. github.com/some/repo")
	flag.StringVar(&branch, "branch", "main", "expected branch the binary was compiled from")
	flag.StringVar(&tag, "tag", "", "[optional] expected tag the binary was compiled from")
	flag.StringVar(&versiontag, "versioned-tag", "",
		"[optional] expected version the binary was compiled from. Uses semantic version to match the tag")
	flag.BoolVar(&printProvenance, "print-provenance", false,
		"print the verified provenance to std out")
	flag.Parse()

	if (provenancePath == "" || artifactPath == "") && artifactReference == "" {
		fmt.Fprintf(os.Stderr, "either 'provenance' and 'artifact-path' or '' must be specified\n")
		flag.Usage()
		os.Exit(1)
	}

	if source == "" {
		flag.Usage()
		os.Exit(1)
	}

	var pbuilderID, ptag, pversiontag *string

	// Note: nil tag, version-tag and builder-id means we ignore them during verification.
	if isFlagPassed("tag") {
		ptag = &tag
	}
	if isFlagPassed("versioned-tag") {
		pversiontag = &versiontag
	}
	if isFlagPassed("builder-id") {
		pbuilderID = &builderID
	}

	if ptag != nil && pversiontag != nil {
		fmt.Fprintf(os.Stderr, "'version' and 'tag' options cannot be used together\n")
		os.Exit(1)
	}

	verifiedProvenance, _, err := runVerify(artifactReference, artifactPath, provenancePath, source,
		branch, pbuilderID, ptag, pversiontag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAILED: SLSA verification failed: %v\n", err)
		os.Exit(2)
	}

	fmt.Fprintf(os.Stderr, "PASSED: Verified SLSA provenance\n")
	if printProvenance {
		for _, verified := range verifiedProvenance {
			fmt.Fprintf(os.Stdout, "%s\n", string(verified))
		}
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

func runVerify(artifactReference, artifactPath, provenancePath, source, branch string,
	builderID, ptag, pversiontag *string,
) ([]byte, string, error) {
	ctx := context.Background()

	// Artifact hash retrieval depends on the artifact type.
	artifactHash, err := getArtifactHash(artifactReference, artifactPath)
	if err != nil {
		return nil, "", err
	}

	provenanceOpts := &options.ProvenanceOpts{
		ExpectedSourceURI:    source,
		ExpectedBranch:       branch,
		ExpectedVersionedTag: pversiontag,
		ExpectedDigest:       artifactHash,
		ExpectedTag:          ptag,
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

	return verifiers.Verify(ctx, artifactReference, provenance, artifactHash, provenanceOpts, builderOpts)
}

func getArtifactHash(artifactReference, artifactPath string) (string, error) {
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
	return container.GetImageDigest(artifactReference)
}
