package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/slsa-framework/slsa-verifier/verification"
)

var (
	provenancePath  string
	artifactPath    string
	source          string
	branch          string
	tag             string
	versiontag      string
	printProvenance bool
)

func main() {
	flag.StringVar(&provenancePath, "provenance", "", "path to a provenance file")
	flag.StringVar(&artifactPath, "artifact-path", "", "path to an artifact to verify")
	flag.StringVar(&source, "source", "",
		"expected source repository that should have produced the binary, e.g. github.com/some/repo")
	flag.StringVar(&branch, "branch", "main", "expected branch the binary was compiled from")
	flag.StringVar(&tag, "tag", "", "[optional] expected tag the binary was compiled from")
	flag.StringVar(&versiontag, "versioned-tag", "",
		"[optional] expected version the binary was compiled from. Uses semantic version to match the tag")
	flag.BoolVar(&printProvenance, "print-provenance", false,
		"print the verified provenance to std out")
	flag.Parse()

	if provenancePath == "" || artifactPath == "" || source == "" {
		flag.Usage()
		os.Exit(1)
	}

	var ptag, pversiontag *string

	if isFlagPassed("tag") {
		ptag = &tag
	}
	if isFlagPassed("versioned-tag") {
		pversiontag = &versiontag
	}

	if ptag != nil && pversiontag != nil {
		fmt.Fprintf(os.Stderr, "'version' and 'tag' options cannot be used together\n")
		os.Exit(1)
	}

	verifiedProvenance, err := runVerify(artifactPath, provenancePath, source, branch, ptag, pversiontag)
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

func runVerify(artifactPath, provenancePath, source, branch string, ptag, pversiontag *string) ([]byte, error) {
	f, err := os.Open(artifactPath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	provenance, err := os.ReadFile(provenancePath)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Panic(err)
	}
	artifactHash := hex.EncodeToString(h.Sum(nil))

	provenanceOpts := &verification.ProvenanceOpts{
		ExpectedBranch:       branch,
		ExpectedDigest:       artifactHash,
		ExpectedVersionedTag: pversiontag,
		ExpectedTag:          ptag,
	}

	ctx := context.Background()
	return verification.Verify(ctx, provenance,
		artifactHash,
		source, provenanceOpts)
}
