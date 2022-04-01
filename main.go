package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/slsa-framework/slsa-verifier/pkg"
)

func usage(p string) {
	panic(fmt.Sprintf("Usage: %s TODO\n", p))
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

var (
	provenancePath string
	binaryPath     string
	source         string
	branch         string
	tag            string
	versiontag     string
)

var defaultRekorAddr = "https://rekor.sigstore.dev"

func verify(ctx context.Context,
	provenancePath, artifactHash, source string,
	branch, tag, versiontag *string,
) error {
	rClient, err := rekor.NewClient(defaultRekorAddr)
	if err != nil {
		return err
	}

	// Get Rekor entries corresponding to the binary artifact in the provenance.
	uuids, err := pkg.GetRekorEntries(rClient, artifactHash)
	if err != nil {
		return err
	}

	provenance, err := os.ReadFile(provenancePath)
	if err != nil {
		return fmt.Errorf("os.ReadFile: %w", err)
	}

	env, err := pkg.EnvelopeFromBytes(provenance)
	if err != nil {
		return err
	}

	// Verify the provenance and return the signing certificate.
	cert, err := pkg.FindSigningCertificate(ctx, uuids, *env, rClient)
	if err != nil {
		return err
	}

	// Get the workflow info given the certificate information.
	workflowInfo, err := pkg.GetWorkflowInfoFromCertificate(cert)
	if err != nil {
		return err
	}

	// Unpack and verify info in the provenance, including the Subject Digest.
	if err := pkg.VerifyProvenance(env, artifactHash); err != nil {
		return err
	}

	// Verify the workflow identity.
	if err := pkg.VerifyWorkflowIdentity(workflowInfo, source); err != nil {
		return err
	}

	// Verify the branch.
	if branch != nil {
		if err := pkg.VerifyBranch(env, *branch); err != nil {
			return err
		}
	}

	// Verify the tag.
	if tag != nil {
		if err := pkg.VerifyTag(env, *tag); err != nil {
			return err
		}
	}

	// Verify the versioned tag.
	if versiontag != nil {
		if err := pkg.VerifyVersionedTag(env, *versiontag); err != nil {
			return err
		}
	}

	b, err := json.MarshalIndent(workflowInfo, "", "\t")
	if err != nil {
		return err
	}

	fmt.Printf("verified SLSA provenance produced at \n %s\n", b)
	return nil
}

func main() {
	flag.StringVar(&provenancePath, "provenance", "", "path to a provenance file")
	flag.StringVar(&binaryPath, "binary", "", "path to a binary to verify")
	flag.StringVar(&source, "source", "", "expected source repository that should have produced the binary, e.g. github.com/some/repo")
	flag.StringVar(&branch, "branch", "main", "[optional] expected branch the binary was compiled from")
	flag.StringVar(&tag, "tag", "", "[optional] expected tag the binary was compiled from")
	flag.StringVar(&versiontag, "versioned-tag", "", "[optional] expected version the binary was compiled from. Uses semantic version to match the tag")
	flag.Parse()

	if provenancePath == "" || binaryPath == "" || source == "" {
		flag.Usage()
		os.Exit(1)
	}

	var pbranch, ptag, pversiontag *string
	if isFlagPassed("branch") {
		pbranch = &branch
	}
	if isFlagPassed("tag") {
		ptag = &tag
	}
	if isFlagPassed("versioned-tag") {
		pversiontag = &versiontag
	}

	if pversiontag != nil && ptag != nil {
		fmt.Fprintf(os.Stderr, "'version' and 'tag' options cannot be used together\n")
		os.Exit(1)
	}

	f, err := os.Open(binaryPath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	if err := verify(ctx, provenancePath,
		hex.EncodeToString(h.Sum(nil)),
		source, pbranch,
		ptag, pversiontag); err != nil {
		log.Fatal(err)
	}

	fmt.Println("successfully verified SLSA provenance")
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
