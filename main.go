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

	"github.com/gossts/slsa-provenance/pkg"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
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
)

var defaultRekorAddr = "https://rekor.sigstore.dev"

func verify(ctx context.Context, provenancePath, artifactHash, source string) error {
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

	// Verify the workflow identity
	if err := pkg.VerifyWorkflowIdentity(workflowInfo, source); err != nil {
		return err
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
	flag.StringVar(&source, "source", "", "expected source repository that should have produced the binary, e.g. github.com/gossts/example")
	flag.Parse()

	if provenancePath == "" || binaryPath == "" || source == "" {
		flag.Usage()
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
	if err := verify(ctx, provenancePath, hex.EncodeToString(h.Sum(nil)), source); err != nil {
		log.Fatal(err)
	}

	fmt.Println("successfully verified SLSA provenance")
}
