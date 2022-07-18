package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/slsa-framework/slsa-verifier/pkg"
)

var (
	provenancePath  string
	artifactPath    string
	ociImageRef     string
	source          string
	branch          string
	tag             string
	versiontag      string
	printProvenance bool
)

var defaultRekorAddr = "https://rekor.sigstore.dev"

func verifyBlob(ctx context.Context,
	provenance []byte, artifactHash, source string) (*envAndCert, error) {
	rClient, err := rekor.NewClient(defaultRekorAddr)
	if err != nil {
		return nil, err
	}

	/* Verify signature on the intoto attestation. */
	env, cert, err := pkg.VerifyProvenanceSignature(ctx, rClient, provenance, artifactHash)
	if err != nil {
		return nil, err
	}

	return &envAndCert{env, cert}, nil
}

func verifyEnvAndCert(env *dsse.Envelope, cert *x509.Certificate, source string, pOpts *pkg.ProvenanceOpts) ([]byte, error) {
	/* Verify properties of the signing identity. */
	// Get the workflow info given the certificate information.
	workflowInfo, err := pkg.GetWorkflowInfoFromCertificate(cert)
	if err != nil {
		return nil, err
	}

	b, err := json.MarshalIndent(workflowInfo, "", "\t")
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "Signing certificate information:\n %s\n", b)

	// Verify the workflow identity.
	if err := pkg.VerifyWorkflowIdentity(workflowInfo, source); err != nil {
		return nil, err
	}

	/* Verify properties of the SLSA provenance. */
	// Unpack and verify info in the provenance, including the Subject Digest.
	if err := pkg.VerifyProvenance(env, pOpts); err != nil {
		return nil, err
	}

	// Return verified provenance.
	return base64.StdEncoding.DecodeString(env.Payload)
}

func main() {
	flag.StringVar(&provenancePath, "provenance", "", "path to a provenance file")
	flag.StringVar(&artifactPath, "artifact-path", "", "path to an artifact to verify")
	flag.StringVar(&ociImageRef, "oci-image", "", "reference to an OCI image to verify")
	flag.StringVar(&source, "source", "",
		"expected source repository that should have produced the binary, e.g. github.com/some/repo")
	flag.StringVar(&branch, "branch", "main", "expected branch the binary was compiled from")
	flag.StringVar(&tag, "tag", "", "[optional] expected tag the binary was compiled from")
	flag.StringVar(&versiontag, "versioned-tag", "",
		"[optional] expected version the binary was compiled from. Uses semantic version to match the tag")
	flag.BoolVar(&printProvenance, "print-provenance", false,
		"print the verified provenance to std out")
	flag.Parse()

	if (provenancePath == "" || artifactPath == "") && ociImageRef == "" {
		fmt.Fprintf(os.Stderr, "either 'provenance' and 'artifact-path' or 'oci-image' must be specified\n")
		flag.Usage()
		os.Exit(1)
	}

	if source == "" {
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

	verifiedProvenance, err := runVerify(ociImageRef, artifactPath, provenancePath, source, branch, ptag, pversiontag)
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

type envAndCert struct {
	env  *dsse.Envelope
	cert *x509.Certificate
}

func runVerify(ociImageRef, artifactPath, provenancePath, source, branch string, ptag, pversiontag *string) ([][]byte, error) {
	// A list of verified envelope and certificates.
	var envAndCerts []*envAndCert
	var artifactHash string

	ctx := context.Background()
	if ociImageRef != "" {
		ref, err := name.ParseReference(ociImageRef)
		if err != nil {
			return nil, err
		}
		// Run container verification.
		atts, _, err := cosign.VerifyImageAttestations(ctx, ref, &cosign.CheckOpts{})
		if err != nil {
			return nil, err
		}
		for _, att := range atts {
			pyld, err := att.Payload()
			if err != nil {
				return nil, err
			}
			env, err := pkg.EnvelopeFromBytes(pyld)
			if err != nil {
				return nil, err
			}
			cert, err := att.Cert()
			if err != nil {
				return nil, err
			}
			envAndCerts = append(envAndCerts, &envAndCert{env, cert})
		}
	} else {
		// Run blob verification.
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
		artifactHash = hex.EncodeToString(h.Sum(nil))

		e, err := verifyBlob(ctx, provenance, artifactHash, source)
		if err != nil {
			return nil, err
		}
		envAndCerts = append(envAndCerts, e)
	}

	provenanceOpts := &pkg.ProvenanceOpts{
		ExpectedBranch:       branch,
		ExpectedDigest:       artifactHash,
		ExpectedVersionedTag: pversiontag,
		ExpectedTag:          ptag,
	}

	verifiedAttestations := make([][]byte, 0)
	var verifyErr error
	for _, envAndCert := range envAndCerts {
		verified, err := verifyEnvAndCert(envAndCert.env, envAndCert.cert, source, provenanceOpts)
		if err != nil {
			verifyErr = err
			continue
		}
		verifiedAttestations = append(verifiedAttestations, verified)
	}

	if len(verifiedAttestations) == 0 {
		return nil, verifyErr
	}

	return verifiedAttestations, nil
}
