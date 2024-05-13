# Api Library

## Verifers

We have exported functions for using slsa-verifier within your own golang packages

- slsa-verifier/verifiers/verifier.go

### Npmjs

With `VerifyNpmPackageWithSigstoreTufClient`, you can pass in your own Tuf client with custom options.
For example, use the embedded Tuf root with `sigstoreTuf.DefaultOptions().WithForceCache()`.

Example:

```go
package main

import (
	"context"
	"fmt"

	sigstoreTuf "github.com/sigstore/sigstore-go/pkg/tuf"
	options "github.com/slsa-framework/slsa-verifier/v2/options"
	apiVerify "github.com/slsa-framework/slsa-verifier/v2/verifiers"
	apiUtils "github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

func main() {
	doVerify()
}

func doVerify() (*apiUtils.TrustedBuilderID, error) {
	packageVersion := "0.1.127"
	packageName := "@ianlewis/actions-test"
	builderId := "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_nodejs_slsa3.yml"
	attestations := []byte(`{"attestations":[{"predicateType":"https://giEntries":[{"logIndex":"2035" ... `)
	tarballHash := "ab786dbef723164a605e55ff0ebe83f8e879159bd411980d4423c9b1646b858a537b4bc4d494fc8f71195db715e5c5e9ab4b8809f8b1b399cd30ac053d180ba7"
	provenanceOpts := &options.ProvenanceOpts{
		ExpectedSourceURI:      "github.com/ianlewis/actions-test",
		ExpectedDigest:         "ab786dbef723164a605e55ff0ebe83f8e879159bd411980d4423c9b1646b858a537b4bc4d494fc8f71195db715e5c5e9ab4b8809f8b1b399cd30ac053d180ba7",
		ExpectedPackageName:    &packageName,
		ExpectedPackageVersion: &packageVersion,
	}
	builderOpts := &options.BuilderOpts{
		ExpectedID: &builderId,
	}
	// example: force using the embedded root, without going online for a refresh
	// opts := sigstoreTuf.DefaultOptions().WithForceCache()
	// example: supply your own root
	// opts := sigstoreTuf.DefaultOptions().WithRoot([]byte(`{"signed":{"_type":"root","spec_version":"1.0","version":9,"expires":"2024-09-12T06:53:10Z","keys":{"1e1d65ce98b10 ...`)).WithForceCache()
	opts := sigstoreTuf.DefaultOptions()
	client, err := sigstoreTuf.New(opts)
	if err != nil {
		fmt.Printf("creating SigstoreTuf client: %v", err)
		return nil, fmt.Errorf("creating SigstoreTuf client: %w", err)
	}
	_, outBuilderID, err := apiVerify.VerifyNpmPackageWithSigstoreTufClient(context.Background(), attestations, tarballHash, provenanceOpts, builderOpts, client)
	if err != nil {
		fmt.Printf("Verifying npm package: FAILED: %v", err)
		return nil, err
	}
	fmt.Printf("builderId: %s\n", outBuilderID.Name())
	fmt.Println("Verifying npm package: PASSED")
	return outBuilderID, nil
}
```

