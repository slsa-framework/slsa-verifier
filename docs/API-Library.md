# Api Library

## Verifers

We have exported functions for using slsa-verifier within your own Go packages

- slsa-verifier/verifiers/verifier.go

### Npmjs

With `VerifyNpmPackageWithSigstoreTUFClient`, you can pass in your own TUF client with custom options.
For example, use the embedded TUF root with `sigstoreTUF.DefaultOptions().WithForceCache()`.

Example:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    sigstoreTUF "github.com/sigstore/sigstore-go/pkg/tuf"
    options "github.com/slsa-framework/slsa-verifier/v2/options"
    apiVerify "github.com/slsa-framework/slsa-verifier/v2/verifiers"
    apiUtils "github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

func main() {
    provBytes, builderID, err := doVerify()
    if err != nil {
        log.Fatalf("Verifying npm package: FAILED: %w", err)
    }
    fmt.Fprintf(os.Stderr, "builderID: %s\n", builderID.Name())
    fmt.Fprintf(os.Stderr, "Verifying npm package: PASSED")
    fmt.Printf("%s", provBytes)
}

func doVerify() ([]byte, *apiUtils.TrustedBuilderID, error) {
    packageVersion := "0.1.127"
    packageName := "@ianlewis/actions-test"
    builderID := "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_nodejs_slsa3.yml"
    attestations, err := os.ReadFile("attestations.json")
    if err != nil {
        return nil, nil, fmt.Errorf("creating sigstoreTUF client: %w", err)
    }
    tarballHash := "ab786dbef723164a605e55ff0ebe83f8e879159bd411980d4423c9b1646b858a537b4bc4d494fc8f71195db715e5c5e9ab4b8809f8b1b399cd30ac053d180ba7"
    provenanceOpts := &options.ProvenanceOpts{
        ExpectedSourceURI:      "github.com/ianlewis/actions-test",
        ExpectedDigest:         "ab786dbef723164a605e55ff0ebe83f8e879159bd411980d4423c9b1646b858a537b4bc4d494fc8f71195db715e5c5e9ab4b8809f8b1b399cd30ac053d180ba7",
        ExpectedPackageName:    &packageName,
        ExpectedPackageVersion: &packageVersion,
    }
    builderOpts := &options.BuilderOpts{
        ExpectedID: &builderID,
    }

    // example: all the default ClientOpts
    // clientOpts, err := options.NewDefaultClientOpts()

    // example: get the default Sigstore TUF client that the library caches
    // client, err := apiUtils.GetDefaultSigstoreTUFClient()

    // example: force using the embedded root, without going online for a refresh
    // opts := sigstoreTUF.DefaultOptions().WithForceCache()

    // example: supply your own root
    // opts := sigstoreTUF.DefaultOptions().WithRoot([]byte(`{"signed":{"_type":"root","spec_version":"1.0","version":9,"expires":"2024-09-12T06:53:10Z","keys":{"1e1d65ce98b10 ...`)).WithForceCache()

    // example: supply your own default Sigstore TUF client
    opts := sigstoreTUF.DefaultOptions()
    client, err := sigstoreTUF.New(opts)
    if err != nil {
        return nil, fmt.Errorf("creating SigstoreTUF client: %w", err)
    }
    clientOpts := options.ClientOpts{
        SigstoreTUFClient: client,
    }
    provBytes, outBuilderID, err := apiVerify.VerifyNpmPackage(context.Background(), attestations, tarballHash, provenanceOpts, builderOpts, clientOpts)
    if err != nil {
        return nil, nil, fmt.Errorf("Verifying npm package: FAILED: %w", err)
    }
    return provBytes, outBuilderID, nil
}
```
