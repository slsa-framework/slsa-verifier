# slsa-verifier setup GitHub Action

This action installs the SLSA verifier and adds it to your PATH.

For more information about `slsa-verifier`, refer to [its documentation](https://github.com/slsa-framework/slsa-verifier#verification-of-provenance).

For more information about SLSA in general, see [https://slsa.dev](https://slsa.dev).

## Usage

To install a specific version of `slsa-verifier`, use:

```yaml
uses: slsa-framework/slsa-verifier/actions/installer@v2.6.0
```

See https://github.com/slsa-framework/slsa-verifier/releases for the list of available `slsa-verifier` releases. Only versions greater or equal to 2.0.1 are supported.

This action requires using GitHub-provided Linux runners.
