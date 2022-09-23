# slsa-verifier setup GitHub Action

This action installs the SLSA verifier and adds it to your PATH.

For more information about `slsa-verifier`, refer to [its documentation](https://github.com/slsa-framework/slsa-verifier#verification-of-provenance).

For more information about SLSA in general, see [https://slsa.dev](https://slsa.dev).

## Usage

To install a specific version of `slsa-verifier`, use:

```yaml
uses: slsa-framework/slsa-verifier-installer@v1.3.0
```

See https://github.com/slsa-framework/slsa-verifier/releases for the list of available `slsa-verifier` releases.

For a full example workflow, see [../../.github/workflows/pre-submit.actions.yml](https://github.com/slsa-framework/slsa-verifier/.github/workflows/pre-submit.actions.yml).

This action requires using GitHub-provided Linux runners.
