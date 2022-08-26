# slsa-verifier setup GitHub Action

This action installs the SLSA verifier so you can verify SLSA provenance in your workflows.

For more information about `slsa-verifier`, refer to [its documentation](https://github.com/slsa-framework/slsa-verifier#verification-of-provenance).

For more information about SLSA in general, see [https://slsa.dev](https://slsa.dev).

## Usage

This action requires using GitHub-provided Linux runners.

Add the following snippet to your Github workflow YAML file:

```yaml
uses: slsa-framework/slsa-verifier-installer@main
with:
    verifier-release: v1.3.0 # optional
```

For a full example workflow, see `.github/workflows/test.yml`.

### Optional Inputs

| Input | Description |
| --- | --- |
| `verifier-release` | `slsa-verifier` version to use. Default value is `v1.3.0`. |

See https://github.com/slsa-framework/slsa-verifier/releases for the list of available `slsa-verifier` releases. In addition to official releases, this action supports installing from main. Installing from main requires installing go 1.18.
