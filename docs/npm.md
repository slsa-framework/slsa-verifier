# NPM

## Provenance

### V1

Unwrapped and base64-decoded from the Sigstore Bundles and DSSE Envelopes, NPM V1 attestations are actually two parts: SLSA's build provenance and NPM's publish attestations. slsa-verifier will verify the envelopes and bundles around both attestations with the attestations file.

example build attestation

```json
$ curl -Ss $(npm view gundam-visor@1.0.1 --json | jq -r '.dist.attestations.url') | jq '.attestations[1].bundle.dsseEnvelope.payload' -r | base64 -d | jq
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "pkg:npm/gundam-visor@1.0.1",
      "digest": {
        "sha512": "8d9d7972f676516c75014aa074e11ae604d98f0b64ec6725a61e2838ff3dab162118fa71433fb31e1550d30bd0dec9d086ce032b94457b583900c507acf39c40"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
      "externalParameters": {
        "workflow": {
          "ref": "refs/tags/v1.0.1",
          "repository": "https://github.com/ramonpetgrave64/gundam-visor",
          "path": ".github/workflows/npm-publish.yml"
        }
      },
      "internalParameters": {
        "github": {
          "event_name": "release",
          "repository_id": "810002373",
          "repository_owner_id": "32398091"
        }
      },
      "resolvedDependencies": [
        {
          "uri": "git+https://github.com/ramonpetgrave64/gundam-visor@refs/tags/v1.0.1",
          "digest": {
            "gitCommit": "599500821344b070902a7a5666064bfdaba715df"
          }
        }
      ]
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/actions/runner/github-hosted"
      },
      "metadata": {
        "invocationId": "https://github.com/ramonpetgrave64/gundam-visor/actions/runs/9358004112/attempts/1"
      }
    }
  }
}
```

exmaple publish attestation

```json
$ curl -Ss $(npm view gundam-visor@1.0.1 --json | jq -r '.dist.attestations.url') | jq '.attestations[0].bundle.dsseEnvelope.payload' -r | base64 -d | jq
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "pkg:npm/gundam-visor@1.0.1",
      "digest": {
        "sha512": "8d9d7972f676516c75014aa074e11ae604d98f0b64ec6725a61e2838ff3dab162118fa71433fb31e1550d30bd0dec9d086ce032b94457b583900c507acf39c40"
      }
    }
  ],
  "predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
  "predicate": {
    "name": "gundam-visor",
    "version": "1.0.1",
    "registry": "https://registry.npmjs.org"
  }
}
```
