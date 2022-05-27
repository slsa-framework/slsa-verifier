# Releasing the verifier

This is a  document to describe the release process for the verifier.

---

- [Publish release](#publish-release)
- [Update documentation](#update-documentation)
- [Update builders](#update-builders)
- [Announce](#announce)

---

## Publish release

Create a new tag for the official generator via [slsa-framework/slsa-verifier/releases/new](https://github.com/slsa-framework/slsa-verifier/releases/new). 

Use a "canonical" semantic version without metadata (`$BUILDER_TAG`). Shorter versions are not accepted by the builder's and verifier's code. 

Set the title to `vX.Y.Z`.

Click `Publish release`.

This will trgger a release workflow: wait until it completes and generates the binary and the provenance.

## Update documentation

Follow the steps:

1. Download the binary and provenance from https://github.com/slsa-verifier/slsa-verifier/releases/tag/vX.Y.Z

2. Clone the slsa-verifier repo, compile and verify the provenance:
```
$ git clone git@github.com:slsa-framework/slsa-verifier.git
$ cd slsa-verifier
$ (Optional: git checkout tags/v1.0.0)
$ go run . -artifact-path slsa-verifier-linux-amd64 -provenance slsa-verifier-linux-amd64.intoto.jsonl -source github.com/slsa-framework/slsa-verifier -tag v0.0.1
```

3. Get the hash of the binary. One on of the following will do:
```
$cat slsa-verifier-linux-amd64.intoto.jsonl | jq -r '.payload' | base64 -d | jq -r '.subject[0].digest.sha256'
```
or
```
$ sha256sum slsa-verifier-linux-amd64
```

If the provenance verification fails, abort. Otherwise, continue.

4. Update the verifier hash in the documentation:

Add an additional entry at the top of [SHA256SUM.md](./SHa256SUM.md):

```
# vX.Y.Z - https://github.com/slsa-framework/slsa-verifier/releases/tag/vX.Y.Z
<the-hash>  slsa-verifier-linux-amd64
```

Update the latest version in the [README.md](./README.md).

In the pull request description, explain the steps to verify the hash update.

## Update builders

Send a similar pull request to update the hash and version of the verifier for the workflow [slsa-framework/slsa-github-generator/blob/main/.github/workflows/builder_go_slsa3.yml#L30-L31](https://github.com/slsa-framework/slsa-github-generator/blob/main/.github/workflows/builder_go_slsa3.yml#L30-L31). Explain the steps to verify the hash. If the pull request for the verifier is already merged, you can simply point to it instead.

Note: you need not cut a release for the generator, unless the verifier has important changes that are required for the builders to work properly.