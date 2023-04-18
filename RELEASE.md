# Releasing the verifier

This is a  document to describe the release process for the verifier.

---

- [Publish release](#publish-release)
- [Verify provenance](#verify-provenance)
- [Update documentation](#update-documentation)
- [Update builders](#update-builders)
- [Announce](#announce)

---

## Publish release

Major and minor releases are released directly from the `main` branch. Patch versions are released from the `release/vX.Y` branch.

### New major or minor release

For a new major version update, ensure that the new version's go.mod file appends the new major version number to the module path. Then, update every imported package from the module with the new major version. See [here](https://go.dev/doc/modules/major-version) for details.

### Dry-Run

Create a release candidate for the official slsa-verifier via [slsa-framework/slsa-verifier/releases/new](https://github.com/slsa-framework/slsa-verifier/releases/new).

Use a pre-release name denoted with a hypen `vX.Y.Z-rc` (do not use a pre-release check, the e2e tests will ignore these). By creating a pre-release version, the release flow and e2e tests can be validated committing to the final version. Because Go module downloads are deterministic through the public GOPROXY, this helps ensure that the final released Go module is immutable: a final release version should not be deleted.

Set the title to `vX.Y.Z-rc`.

Click `Publish release`.

This will trigger a release workflow: wait until it completes and generates the binary and the provenance.

Do **NOT** submit any more code between now and the final release.

Check the following:

1. Ensure that the release is successful and provenance can be verified properly.
2. Either manually trigger or wait for a nightly scheduled run of all [example-package e2e tests](https://github.com/slsa-framework/example-package/tree/main/.github/workflows) and ensure that all tests are passing.
3. Ensure that the latest release can be installed via a `go install`.
4. Verify that the version reported by the `version` command is correct:
```shell
$ ./slsa-verifier version 2>&1 | grep GitVersion
```
5. Ensure the installer Action works by manually running the [schedule.installer.yml](https://github.com/slsa-framework/slsa-verifier/actions/workflows/pre-submit.actions.yml). 


If both of these steps succeed, then move on to the [Final Release](#final-release).

### Final Release

Use a "canonical" semantic version without metadata `vX.Y.Z`.

Set the title to `vX.Y.Z`.

Click `Publish release`.

This will trigger a release workflow: wait until it completes and generates the binary and the provenance.

From the repository landing page, use the branch drop-down to create a branch from the tagged release with the format `release/vX.Y`. This will be used for backporting critical fixes and releases patch versions.

### New patch release

Critical patch fixes are released from the `release/vX.Y` branch. Once the backported fix has been merged, create a new tag for the official generator via [slsa-framework/slsa-verifier/releases/new](https://github.com/slsa-framework/slsa-verifier/releases/new). Use the `release/vX.Y` branch as the Target.

Use a "canonical" semantic version without metadata `vX.Y.Z`.

Set the title to `vX.Y.Z`.

Click `Publish release`.

This will trigger a release workflow: wait until it completes and generates the binary and the provenance.

## Verify provenance

Follow the steps:

1. Download the binary and provenance from https://github.com/slsa-framework/slsa-verifier/releases/tag/vX.Y.Z

2. Clone the slsa-verifier repo, compile and verify the provenance:
```
$ git clone git@github.com:slsa-framework/slsa-verifier.git
$ cd slsa-verifier
# $ (Optional: git checkout tags/v1.1.1: you may need to change the command below)
$ go run ./cli/slsa-verifier verify-artifact ~/Downloads/slsa-verifier-linux-amd64 --provenance-path ~/Downloads/slsa-verifier-linux-amd64.intoto.jsonl --source-uri github.com/slsa-framework/slsa-verifier --source-tag vX.Y.Z
```

You should include the `-branch release/vX.Y` for patch version releases.

If the provenance verification fails, delete the release and the tag. Otherwise, continue.

## Update documentation

Follow these steps:

1. Compute the hashes of all the binaries. One of the following commands will do:
```
$ cat slsa-verifier-linux-amd64.intoto.jsonl | jq -r '.payload' | base64 -d | jq -r '.subject[0].digest.sha256'
```
or
```
$ sha256sum slsa-verifier-linux-amd64
```

2. Add additional entries for each release binary at the top of [SHA256SUM.md](./SHA256SUM.md):

```
### [vX.Y.Z](https://github.com/slsa-framework/slsa-verifier/releases/tag/vX.Y.Z)
<the-hash>  slsa-verifier-linux-amd64
<the-hash>  slsa-verifier-linux-arm64
```

3. Update the latest version in the main [README.md](./README.md) and the installer Action's [actions/installer/README.md](./actions/installer/README.md):

```shell
$ sed -i "s/v1.0.0/v1.1.1/g" ./README.md ./actions/installer/README.md
```

4. Send a pull request with the changes. In the description:
   - add the string `#label:release vX.Y.Z` on its own line;
   - explain the steps to verify the hash update, i.e., reviewers shoud LGTM only if the provenance verification succeeds and the hash in the pull request matches the one computed on the binary. You can use [#slsa-framework/slsa-github-generator#113](https://github.com/slsa-framework/slsa-github-generator/pull/113) as an example.

5. Update all version / commit references to the `slsa-verifier` repo in [`example-package`'s e2e.installer-action.yml](https://github.com/slsa-framework/example-package/blob/main/.github/workflows/e2e.installer-action.yml). Each reference has the comment `# UPDATE ON RELEASE`.

## Update builders

Send a similar pull request to update the hash and version of the verifier for the action [generate-builder](https://github.com/slsa-framework/slsa-github-generator/blob/6a2cc1cb559a81ffbbcd4248026c6ea89bdab2b6/.github/actions/generate-builder/action.yml#L70-L71). Explain the steps to verify the hash. If the pull request for the verifier is already merged, you can simply point to it instead.

Note: you need not cut a release for the generator, unless the verifier has important changes that are required for the builders to work properly.
