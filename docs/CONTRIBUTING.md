# Contributing

## Updating Github Actions Dependencies

### Renovate-Bot PRs

`renovate-bot` will periodically send PRs to update the `package.json` and `package-lock.json` in the Github Actions of this repo.
But, it will not also automatically recompile the packages into `.js` files.

We use a Workflow [Update actions dist post-commit](../.github/workflows/update-actions-dist-post-commit.yml) to 
help maintainers easily recompile the Github Actions against a PR.

Use the UI to invoke the workflow

[update-actions-dist-post-commit.yml](https://github.com/slsa-framework/slsa-verifier/actions/workflows/update-actions-dist-post-commit.yml)

or invoke with

```shell
gh workflow run update-actions-dist-post-commit.yml -F pr_number=<pull request number>
```