#!/bin/bash

repo="slsa-framework/example-package"
api_version="X-GitHub-Api-Version: 2022-11-28"
# Verify provenance authenticity with slsa-verifier at HEAD

# Get workflow ID.
workflow_id=$(gh api -H "Accept: application/vnd.github+json" -H "$api_version" "/repos/$repo/actions/workflows?per_page=100" | jq '.workflows[] | select(.path == ".github/workflows/e2e.generic.schedule.main.multi-uses.slsa3.yml") | .id')
echo "workflow_id:${workflow_id}"

# Get the run ID for the most recent run.
run_id=$(gh api -H "Accept: application/vnd.github+json" -H "$api_version" "/repos/$repo/actions/workflows/$workflow_id/runs?per_page=1" | jq '.workflow_runs[0].id')
echo "run_id:${run_id}"

gh run download -R "${repo}" -n "artifacts1" "${run_id}"
gh run download -R "${repo}" -n "attestation1.intoto.jsonl" "${run_id}"

cd __EXAMPLE_PACKAGE__ || exit 1
# shellcheck source=/dev/null
source "./.github/workflows/scripts/e2e-verify.common.sh"
cd - || exit 1

# HACK: Set THIS_FILE to correspond with the artifact properties
export THIS_FILE=e2e.generic.schedule.main.multi-uses.slsa3.yml

# Set BINARY and PROVENANCE
export BRANCH=main
export BINARY=artifact1
export PROVENANCE=attestation1.intoto.jsonl
export GITHUB_REPOSITORY="${repo}"

verify_provenance_authenticity "./__THIS_REPO__/slsa-verifier" "HEAD"
