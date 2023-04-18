#!/bin/bash

repo="slsa-framework/example-package"
api_version="X-GitHub-Api-Version: 2022-11-28"
# Verify provenance authenticity with slsa-verifier at HEAD

download_artifact() {
    local run_id="$1"
    local artifact_name="$2"
    # Get the artifact ID for 'artifact1'
    artifact_id=$(gh api -H "Accept: application/vnd.github+json" -H "$api_version" "/repos/$repo/actions/runs/$run_id/artifacts" | jq ".artifacts[] | select(.name == \"$artifact_name\") | .id")
    echo "artifact_id:$artifact_id"

    gh api -H "Accept: application/vnd.github+json" -H "$api_version" "/repos/$repo/actions/artifacts/$artifact_id/zip" >"$artifact_name.zip"
    unzip "$artifact_name".zip
}

# Get workflow ID.
workflow_id=$(gh api -H "Accept: application/vnd.github+json" -H "$api_version" "/repos/$repo/actions/workflows?per_page=100" | jq '.workflows[] | select(.path == ".github/workflows/e2e.generic.schedule.main.multi-uses.slsa3.yml") | .id')
echo "workflow_id:$workflow_id"

# Get the run ID for the most recent run.
run_id=$(gh api -H "Accept: application/vnd.github+json" -H "$api_version" "/repos/$repo/actions/workflows/$workflow_id/runs?per_page=1" | jq '.workflow_runs[0].id')
echo "run_id:$run_id"

download_artifact "$run_id" "artifacts1"
download_artifact "$run_id" "attestation1.intoto.jsonl"

cd __EXAMPLE_PACKAGE__ || exit 1
# shellcheck source=/dev/null
source "./.github/workflows/scripts/e2e-verify.common.sh"

# Set THIS_FILE to correspond with the artifact properties
export THIS_FILE=e2e.generic.schedule.main.multi-uses.slsa3.yml
export BRANCH=main

# Set BINARY and PROVENANCE
cd - || exit 1
export BINARY=artifact1
export PROVENANCE=attestation1.intoto.jsonl

GITHUB_REPOSITORY="$repo" verify_provenance_authenticity "./__THIS_REPO__/slsa-verifier" "HEAD"
