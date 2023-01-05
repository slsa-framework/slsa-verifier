#!/bin/bash

# Verify provenance authenticity with slsa-verifier at HEAD


cd __EXAMPLE_PACKAGE__
# shellcheck source=/dev/null
source "./.github/workflows/scripts/e2e-verify.common.sh"

# Set THIS_FILE to correspond with the artifact properties
export THIS_FILE=e2e.go.workflow_dispatch.main.config-noldflags.slsa3.yml
export BRANCH=main

# Set BINARY and PROVENANCE
cd -
export BINARY=__THIS_REPO__/cli/slsa-verifier/testdata/gha_go/v1.2.2/binary-linux-amd64-workflow_dispatch
export PROVENANCE=__THIS_REPO__/cli/slsa-verifier/testdata/gha_go/v1.2.2/binary-linux-amd64-workflow_dispatch.intoto.jsonl

GITHUB_REPOSITORY=slsa-framework/example-package verify_provenance_authenticity "./__THIS_REPO__/slsa-verifier" "HEAD"
