#!/bin/bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 tag"
    exit 1
fi

# Verify GH_TOKEN is set.
if [[ -z "${GH_TOKEN:-}" ]]; then
    echo "GH_TOKEN is unset"
    exit 1
fi

# Set the gh CLI.
if [[ -z "${GH:-}" ]]; then
    GH="gh"
fi

dir=$(mktemp -d)
tag="$1"

mkdir -p "${dir}"
rm -rf "${dir:?}/"* 2>/dev/null || true

echo "INFO: using dir: ${dir}"
echo

# Download artifacts and provenance.
cd "${dir}"
"${GH}" release -R slsa-framework/slsa-verifier download "${tag}"
cd -

for file in "${dir}"/*; do 
    if [[ "${file}" == *".intoto.jsonl" ]]; then
        continue
    fi
    go run ./cli/slsa-verifier verify-artifact "${file}" --provenance-path "${file}".intoto.jsonl --source-uri github.com/slsa-framework/slsa-verifier --source-tag "${tag}"
done

