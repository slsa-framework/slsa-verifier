#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "./.github/workflows/scripts/e2e-utils.sh"

minimum_version="$MINIMUM_INSTALLER_VERSION"
list="\"$minimum_version\""
# Check the releases.
echo "Listing releases"
# Note: can remove -R option.
release_list=$(gh -R slsa-framework/slsa-verifier release list)
while read -r line; do
    tag=$(echo "$line" | cut -f1)
    if version_gt "$tag" "$minimum_version"; then
        echo " INFO: found version to test: $tag"
        list="$list, \"$tag\""
    fi
done <<<"$release_list"

versions="[$list]"
echo "version=$versions" >> "$GITHUB_OUTPUT"
