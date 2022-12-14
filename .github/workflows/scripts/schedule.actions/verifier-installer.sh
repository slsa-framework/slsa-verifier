#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "./.github/workflows/scripts/e2e-utils.sh"

minimum_version="$MINIMUM_INSTALLER_VERSION"
list=""
# Check the releases.
echo "Listing releases"
release_list=$(gh -R "$GITHUB_REPOSITORY" release list)
while read -r line; do
    tag=$(echo "$line" | cut -f1)
    if version_ge "$tag" "$minimum_version"; then
        echo " INFO: found version to test: $tag"
        if [[ -n $list ]]; then
            list="$list, \"$tag\""
        else
            list="\"$tag\""
        fi
    fi
done <<<"$release_list"

versions="[$list]"
echo "version=$versions" >> "$GITHUB_OUTPUT"
