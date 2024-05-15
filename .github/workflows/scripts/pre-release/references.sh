#!/bin/bash

# Verify that all references point to the same version

set -euo pipefail

function get_first_nonblank_line() {
    while read line; do
        [[ "$line" =~ [^[:blank:]] ]] && break
    done < "$1"
    echo "$line"
}

###
### SHA256SUM.md
###

line=$(get_first_nonblank_line SHA256SUM.md)

# Ensure both visible text and link point to the same release
version_txt="$(sed -E "s~.*\[v(.*)\].*~\1~" <<< "$line")"
version_lnk="$(sed -E "s~.*/v(.*)\)$~\1~" <<< "$line")"

if [[ "$version_txt" != "$version_lnk" ]]; then
    mark_txt="$(head -c ${#version_txt} < /dev/zero | tr '\0' '^')"
    mark_lnk="$(head -c ${#version_lnk} < /dev/zero | tr '\0' '^')"

    marks="${line/"$version_txt"/"$mark_txt"}"
    marks="${marks/"$version_lnk"/"$mark_lnk"}"
    marks="$(sed 's/[^^]/ /g' <<< "$marks")"

    echo "SHA256SUM.md: Visible text and linked URL do not match:"
    echo "$line"
    echo "$marks"

    exit 1
fi

# Ensure version matches what's declared in the PR body
if [[ "$version_txt" != "$RELEASE_TAG" ]]; then
    echo "SHA256SUM.md version doesn't match version declared in PR body"
    echo "PR body: #label:release v$RELEASE_TAG"
    echo "SHA256SUM.md: v$version_txt"

    exit 1
fi

###
### go.mod
###

# Get major version from go.mod
major_version_go_mod="$(get_first_nonblank_line go.mod | sed -E 's~.*/v(.*)~\1~')"

# Get major version declared in PR body
major_version="$(sed -E 's/(.+)\..+\..+/\1/' <<< "$RELEASE_TAG")"

# Ensure major version from SHA256SUM.md matches go.mod's
if [[ "$major_version_go_mod" != "$major_version" ]]; then
    echo "go.mod version doesn't match version declared in PR body:"
    echo "PR body: v$major_version (v$RELEASE_TAG)"
    echo "go.mod:  v$major_version_go_mod"

    exit 1
fi

###
### README.md
###

# Select all version numbers following a reference to slsa-verifier that are different
# from the version defined in SHA256SUM.md
results=$(
    grep -Pon ".*?slsa-verifier.*?v\d+\.\d+\.\d+" README.md actions/installer/README.md |
    grep -v "$RELEASE_TAG$" |
    sed -E 's/(.*)/  \1/' || true
)

if [[ "$results" != "" ]]; then
    echo "README.md version doesn't match version declared in PR body:"
    echo "PR body: #label:release v$RELEASE_TAG"
    echo "README.md:"
    echo "$results"
    exit 1
fi
