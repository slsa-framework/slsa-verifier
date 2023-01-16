#!/bin/bash

# Verify that all references point to the same version

set -euo pipefail

# Get major version from go.mod
major_version_go="$(head -n 1 go.mod | sed -E 's~.*/v(.*)~\1~')"

###
### SHA256SUM.md
###

read -r line < SHA256SUM.md

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

# Ensure major version matches go.mod
major_version_sha="$(sed -E 's/(.+)\..+\..+/\1/' <<< "$version")"

if [[ "$major_version_go" != "$major_version_sha" ]]; then
    echo "SHA256SUM.md and go.mod have different major versions:"
    echo "go.mod:       v$major_version_go"
    echo "SHA256SUM.md: v$major_version_sha (v$version)"
    
    exit 1
fi

version="$version_txt"

###
### README.md
###

results=$(
    grep -Pon ".*?slsa-verifier.*?\d+\.\d+\.\d+" README.md |
    grep -v "$version$" |
    sed -E 's/(.*)/  \1/' || true
)

if [[ "$results" != "" ]]; then
    echo "README.md and SHA256SUM.md refer to different versions:"
    echo "SHA256SUM.md: v$version"
    echo "README.md:"
    echo "$results"
    exit 1
fi
