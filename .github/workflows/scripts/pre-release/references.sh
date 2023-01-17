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

version="$version_txt"

major_version_sha256sum_md="$(sed -E 's/(.+)\..+\..+/\1/' <<< "$version")"

###
### go.mod
###

# Get major version from go.mod
major_version_go_mod="$(get_first_nonblank_line go.mod | sed -E 's~.*/v(.*)~\1~')"

# Ensure major version from SHA256SUM.md matches go.mod's
if [[ "$major_version_go_mod" != "$major_version_sha256sum_md" ]]; then
    echo "SHA256SUM.md and go.mod have different major versions:"
    echo "go.mod:       v$major_version_go_mod"
    echo "SHA256SUM.md: v$major_version_sha256sum_md (v$version)"

    exit 1
fi

###
### README.md
###

# Select all version numbers following a reference to slsa-verifier that are different
# from the version defined in SHA256SUM.md
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
