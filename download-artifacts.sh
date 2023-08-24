#!/bin/bash
set -euo pipefail

# USAGE: mkdir -p tmp/v14 tmp/v14.2 tmp/v13.0.30 tmp/dispatch
# cd in each folder, and run `bash ../../download-artifacts.sh run_id builder_tag
# example: bash ../../download-artifacts.sh 5947345583 v1.9.0

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 run_id version"
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


unzip_files() {
    local zip_path="$1"
    local output_path="$2"

    case "${zip_path}" in

    # Ignore some files.
    ./slsa-builder-go-linux-amd64*)
        echo "Ignoring ${zip_path}"
        ;;

    # Container-based artifact and provenance.
    ./build-outputs-*.zip | ./slsa-outputs-*.zip)
        unzip -o "${zip_path}" -d "${output_path}"
        ;;

    # See partern marching https://stackoverflow.com/questions/4554718/how-to-use-patterns-in-a-case-statement.
    ./gha_*)
        unzip -o "${zip_path}" -d "${output_path}"
        ;;

    # Low-perm delegator artifact.
    ./*-artifacts.zip)
        tmp_dir=$(mktemp -d) 
        unzip -o "${zip_path}" -d "${tmp_dir}"
        cd "${tmp_dir}"
        tar xvzf folder.tgz
        cd -
        cp "${tmp_dir}/artifacts/"* "${output_path}"
        rm -rf "${tmp_dir}"
        ;;

    # delegator attestations.
    ./*-slsa-attestations.zip)
        tmp_dir=$(mktemp -d) 
        unzip -o "${zip_path}" -d "${tmp_dir}"
        cd "${tmp_dir}"
        tar xvzf folder.tgz
        cd -
        cp "${tmp_dir}/${zip_path%.*}/"* "${output_path}"
        rm -rf "${tmp_dir}"
        ;;

    # Maven artifacts.
    ./*-target.zip)
        tmp_dir=$(mktemp -d) 
        unzip -o "${zip_path}" -d "${tmp_dir}"
        cd "${tmp_dir}"
        tar xvzf folder.tgz
        cd -
        cp "${tmp_dir}/target/test-java-project-"*.jar "${output_path}"
        rm -rf "${tmp_dir}"
        ;;

     # Gradle artifacts.
    ./*-build.zip)
        tmp_dir=$(mktemp -d) 
        unzip -o "${zip_path}" -d "${tmp_dir}"
        cd "${tmp_dir}"
        tar xvzf folder.tgz
        cd -
        cp "${tmp_dir}/build/libs/workflow_dispatch-"*.jar "${output_path}"
        rm -rf "${tmp_dir}"
        ;;

    *)
        echo "unexpected file path: ${zip_path}"
        exit 1
        ;;
    esac

    # Cleanup
    rm *sources.jar* *javadoc.jar* folder.tgz original-test-java-project* 2>/dev/null || true
    rm "${zip_path}"
}

copy_files() {
    local binary="$1"
    local path="$2"
    mkdir -p "${path}"
    for fn in $(ls | grep "${binary}"); do
        prefix=$(echo "${fn}" | cut -d- -f1)"-"
        cp "${fn}" "${path}/${fn#"${prefix}"}"
    done;
}

# Rename jar files and their attestations.
rename_java_files() {
    local path="$1"
    local name="$2"
    v=$(ls | grep gha_delegator-binary-linux-amd64- | grep -v slsa | cut -d- -f5)
    if [[ "${v}" == "" ]]; then
        return
    fi
    artifact=$(ls | grep "${path}" | grep -v slsa || true)
    if [[ "${artifact}" == "" ]]; then
        return
    fi 
    mv "${artifact}" "gha_${name}-binary-linux-amd64-${v}"
    mv "${artifact}.build.slsa" "gha_${name}-binary-linux-amd64-${v}.build.slsa"
}

# Script inputs
run_id="$1"
version="$2"
output_path="."
repo=slsa-framework/example-package

artifacts=$($GH api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "/repos/${repo}/actions/runs/${run_id}/artifacts" |
    jq -r -c '.artifacts')

arr=$(echo "$artifacts" | jq -c '.[]')

for item in ${arr}; do
    artifact_id=$(echo "${item}" | jq -r '.id')
    artifact_name=$(echo "${item}" | jq -r '.name')
    zip_path="${output_path}/${artifact_name}.zip"
    $GH api \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "/repos/${repo}/actions/artifacts/${artifact_id}/zip" \
        >"${zip_path}"
    echo "Downloaded ${zip_path}"
    unzip_files "${zip_path}" "${output_path}"
done

rename_java_files "test-java-project-" "maven"
rename_java_files "workflow_dispatch-" "gradle"

# Files downloaded. Now copy them
repo_path="../.."

# Go builder files.
copy_files "gha_go-binary-linux-amd64-" "${repo_path}/cli/slsa-verifier/testdata/gha_go/${version}"

# Generic generator.
copy_files "gha_generic-binary-linux-amd64-" "${repo_path}/cli/slsa-verifier/testdata/gha_generic/${version}"
# Container based.
copy_files "gha_container-based-binary-linux-amd64-" "${repo_path}/cli/slsa-verifier/testdata/gha_container-based/${version}"
# TODO: generic container

# Delegator
copy_files "gha_delegator-binary-linux-amd64-" "${repo_path}/cli/slsa-verifier/testdata/gha_delegator/${version}"
# Maven builder
copy_files "gha_maven-binary-linux-amd64-" "${repo_path}/cli/slsa-verifier/testdata/gha_maven/${version}"
# gradle builder
copy_files "gha_gradle-binary-linux-amd64-" "${repo_path}/cli/slsa-verifier/testdata/gha_gradle/${version}"