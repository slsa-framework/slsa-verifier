#!/bin/bash
# SLSA verifier install script

shopt -s expand_aliases
if [ -z "$NO_COLOR" ]; then
  alias log_info="echo -e \"\033[1;32mINFO\033[0m:\""
  alias log_error="echo -e \"\033[1;31mERROR\033[0m:\""
else
  alias log_info="echo \"INFO:\""
  alias log_error="echo \"ERROR:\""
fi
set -euo pipefail

verifier_release="$1"
install_dir="$HOME/.slsa/bin/${verifier_release}"

mkdir -p "$install_dir"
cd "$install_dir"

if [[ "$verifier_release" == "main" ]]; then
    log_info "installing verifier via 'go install' from its main version"
    gobin="$(go env GOPATH)/bin"
    go install github.com/slsa-framework/slsa-verifier/cli/slsa-verifier@main
    ln -s "$gobin/slsa-verifier" "$install_dir/slsa-verifier"
    echo "Installed SLSA verifier at $install_dir/slsa-verifier"
    exit 0
fi

# Download v1.2.0 for bootstrapping
binary_addr="https://github.com/slsa-framework/slsa-verifier/releases/download/v1.2.0/slsa-verifier-linux-amd64"
sha256="37db23392c7918bb4e243cdb097ed5f9d14b9b965dc1905b25bc2d1c0c91bf3d slsa-verifier-linux-amd64"
if [[ "$verifier_release" == "test-force-checksum-error" ]]; then
  binary_addr="https://github.com/slsa-framework/slsa-verifier/releases/download/v0.0.1/slsa-verifier-linux-amd64"
fi
curl -sL "$binary_addr" -o slsa-verifier-linux-amd64
echo "$sha256" >> SHA256SUM.md

if ! sha256sum --quiet -c SHA256SUM.md ; then
  rm slsa-verifier-linux-amd64
  rm SHA256SUM.md
  log_error "Failed to verify binary checksum. Did not install SLSA verifier."
  exit 1
fi
mv slsa-verifier-linux-amd64 slsa-verifier-bootstrap
chmod +x slsa-verifier-bootstrap

case "$verifier_release" in
  "v0.0.1")
    ;&
  "v1.0.0")
    ;&
  "v1.0.1")
    ;&
  "v1.0.2")
    ;&
  "v1.1.0")
    ;&
  "v1.1.1")
    ;&
  "v1.3.0")
    binary_addr="https://github.com/slsa-framework/slsa-verifier/releases/download/$verifier_release/slsa-verifier-linux-amd64"
    provenance_addr="https://github.com/slsa-framework/slsa-verifier/releases/download/$verifier_release/slsa-verifier-linux-amd64.intoto.jsonl"
    ;;
  "v1.2.0")
    mv slsa-verifier-bootstrap slsa-verifier
    echo "Installed SLSA verifier at $install_dir/slsa-verifier"
    exit 0
    ;;
  "test-force-provenance-error")
    binary_addr="https://github.com/slsa-framework/slsa-verifier/releases/download/v1.3.0/slsa-verifier-linux-amd64"
    provenance_addr="https://github.com/slsa-framework/slsa-verifier/releases/download/v0.0.1/slsa-verifier-linux-amd64.intoto.jsonl"
    ;;
  *)
    log_error "Unknown SLSA verifier release $verifier_release"
    exit 1
    ;;
esac

curl -sL "$binary_addr" -o slsa-verifier-linux-amd64
curl -sL "$provenance_addr" -o slsa-verifier-linux-amd64.intoto.jsonl

if ! ./slsa-verifier-bootstrap -artifact-path slsa-verifier-linux-amd64 -provenance slsa-verifier-linux-amd64.intoto.jsonl -source github.com/slsa-framework/slsa-verifier -tag "$verifier_release" ; then
  rm slsa-verifier-linux-amd64
  rm slsa-verifier-linux-amd64.intoto.jsonl
  rm slsa-verifier-bootstrap
  rm SHA256SUM.md
  log_error "Failed to verify binary provenance. Did not install SLSA verifier."
  exit 2
fi

mv slsa-verifier-linux-amd64 slsa-verifier
chmod +x slsa-verifier
echo "Installed SLSA verifier at $install_dir/slsa-verifier"
exit 0
