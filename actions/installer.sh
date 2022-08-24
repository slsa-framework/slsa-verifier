#!/bin/bash
# SLSA verifier install script

VERIFIER_RELEASE="$1"
INSTALL_DIR="$2"
SUDO=
if [[ "$3" == "true" ]]; then
  SUDO=sudo
fi

shopt -s expand_aliases
if [ -z "$NO_COLOR" ]; then
  alias log_info="echo -e \"\033[1;32mINFO\033[0m:\""
  alias log_error="echo -e \"\033[1;31mERROR\033[0m:\""
else
  alias log_info="echo \"INFO:\""
  alias log_error="echo \"ERROR:\""
fi
set -e

${SUDO} mkdir -p ${INSTALL_DIR}
cd ${INSTALL_DIR}

if [[ "${VERIFIER_RELEASE}" == "main" ]]; then
    log_info "installing verifier via 'go install' from its main version"
    GOBIN=$(go env GOPATH)/bin
    go install github.com/slsa-framework/slsa-verifier/cli/slsa-verifier@main
    ${SUDO} ln -s ${GOBIN}/slsa-verifier ${INSTALL_DIR}/slsa-verifier
    echo "Installed SLSA verifier at ${INSTALL_DIR}/slsa-verifier"
    exit 0
fi

# Download v1.2.0 for bootstrapping
BINARY_ADDR="https://github.com/slsa-framework/slsa-verifier/releases/download/v1.2.0/slsa-verifier-linux-amd64"
SHA256="37db23392c7918bb4e243cdb097ed5f9d14b9b965dc1905b25bc2d1c0c91bf3d slsa-verifier-linux-amd64"
${SUDO} curl -sL ${BINARY_ADDR} -o slsa-verifier-linux-amd64
if [[ "$3" == "true" ]]; then
  echo "${SHA256}" | sudo tee -a SHA256SUM.md > /dev/null
else
  echo ${SHA256} >> SHA256SUM.md
fi

if [[ ! $(sha256sum -c SHA256SUM.md) ]]; then
  ${SUDO} rm slsa-verifier-linux-amd64
  ${SUDO} rm SHA256SUM.md
  log_error "Failed to verify binary checksum. Did not install SLSA verifier."
  exit 1
fi
${SUDO} mv slsa-verifier-linux-amd64 slsa-verifier-bootstrap
${SUDO} chmod +x slsa-verifier-bootstrap


case "${VERIFIER_RELEASE}" in
  "v0.0.1")
    BINARY_ADDR="https://github.com/slsa-framework/slsa-verifier/releases/download/v0.0.1/slsa-verifier-linux-amd64"
    PROVENANCE_ADDR="https://github.com/slsa-framework/slsa-verifier/releases/download/v1.3.0/slsa-verifier-linux-amd64.intoto.jsonl"
    ;;
  "v1.0.0")
    BINARY_ADDR="https://github.com/slsa-framework/slsa-verifier/releases/download/v1.0.0/slsa-verifier-linux-amd64"
    PROVENANCE_ADDR="https://github.com/slsa-framework/slsa-verifier/releases/download/v1.3.0/slsa-verifier-linux-amd64.intoto.jsonl"
    ;;
  "v1.0.1")
    BINARY_ADDR="https://github.com/slsa-framework/slsa-verifier/releases/download/v1.0.1/slsa-verifier-linux-amd64"
    PROVENANCE_ADDR="https://github.com/slsa-framework/slsa-verifier/releases/download/v1.3.0/slsa-verifier-linux-amd64.intoto.jsonl"
    ;;
  "v1.0.2")
    BINARY_ADDR="https://github.com/slsa-framework/slsa-verifier/releases/download/v1.0.2/slsa-verifier-linux-amd64"
    PROVENANCE_ADDR="https://github.com/slsa-framework/slsa-verifier/releases/download/v1.3.0/slsa-verifier-linux-amd64.intoto.jsonl"
    ;;
  "v1.1.0")
    BINARY_ADDR="https://github.com/slsa-framework/slsa-verifier/releases/download/v1.1.0/slsa-verifier-linux-amd64"
    PROVENANCE_ADDR="https://github.com/slsa-framework/slsa-verifier/releases/download/v1.3.0/slsa-verifier-linux-amd64.intoto.jsonl"
    ;;
  "v1.1.1")
    BINARY_ADDR="https://github.com/slsa-framework/slsa-verifier/releases/download/v1.1.1/slsa-verifier-linux-amd64"
    PROVENANCE_ADDR="https://github.com/slsa-framework/slsa-verifier/releases/download/v1.3.0/slsa-verifier-linux-amd64.intoto.jsonl"
    ;;
  "v1.2.0")
    ${SUDO} mv slsa-verifier-bootstrap slsa-verifier
    echo "Installed SLSA verifier at ${INSTALL_DIR}/slsa-verifier"
    exit 0
    ;;
  "v1.3.0")
    BINARY_ADDR="https://github.com/slsa-framework/slsa-verifier/releases/download/v1.3.0/slsa-verifier-linux-amd64"
    PROVENANCE_ADDR="https://github.com/slsa-framework/slsa-verifier/releases/download/v1.3.0/slsa-verifier-linux-amd64.intoto.jsonl"
    ;;
  *)
    log_error "Unknown SLSA verifier release ${VERIFIER_RELEASE}"
    exit 1
    ;;
esac

${SUDO} curl -sL ${BINARY_ADDR} -o slsa-verifier-linux-amd64
${SUDO} curl -sL ${PROVENANCE_ADDR} -o slsa-verifier-linux-amd64.intoto.jsonl

if [[ $(slsa-verifier-bootstrap -artifact-path slsa-verifier-linux-amd64 -provenance slsa-verifier-linux-amd64.intoto.jsonl -source github.com/slsa-framework/slsa-verifier -tag ${VERIFIER_RELEASE}) ]]; then
  ${SUDO} rm slsa-verifier-linux-amd64
  ${SUDO} rm slsa-verifier-linux-amd64.intoto.jsonl
  ${SUDO} rm slsa-verifier-bootstrap
  ${SUDO} rm SHA256SUM.md
  log_error "Failed to verify binary provenance. Did not install SLSA verifier."
  exit 1
fi

${SUDO} mv slsa-verifier-linux-amd64 slsa-verifier
${SUDO} chmod +x slsa-verifier
echo "Installed SLSA verifier at ${INSTALL_DIR}/slsa-verifier"
exit 0
