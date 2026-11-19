#!/usr/bin/env bash
set -euo pipefail

version=0.76.2
digest=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf
cd "${RUNNER_TEMP:?}"
curl -fsSLo trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${version}/trivy_${version}_Linux-64bit.tar.gz"
echo "${digest}  trivy.tgz" | sha256sum -c -
tar xzf trivy.tgz trivy
