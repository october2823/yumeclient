#!/usr/bin/env sh
# Build one manylinux py3-none wheel inside the pypa manylinux image.
# Usage: build-linux-wheel.sh [x86_64|aarch64]   (default: host architecture)
# Run on a runner of the same architecture (ubuntu-*-arm for aarch64).
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
arch="${1:-$(uname -m)}"
case "$arch" in
  x86_64|amd64) arch=x86_64; goarch=amd64 ;;
  aarch64|arm64) arch=aarch64; goarch=arm64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 2 ;;
esac
go_version="${GO_VERSION:-1.24.13}"
image="quay.io/pypa/manylinux_2_28_${arch}"

docker run --rm -e GO_VERSION="$go_version" -e GOARCH_HOST="$goarch" -v "$root:/src" -w /src "$image" bash -lc '
set -eu
curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH_HOST}.tar.gz" -o /tmp/go.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tar.gz
export PATH=/usr/local/go/bin:$PATH
CGO_ENABLED=1 go -C native build -buildvcs=false -trimpath -buildmode=c-shared -o ../yumeclient/yumeclient.so .
rm -f yumeclient/yumeclient.h
py=/opt/python/cp312-cp312/bin/python
"$py" -m pip install --disable-pip-version-check setuptools wheel auditwheel
"$py" setup.py bdist_wheel
mkdir -p dist/repaired
"$py" -m auditwheel repair dist/*-linux_*.whl -w dist/repaired
rm -f dist/*-linux_*.whl
mv dist/repaired/*.whl dist/
rm -rf dist/repaired build yumeclient.egg-info
'
