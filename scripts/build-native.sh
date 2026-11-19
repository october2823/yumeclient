#!/usr/bin/env sh
# Build the native library for Linux (yumeclient.so) or macOS (yumeclient.dylib).
# Windows uses scripts/build-native.ps1 (yumeclient.dll); running this script
# there used to drop a PE image named yumeclient.so into Windows wheels.
#
# macOS: builds arm64 + x86_64 with MACOSX_DEPLOYMENT_TARGET (default 11.0, the
# Go 1.24 minimum) and merges them with lipo into a real universal2 dylib.
# Set YUMECLIENT_MAC_ARCHS="arm64" (or "amd64") for a faster host-only build.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out="$root/yumeclient"
mkdir -p "$out"
goos=$(go env GOOS)

case "$goos" in
  windows)
    echo "build-native.sh: use scripts/build-native.ps1 on Windows" >&2
    exit 1
    ;;
  darwin)
    target="${MACOSX_DEPLOYMENT_TARGET:-11.0}"
    export MACOSX_DEPLOYMENT_TARGET="$target"
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    slices=""
    for arch in ${YUMECLIENT_MAC_ARCHS:-arm64 amd64}; do
      clang_arch=$arch
      [ "$arch" = amd64 ] && clang_arch=x86_64
      CGO_ENABLED=1 GOOS=darwin GOARCH="$arch" CC="clang -arch $clang_arch" \
        CGO_CFLAGS="-mmacosx-version-min=$target" CGO_LDFLAGS="-mmacosx-version-min=$target" \
        go -C "$root/native" build -trimpath -buildmode=c-shared -o "$tmp/yumeclient-$arch.dylib" .
      slices="$slices $tmp/yumeclient-$arch.dylib"
    done
    # shellcheck disable=SC2086
    lipo -create -output "$out/yumeclient.dylib" $slices
    lipo -info "$out/yumeclient.dylib"
    ;;
  *)
    CGO_ENABLED=1 go -C "$root/native" build -trimpath -buildmode=c-shared -o "$out/yumeclient.so" .
    ;;
esac
rm -f "$out/yumeclient.h"
