#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="/var/lib/cybersecurity-ops/downloads"
if [ "$#" -ge 1 ]; then
  OUT="$1"
fi

mkdir -p "$OUT"
cd "$ROOT/agent"

build() {
  local goos="$1"
  local goarch="$2"
  local name="$3"
  echo "Building $name..."
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags="-s -w" -o "$OUT/$name" .
}

build linux amd64 cyberagent-linux-amd64
build linux arm64 cyberagent-linux-arm64
build windows amd64 cyberagent-windows-amd64.exe
build windows arm64 cyberagent-windows-arm64.exe
build darwin amd64 cyberagent-darwin-amd64
build darwin arm64 cyberagent-darwin-arm64

tmp="$(mktemp -d)"
cp "$OUT/cyberagent-darwin-amd64" "$tmp/"
cp "$OUT/cyberagent-darwin-arm64" "$tmp/"
(
  cd "$tmp"
  zip -q "$OUT/cyberagent-darwin-universal.zip" cyberagent-darwin-amd64 cyberagent-darwin-arm64
)
rm -rf "$tmp"

echo "Desktop agent builds written to $OUT"
