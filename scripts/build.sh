#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
(cd web && npm ci --ignore-scripts && npm run build)
go mod verify
go test ./...
for target in windows/amd64 linux/amd64 linux/arm64; do
 os=${target%/*}; arch=${target#*/}; name=portal
 [[ $os == windows ]] && name=portal.exe
 mkdir -p "dist/$os-$arch"
 CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags='-s -w' -o "dist/$os-$arch/$name" ./cmd/portal
done
