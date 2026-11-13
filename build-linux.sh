#!/bin/bash
# Builds the Linux app in Docker (it needs Linux tools), into desktop/dist:
#   AppImage for x64, and .deb for x64 and arm64, plus SHA256SUMS-linux.txt.
# VERSION defaults to the one in desktop/package.json. release.sh uploads these files with the release.
set -euo pipefail
cd "$(dirname "$0")"
VERSION="${VERSION:-$(node -p "require('./desktop/package.json').version")}"
node desktop/gen-strings.js --check
node --test test/ >/dev/null || { echo "Tests failed: run  node --test test/  to see which."; exit 1; }
(cd desktop && npm version --no-git-tag-version --allow-same-version "$VERSION" >/dev/null)
docker build -q -t ai-access-auditor-linux-build -f desktop/build.Dockerfile desktop >/dev/null
docker run --rm -v "$PWD":/src -v ai-access-auditor-node-modules:/src/desktop/node_modules -v ai-access-auditor-build-cache:/root/.cache \
  -w /src/desktop -e USE_SYSTEM_FPM=true -e ELECTRON_SKIP_BINARY_DOWNLOAD=1 ai-access-auditor-linux-build bash -c "
    npm ci --no-audit --no-fund >/dev/null
    rm -rf dist
    npx electron-builder --linux --publish never 2>&1 | grep -E 'building|⨯|rror' || true
    cd dist && sha256sum *.AppImage *.deb > SHA256SUMS-linux.txt
    chown -R $(id -u):$(id -g) /src/desktop/dist"
for f in "AI-Access-Auditor-$VERSION-x86_64.AppImage" "AI-Access-Auditor-$VERSION-amd64.deb" "AI-Access-Auditor-$VERSION-arm64.deb"; do
  [ -f "desktop/dist/$f" ] || { echo "Missing desktop/dist/$f"; exit 1; }
done
cat desktop/dist/SHA256SUMS-linux.txt
