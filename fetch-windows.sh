#!/bin/bash
# Downloads the Windows installers that AppVeyor built and tested for the current commit (see appveyor.yml)
# into desktop/dist/windows, with SHA256SUMS-windows.txt. release.sh runs it and uploads the files.
set -euo pipefail
cd "$(dirname "$0")"
VERSION="${VERSION:-$(node -p "require('./desktop/package.json').version")}"
PROJECT="https://ci.appveyor.com/api/projects/dirmedmr-alt/ai-access-auditor"
COMMIT=$(git rev-parse HEAD)
BUILD=$(curl -fsS "$PROJECT/history?recordsNumber=30" | node -e "
  let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
    const b=JSON.parse(d).builds.find(x=>x.commitId==='$COMMIT'&&x.status==='success');
    console.log(b?b.version:'')})")
if [ -z "$BUILD" ]; then echo "No successful AppVeyor build for $COMMIT yet: push it and wait for https://ci.appveyor.com/project/dirmedmr-alt/ai-access-auditor"; exit 1; fi
JOB=$(curl -fsS "$PROJECT/build/$BUILD" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>console.log(JSON.parse(d).build.jobs[0].jobId))")
OUT=desktop/dist/windows
mkdir -p "$OUT"
for A in x64 arm64; do
  F="AI-Access-Auditor-$VERSION-windows-$A.exe"
  curl -fsSL -o "$OUT/$F" "https://ci.appveyor.com/api/buildjobs/$JOB/artifacts/desktop/dist/$F"
done
( cd "$OUT" && shasum -a 256 AI-Access-Auditor-$VERSION-windows-*.exe > SHA256SUMS-windows.txt && cat SHA256SUMS-windows.txt )
