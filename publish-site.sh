#!/bin/bash
# Publishes the site/ folder to GitHub Pages (served from the gh-pages branch).
set -euo pipefail
cd "$(dirname "$0")"
git subtree split --prefix site -b gh-pages-new >/dev/null
git push -f origin gh-pages-new:gh-pages
git branch -D gh-pages-new >/dev/null
echo "Published: https://dirmedmr-alt.github.io/ai-access-auditor/ (live in about a minute)"
