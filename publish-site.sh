#!/bin/bash
# Publishes the site/ folder to GitHub Pages (served from the gh-pages branch).
set -euo pipefail
cd "$(dirname "$0")"
node i18n/build-site.js   # rebuild the French and Arabic pages from site/index.html
if [ -n "$(git status --porcelain -- site i18n)" ]; then
  echo "site/ or i18n/ has changes that aren't committed yet. Commit them first, then run this again:"
  git status --short -- site i18n
  exit 1
fi
git subtree split --prefix site -b gh-pages-new >/dev/null
git push -f origin gh-pages-new:gh-pages
git branch -D gh-pages-new >/dev/null
echo "Published: https://dirmedmr-alt.github.io/ai-access-auditor/ (live in about a minute)"
