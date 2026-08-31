#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
OWNER="${FSS_GITHUB_OWNER:-Dicklesworthstone}"
REPO="${FSS_GITHUB_REPO:-franken_surveillance_system}"
VISIBILITY="${FSS_GITHUB_VISIBILITY:-public}"

bash scripts/qualify.sh --lane policy
if ! command -v gh >/dev/null 2>&1; then
  printf '%s\n' 'GitHub CLI `gh` is required. Install and authenticate it, then rerun.' >&2
  exit 2
fi
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git init -b main
fi
if ! git config user.name >/dev/null 2>&1; then
  git config user.name "${FSS_GIT_AUTHOR_NAME:-FSS Publisher}"
fi
if ! git config user.email >/dev/null 2>&1; then
  git config user.email "${FSS_GIT_AUTHOR_EMAIL:-fss-publisher@users.noreply.github.com}"
fi
if ! git diff --quiet || ! git diff --cached --quiet || [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  git add --all
  git commit -m "Initial FSS architecture constitution"
fi
if gh repo view "$OWNER/$REPO" >/dev/null 2>&1; then
  git remote remove origin >/dev/null 2>&1 || true
  git remote add origin "https://github.com/$OWNER/$REPO.git"
  git push -u origin main
else
  gh repo create "$OWNER/$REPO" --"$VISIBILITY" --source=. --remote=origin --push \
    --description "Evidence-native, local-first multimodal sensor fusion and home security in Rust"
fi
printf 'Published https://github.com/%s/%s\n' "$OWNER" "$REPO"
