#!/usr/bin/env bash
set -euo pipefail

git add -A
git commit -s -m "$(cat <<'EOF'
feat(F022-F024): CRDs + priority enforcement + cache consistency + red team hardened

EOF
)"
git push origin main
git status --short
