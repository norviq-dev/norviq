#!/usr/bin/env bash
set -euo pipefail
git add -A
git commit --trailer "Co-authored-by: Cursor <cursoragent@cursor.com>" -s -m "$(cat <<'EOF'
fix(ci): render Helm templates before kubeconform validation

EOF
)"
git push origin main
git status --short
