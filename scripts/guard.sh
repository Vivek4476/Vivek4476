#!/usr/bin/env bash
# Leak guard for this public profile repo.
#   guard.sh staged   -> checks what is about to be committed (pre-commit hook)
#   guard.sh tree     -> checks every tracked file (CI)
# The denylist of sensitive terms is NEVER stored in this repo:
#   locally  -> $HOME/.config/profile-guard/denylist.txt
#   in CI    -> the DENYLIST repository secret, passed via $DENYLIST_FILE
set -euo pipefail
mode="${1:-staged}"
denylist="${DENYLIST_FILE:-$HOME/.config/profile-guard/denylist.txt}"
fail=0
say() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; fail=1; }

[ -s "$denylist" ] || { say "denylist missing or empty ($denylist) — refusing to continue"; exit 1; }

if [ "$mode" = staged ]; then
  files=$(git diff --cached --name-only --diff-filter=ACMR)
  show() { git show ":$1"; }
else
  files=$(git ls-files)
  show() { cat "$1"; }
fi

# 1. Secrets (tokens, keys, credentials)
if [ "$mode" = staged ]; then
  gitleaks git --pre-commit --staged --no-banner --redact >/dev/null 2>&1 || say "gitleaks found a secret — run: gitleaks git --pre-commit --staged -v"
else
  gitleaks dir . --no-banner --redact >/dev/null 2>&1 || say "gitleaks found a secret — run: gitleaks dir . -v"
fi

for f in $files; do
  case "$f" in scripts/guard.sh) continue ;; esac
  # 2. Sensitive file names
  printf '%s\n' "$f" | grep -qiF -f "$denylist" && say "$f: file name matches denylist"
  case "$f" in
    *.jpg|*.jpeg|*.png|*.heic|*.webp|*.gif|*.tif|*.tiff)
      # 3. Raster images must carry no metadata (GPS, device, owner)
      show "$f" | python3 -c 'import sys,io
from PIL import Image
im=Image.open(io.BytesIO(sys.stdin.buffer.read()))
bad=[k for k in ("exif","xmp","icc_profile","comment") if im.info.get(k)] + (["EXIF"] if len(im.getexif()) else [])
sys.exit(1 if bad else 0)' || say "$f: image carries metadata — strip it first"
      continue ;;
    *.csv|*.xlsx|*.xls|*.json|*.sqlite|*.db|*.env|*.pem|*.key)
      say "$f: data/credential file types are not allowed in this repo"; continue ;;
  esac
  # strip embedded base64 blobs (e.g. the avatar) before text checks
  text=$(show "$f" | sed -E 's#data:[a-z/+.-]+;base64,[A-Za-z0-9+/=]+#<blob>#g')
  # 4. Denylisted terms
  hits=$( { printf "%s" "$text" | grep -oiF -f "$denylist" || true; } | sort -u | wc -l | tr -d " ")
  [ "$hits" != 0 ] && say "$f: contains $hits denylisted term(s) — run: grep -niF -f \"$denylist\" $f"
  # 5. Personal contact details
  emails=$(printf '%s' "$text" | grep -oiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' | grep -viE 'noreply' || true)
  [ -n "$emails" ] && say "$f: contains an email address"
  printf '%s' "$text" | grep -qE '(^|[^0-9])[6-9][0-9]{9}([^0-9]|$)' && say "$f: contains a phone-number-like string"
  # 6. IP addresses
  printf '%s' "$text" | grep -qE '(^|[^0-9.])([0-9]{1,3}\.){3}[0-9]{1,3}([^0-9.]|$)' && say "$f: contains an IP address"
done

[ "$fail" = 0 ] && echo "✓ leak guard passed ($mode)" || { echo "✗ leak guard BLOCKED ($mode)" >&2; exit 1; }
