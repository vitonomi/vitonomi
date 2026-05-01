#!/usr/bin/env bash
# check-spec-refs.sh — verify that every internal link in docs/ resolves.
#
# Walks all markdown files in docs/ and checks that:
#   1. Every relative link target exists as a file
#   2. Every #anchor link points to a heading that exists in the target
#
# Usage: scripts/check-spec-refs.sh [--strict]
#   --strict: also fail on TODO/TBD/XXX in stable-marked docs
#
# Run from the repo root.

set -euo pipefail

DOCS_DIR="$(dirname "$0")/../docs"
STRICT="${1:-}"

if [[ ! -d "$DOCS_DIR" ]]; then
  echo "error: $DOCS_DIR does not exist" >&2
  exit 1
fi

cd "$DOCS_DIR"

errors=0

# Extract every Markdown link of the form [text](target) where target does NOT
# start with a URL scheme. Also handle anchor-only links.
while IFS= read -r -d '' file; do
  while IFS= read -r match; do
    # match is like "(target)"; strip the parens
    target="${match#(}"
    target="${target%)}"

    # skip URLs and mailto links
    if [[ "$target" =~ ^https?:// ]] || [[ "$target" =~ ^mailto: ]]; then
      continue
    fi

    # split target into path#anchor
    path="${target%%#*}"
    anchor=""
    if [[ "$target" == *"#"* ]]; then
      anchor="${target#*#}"
    fi

    # resolve path (relative to the file it appears in)
    if [[ -n "$path" ]]; then
      resolved="$(dirname "$file")/$path"
    else
      resolved="$file"
    fi

    if [[ ! -f "$resolved" ]]; then
      echo "error: $file → broken link: $target (file not found at $resolved)" >&2
      errors=$((errors + 1))
      continue
    fi

    # check anchor if present (loose: case-insensitive header match)
    if [[ -n "$anchor" ]]; then
      anchor_lower="$(echo "$anchor" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')"
      if ! grep -qiE "^#+ .*${anchor_lower//-/.}" "$resolved"; then
        echo "error: $file → broken anchor: $target (anchor #$anchor not found in $resolved)" >&2
        errors=$((errors + 1))
      fi
    fi
  done < <(grep -oE '\([^()]+\.(md|yaml)(#[^()]+)?\)' "$file" || true)
done < <(find . -name '*.md' -print0)

if [[ "$STRICT" == "--strict" ]]; then
  while IFS= read -r -d '' file; do
    if grep -q '^status: stable' "$file"; then
      if grep -nE 'TODO|TBD|XXX' "$file" > /dev/null; then
        echo "error: $file is status:stable but contains TODO/TBD/XXX:" >&2
        grep -nE 'TODO|TBD|XXX' "$file" >&2
        errors=$((errors + 1))
      fi
    fi
  done < <(find . -name '*.md' -print0)
fi

if [[ $errors -gt 0 ]]; then
  echo "" >&2
  echo "$errors error(s) found." >&2
  exit 1
fi

echo "spec refs OK"
