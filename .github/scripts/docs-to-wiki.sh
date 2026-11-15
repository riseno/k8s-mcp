#!/usr/bin/env bash
# Render docs/ as GitHub wiki pages: usage: docs-to-wiki.sh <docs-dir> <out-dir> <owner/repo>
#
# Wiki pages are flat and linked by page name, so `page.md` and `adr/page.md` links become
# `page`, and `../FILE` links point at the file on the default branch. SUMMARY.md becomes the
# Home page and the sidebar; a footer says edits belong in the repository.
set -euo pipefail
docs="$1" out="$2" repo="$3"
blob="https://github.com/$repo/blob/main"

links() {
  sed -E \
    -e "s|\]\(\.\./([^)#]+)(#[^)]*)?\)|](${blob}/\1\2)|g" \
    -e 's|\]\((adr/)?([A-Za-z0-9_.-]+)\.md(#[^)]*)?\)|](\2\3)|g'
}

mkdir -p "$out"
find "$docs" -name '*.md' ! -name SUMMARY.md -print0 | while IFS= read -r -d '' f; do
  links < "$f" > "$out/$(basename "$f")"
done
{
  echo "# k8s-mcp documentation"
  echo
  echo "Safe, read-only-by-default MCP server for troubleshooting any Kubernetes cluster. Start with the [README]($blob/README.md)."
  echo
  links < "$docs/SUMMARY.md" | sed '1d' | sed '/./,$!d'
} > "$out/Home.md"
links < "$docs/SUMMARY.md" | sed '1s/^# Summary$/**[Home](Home)**/' > "$out/_Sidebar.md"
echo "Generated from [\`docs/\`]($blob/docs) in the repository by the \`wiki\` workflow. Edit the files there: changes made here are overwritten." > "$out/_Footer.md"
