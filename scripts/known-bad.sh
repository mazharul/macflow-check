#!/bin/sh
# Sign and publish the known-bad list. Owner-only: needs the minisign secret key.
#
# usage:
#   scripts/known-bad.sh sign       on the list PR's branch: checks the list, signs it
#                                   (asks for the key password), then commit the .minisig
#   scripts/known-bad.sh publish    after the PR is merged: copies known-bad/ from the
#                                   merged monorepo main to the public repo and pushes
#
# Users' scanners download known-bad/known-bad.json and its .minisig from the public
# repo and use the list only if this key signed it and its serial is newer than the
# copy built into their binary.
set -eu

KEY=${MACFLOW_LIST_KEY:-$HOME/.minisign/macflow-known-bad.key}
PUBLIC_REPO=git@github.com:mazharul/macflow-check.git
RAW=https://raw.githubusercontent.com/mazharul/macflow-check/main/known-bad/known-bad.json

here=$(cd "$(dirname "$0")/.." && pwd)
list="$here/known-bad/known-bad.json"
pub="$here/known-bad/minisign.pub"

serial_of() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)["serial"])'
}

case "${1:-}" in
sign)
  command -v minisign >/dev/null || { echo "install minisign: brew install minisign" >&2; exit 1; }
  [ -f "$KEY" ] || { echo "no secret key at $KEY" >&2; exit 1; }
  new=$(serial_of <"$list")
  live=$(curl -sS --fail --max-time 10 "$RAW" 2>/dev/null | serial_of 2>/dev/null || echo 0)
  if [ "$new" -le "$live" ]; then
    echo "serial $new is not newer than the published list ($live); bump \"serial\" first" >&2
    exit 1
  fi
  # The scanner checks the same rules; this catches a list that would be dropped.
  (cd "$here" && cargo test -q -p macflow-scan known_bad >/dev/null)
  minisign -S -s "$KEY" -m "$list" -t "macflow-check known-bad list, serial $new"
  minisign -V -q -p "$pub" -m "$list"
  echo "signed serial $new. Commit known-bad/known-bad.json.minisig to this PR."
  ;;
publish)
  mono=$(git -C "$here" rev-parse --show-toplevel)
  git -C "$mono" fetch -q origin
  stage=$(mktemp -d)
  trap 'rm -rf "$stage"' EXIT
  git clone -q --depth 1 "$PUBLIC_REPO" "$stage/repo"
  mkdir -p "$stage/repo/known-bad"
  for f in known-bad.json known-bad.json.minisig minisign.pub; do
    git -C "$mono" show "origin/main:oss/macflow-check/known-bad/$f" >"$stage/repo/known-bad/$f"
  done
  minisign -V -q -p "$pub" -m "$stage/repo/known-bad/known-bad.json" \
    -x "$stage/repo/known-bad/known-bad.json.minisig" || {
    echo "the list on monorepo main is not signed by the owner key; run 'sign' on the PR first" >&2
    exit 1
  }
  new=$(serial_of <"$stage/repo/known-bad/known-bad.json")
  cd "$stage/repo"
  if git diff --quiet -- known-bad && [ -z "$(git status --porcelain known-bad)" ]; then
    echo "public repo already has serial $new"
    exit 0
  fi
  git add known-bad
  git -c user.name="Mazharul Anwar" -c user.email="mazharul@users.noreply.github.com" \
    commit -q -m "known-bad list: serial $new"
  git push -q origin HEAD:main
  echo "published serial $new: scanners pick it up on their next online run"
  ;;
*)
  sed -n '2,13p' "$0" >&2
  exit 2
  ;;
esac
