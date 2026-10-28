#!/bin/sh
# Pack a built macflow-check binary into the release tarball and its checksum.
# usage: scripts/package.sh <path-to-binary> <version> <out-dir>
# Writes macflow-check-<version>-macos-universal.tar.gz and a .sha256 next to it.
set -eu

bin=$1
version=$2
out=$3

name="macflow-check-${version}-macos-universal"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

mkdir -p "$stage/$name" "$out"
cp "$bin" "$stage/$name/macflow-check"
chmod 755 "$stage/$name/macflow-check"
for f in README.md LICENSE; do
  [ -f "$f" ] && cp "$f" "$stage/$name/"
done

tar -C "$stage" -czf "$out/$name.tar.gz" "$name"
(cd "$out" && shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256")
echo "$out/$name.tar.gz"
