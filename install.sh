#!/bin/sh
# Install macflow-check from GitHub Releases.
#   curl -fsSL https://raw.githubusercontent.com/mazharul/macflow-check/main/install.sh | sh
# Downloads the universal macOS binary, verifies its SHA-256, and installs it to
# ~/.local/bin (or $MACFLOW_CHECK_INSTALL_DIR). Never uses sudo.
# Homebrew alternative: brew install mazharul/tap/macflow-check
set -eu

repo="mazharul/macflow-check"
version="${MACFLOW_CHECK_VERSION:-latest}"
dest="${MACFLOW_CHECK_INSTALL_DIR:-$HOME/.local/bin}"

fail() {
  echo "macflow-check install: $1" >&2
  exit 1
}

[ "$(uname -s)" = "Darwin" ] || fail "macflow-check runs on macOS only."
command -v curl >/dev/null || fail "curl is required."
command -v shasum >/dev/null || fail "shasum is required."

if [ "$version" = "latest" ]; then
  version=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" |
    sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -n 1)
  [ -n "$version" ] || fail "could not find the latest release of $repo."
fi
version=${version#v}

name="macflow-check-${version}-macos-universal"
base="${MACFLOW_CHECK_BASE_URL:-https://github.com/$repo/releases/download/v$version}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading macflow-check $version..."
curl -fsSL "$base/$name.tar.gz" -o "$tmp/$name.tar.gz" || fail "download failed: $base/$name.tar.gz"
curl -fsSL "$base/$name.tar.gz.sha256" -o "$tmp/$name.tar.gz.sha256" || fail "checksum download failed."

expected=$(awk '{print $1}' "$tmp/$name.tar.gz.sha256")
actual=$(shasum -a 256 "$tmp/$name.tar.gz" | awk '{print $1}')
[ -n "$expected" ] && [ "$expected" = "$actual" ] || fail "checksum mismatch; not installing."

tar -C "$tmp" -xzf "$tmp/$name.tar.gz"
mkdir -p "$dest"
install -m 755 "$tmp/$name/macflow-check" "$dest/macflow-check"

echo "Installed $dest/macflow-check"
case ":$PATH:" in
  *":$dest:"*) echo "Run: macflow-check" ;;
  *) echo "Run: $dest/macflow-check   (or add $dest to your PATH)" ;;
esac
