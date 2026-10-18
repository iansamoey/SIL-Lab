#!/usr/bin/env bash
# Installs pinned security tools into ~/.local/bin, verifying checksums.
# Pinned versions are at least two weeks old (new releases are a supply-chain risk).
set -euo pipefail
GITLEAKS_VERSION="8.30.1"
BIN="$HOME/.local/bin"; mkdir -p "$BIN"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

echo "== gitleaks v$GITLEAKS_VERSION"
base="https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION"
tarball="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
curl -fsSL -o "$tmp/$tarball" "$base/$tarball"
curl -fsSL -o "$tmp/checksums.txt" "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt"
(cd "$tmp" && grep " $tarball\$" checksums.txt | sha256sum -c -)   # refuse a tampered download
tar -xzf "$tmp/$tarball" -C "$tmp" gitleaks
install -m 0755 "$tmp/gitleaks" "$BIN/gitleaks"
"$BIN/gitleaks" version

echo "== pre-commit"
if ! command -v pre-commit >/dev/null; then
  sudo apt-get install -y pre-commit
fi
pre-commit --version

case ":$PATH:" in *":$BIN:"*) ;; *) echo "NOTE: add $BIN to your PATH:  echo 'export PATH=\$HOME/.local/bin:\$PATH' >> ~/.bashrc && source ~/.bashrc";; esac
