#!/bin/bash
set -e

REPO="Ehsan-U/goproxy"
INSTALL_DIR="$HOME/.local/bin"
BINARY="goproxy"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *) echo "unsupported architecture: $ARCH"; exit 1 ;;
esac

TAG=$(curl -sL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
if [ -z "$TAG" ]; then
    echo "failed to fetch latest release"
    exit 1
fi

URL="https://github.com/$REPO/releases/download/$TAG/goproxy-linux-$ARCH"
echo "downloading $BINARY $TAG (linux/$ARCH)..."

mkdir -p "$INSTALL_DIR"
curl -sL "$URL" -o "$INSTALL_DIR/$BINARY"
chmod +x "$INSTALL_DIR/$BINARY"

echo "installed to $INSTALL_DIR/$BINARY"

if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo "note: add $INSTALL_DIR to your PATH"
fi
