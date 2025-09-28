#!/usr/bin/env bash
set -euo pipefail

# Full installer URL you provided:
INSTALLER_URL="https://raw.githubusercontent.com/Jeykobz/Flawk_Ad_Runner/refs/heads/main/reset_or_install.sh"

TMP="/tmp/flawk-reset-or-install.sh"

# Pick a downloader
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$INSTALLER_URL" -o "$TMP"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TMP" "$INSTALLER_URL"
else
  echo "[flawk] Installing curl..."
  apt-get update -y >/dev/null
  apt-get install -y curl >/dev/null
  curl -fsSL "$INSTALLER_URL" -o "$TMP"
fi

chmod +x "$TMP"
echo "[flawk] Running installer (you’ll be prompted for configuration)…"
sudo bash "$TMP"
