#!/usr/bin/env bash
set -euo pipefail

echo "Use tools/update/avorax-build-update-package.ps1 on Windows build hosts."
echo "The package builder requires AVORAX_UPDATE_SIGNER and refuses unsigned .aup packages."
exit 1
