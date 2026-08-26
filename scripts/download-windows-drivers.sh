#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out="$project_dir/artifacts/windows-driver"
mkdir -p "$out"

curl -fL --retry 3 \
  https://download.lenovo.com/consumer/mobiles/74ti05afkkxbyyb0.exe \
  -o "$out/74ti05afkkxbyyb0-win10.exe"
curl -fL --retry 3 \
  https://download.lenovo.com/consumer/mobiles/74ti04afkkxbyyb0.exe \
  -o "$out/74ti04afkkxbyyb0-win11.exe"

cat >"$out/SHA256SUMS" <<'SUMS'
c94d7c866b0fc0be4d62511b780294900eef972f6e8ec9db761b74cfdf1af4ea  74ti05afkkxbyyb0-win10.exe
27b211eee3f973b2e5b70823d6fb7c69394876839ab9e2e9a85f14b8ce1008ee  74ti04afkkxbyyb0-win11.exe
SUMS

cd "$out"
sha256sum -c SHA256SUMS
