#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
artifact_dir="$project_dir/artifacts/windows-driver"
extractor=${INNOEXTRACT:-innoextract}

if ! command -v "$extractor" >/dev/null 2>&1 && [[ ! -x "$extractor" ]]; then
  local_extractor="$project_dir/.tools/innoextract/usr/bin/innoextract"
  if [[ -x "$local_extractor" ]]; then
    extractor=$local_extractor
  else
    printf 'innoextract not found; set INNOEXTRACT or install it locally\n' >&2
    exit 1
  fi
fi

cd "$artifact_dir"
sha256sum -c SHA256SUMS

rm -rf extracted/win10 extracted/win11
mkdir -p extracted/win10 extracted/win11
"$extractor" --extract --silent --output-dir extracted/win10 \
  74ti05afkkxbyyb0-win10.exe
"$extractor" --extract --silent --output-dir extracted/win11 \
  74ti04afkkxbyyb0-win11.exe

printf 'Extracted official drivers under %s/extracted\n' "$artifact_dir"
