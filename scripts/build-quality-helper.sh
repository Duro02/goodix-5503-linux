#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
libfprint_source=${LIBFPRINT_SOURCE:-/tmp/libfprint-v1.94.10}
out="$repo_dir/.tools/goodix5503-quality"

if [[ ! -f "$libfprint_source/libfprint/fpi-image.h" ]]; then
  printf 'Set LIBFPRINT_SOURCE to a libfprint v1.94.10 checkout\n' >&2
  exit 1
fi
if [[ $(pkg-config --modversion libfprint-2) != 1.94.100 ]]; then
  printf 'The prototype helper requires system libfprint 1.94.100\n' >&2
  exit 1
fi
mkdir -p -- "$repo_dir/.tools"

cc -std=c11 -Wall -Wextra -Werror -O2 \
  -I"$libfprint_source/libfprint" \
  "$repo_dir/tools/goodix5503_quality.c" \
  -o "$out" \
  $(pkg-config --cflags --libs libfprint-2)
chmod 0755 "$out"
printf 'Built %s\n' "$out"
