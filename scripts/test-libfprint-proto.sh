#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
binary=$(mktemp --tmpdir goodix5503-proto-test.XXXXXX)
trap 'rm -f -- "$binary"' EXIT

cc -std=c11 -Wall -Wextra -Werror -O2 \
  -I"$repo_dir/libfprint/drivers" \
  "$repo_dir/libfprint/drivers/goodix5503-proto.c" \
  "$repo_dir/libfprint/tests/test-goodix5503-proto.c" \
  -o "$binary" \
  $(pkg-config --cflags --libs glib-2.0)
"$binary"
