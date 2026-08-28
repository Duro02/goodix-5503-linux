#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
proto_binary=$(mktemp --tmpdir goodix5503-proto-test.XXXXXX)
tls_binary=$(mktemp --tmpdir goodix5503-tls-test.XXXXXX)
config_binary=$(mktemp --tmpdir goodix5503-config-test.XXXXXX)
trap 'rm -f -- "$proto_binary" "$tls_binary" "$config_binary"' EXIT

cc -std=c11 -Wall -Wextra -Werror -O2 \
  -I"$repo_dir/libfprint/drivers" \
  "$repo_dir/libfprint/drivers/goodix5503-proto.c" \
  "$repo_dir/libfprint/tests/test-goodix5503-proto.c" \
  -o "$proto_binary" \
  $(pkg-config --cflags --libs glib-2.0)
"$proto_binary"

cc -std=c11 -Wall -Wextra -Werror -O2 \
  -I"$repo_dir/libfprint/drivers" \
  "$repo_dir/libfprint/drivers/goodix5503-tls.c" \
  "$repo_dir/libfprint/tests/test-goodix5503-tls.c" \
  -o "$tls_binary" \
  $(pkg-config --cflags --libs glib-2.0 openssl)
"$tls_binary"

cc -std=c11 -Wall -Wextra -Werror -O2 \
  -I"$repo_dir/libfprint/drivers" \
  "$repo_dir/libfprint/drivers/goodix5503-config.c" \
  "$repo_dir/libfprint/tests/test-goodix5503-config.c" \
  -o "$config_binary" \
  $(pkg-config --cflags --libs glib-2.0)
"$config_binary"
