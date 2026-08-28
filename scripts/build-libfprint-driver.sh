#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_dir=${LIBFPRINT_SOURCE:-/tmp/libfprint-v1.94.10}
work_dir="$repo_dir/.tools/libfprint-goodix5503"

if [[ ! -f "$source_dir/libfprint/meson.build" ]]; then
  printf 'Set LIBFPRINT_SOURCE to a libfprint v1.94.10 checkout\n' >&2
  exit 1
fi
rm -rf -- "$work_dir"
mkdir -p -- "$work_dir"
cp -a --reflink=auto "$source_dir/." "$work_dir/source"
cp -- "$repo_dir/libfprint/drivers/goodix5503.c" \
      "$repo_dir/libfprint/drivers/goodix5503-proto.c" \
      "$repo_dir/libfprint/drivers/goodix5503-proto.h" \
      "$repo_dir/libfprint/drivers/goodix5503-config.c" \
      "$repo_dir/libfprint/drivers/goodix5503-config.h" \
      "$repo_dir/libfprint/drivers/goodix5503-security.c" \
      "$repo_dir/libfprint/drivers/goodix5503-security.h" \
      "$repo_dir/libfprint/drivers/goodix5503-image.c" \
      "$repo_dir/libfprint/drivers/goodix5503-image.h" \
      "$repo_dir/libfprint/drivers/goodix5503-tls.c" \
      "$repo_dir/libfprint/drivers/goodix5503-tls.h" \
      "$work_dir/source/libfprint/drivers/"

python - "$work_dir/source" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
top = source / "meson.build"
text = top.read_text()
old = "all_drivers = default_drivers + virtual_drivers\n"
new = "all_drivers = default_drivers + virtual_drivers + [ 'goodix5503' ]\n"
if text.count(old) != 1:
    raise SystemExit("unexpected top-level driver list")
top.write_text(text.replace(old, new))

text = top.read_text()
old = "    'uru4000' : [ 'openssl' ],\n"
new = old + "    'goodix5503' : [ 'openssl' ],\n"
if text.count(old) != 1:
    raise SystemExit("unexpected driver helper map")
top.write_text(text.replace(old, new))

lib = source / "libfprint/meson.build"
text = lib.read_text()
old = "    'goodixmoc' :\n        [ 'drivers/goodixmoc/goodix.c', 'drivers/goodixmoc/goodix_proto.c' ],\n"
new = "    'goodix5503' :\n        [ 'drivers/goodix5503.c', 'drivers/goodix5503-proto.c',\n          'drivers/goodix5503-config.c', 'drivers/goodix5503-security.c',\n          'drivers/goodix5503-image.c', 'drivers/goodix5503-tls.c' ],\n" + old
if text.count(old) != 1:
    raise SystemExit("unexpected libfprint driver source map")
lib.write_text(text.replace(old, new))
PY

meson setup "$work_dir/build" "$work_dir/source" \
  -Ddrivers=goodix5503 \
  -Dintrospection=false \
  -Ddoc=false \
  -Dudev_rules=disabled \
  -Dudev_hwdb=disabled
ninja -C "$work_dir/build" \
  libfprint/libfprint-2.so.2.0.0 \
  examples/enroll examples/verify examples/img-capture
printf 'Built development driver in %s\n' "$work_dir/build"
