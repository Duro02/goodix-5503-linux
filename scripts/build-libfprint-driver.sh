#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ -n ${LIBFPRINT_SOURCE:-} ]]; then
  source_dir=$LIBFPRINT_SOURCE
elif [[ -f "$repo_dir/.tools/libfprint-v1.94.10-source/libfprint/meson.build" ]]; then
  source_dir="$repo_dir/.tools/libfprint-v1.94.10-source"
else
  source_dir=/tmp/libfprint-v1.94.10
fi
work_dir="$repo_dir/.tools/libfprint-goodix5503"
pinned_source_commit=0c97a47d8ef405cd577b87058c1e89cae9d242e7
if pkg-config --exists opencv5; then
  opencv_pkg=opencv5
  opencv_features_lib=-lopencv_features
elif pkg-config --exists opencv4; then
  opencv_pkg=opencv4
  opencv_features_lib=-lopencv_features2d
else
  printf 'OpenCV 4 or 5 development files are required\n' >&2
  exit 1
fi
read -r -a opencv_cflags <<< "$(pkg-config --cflags "$opencv_pkg")"
opencv_libs=(-lopencv_core "$opencv_features_lib" -lopencv_flann -lopencv_imgproc)

if [[ ! -f "$source_dir/libfprint/meson.build" ]]; then
  printf 'Set LIBFPRINT_SOURCE to a clean libfprint v1.94.10 checkout\n' >&2
  exit 1
fi
if [[ $(git -C "$source_dir" rev-parse HEAD 2>/dev/null || true) != "$pinned_source_commit" ]] ||
   [[ -n $(git -C "$source_dir" status --porcelain=v1 2>/dev/null || true) ]]; then
  printf 'libfprint source must be the clean pinned v1.94.10 commit %s\n' \
    "$pinned_source_commit" >&2
  exit 1
fi
rm -rf -- "$work_dir"
mkdir -p -- "$work_dir"
cp -a --reflink=auto "$source_dir/." "$work_dir/source"
cp -a -- "$repo_dir/libfprint/sigfm" "$work_dir/source/libfprint/"
patch -d "$work_dir/source" -p1 --forward --batch \
  < "$repo_dir/libfprint/patches/sigfm-core-v1.94.10.patch"
cp -- "$repo_dir/libfprint/tests/test-goodix5503-sigfm-core.cpp" \
      "$repo_dir/libfprint/tests/test-goodix5503-sigfm-detection.c" \
      "$repo_dir/libfprint/tests/test-goodix5503-sigfm-gallery.cpp" \
      "$work_dir/source/tests/"
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
  examples/enroll examples/verify examples/img-capture \
  tests/test-goodix5503-sigfm-core \
  tests/test-goodix5503-sigfm-detection \
  tests/test-goodix5503-sigfm-gallery
meson test -C "$work_dir/build" --print-errorlogs \
  goodix5503-sigfm-core goodix5503-sigfm-detection \
  goodix5503-sigfm-gallery

cc -std=c11 -Wall -Wextra -Werror -O2 \
  -I"$work_dir/build/libfprint" \
  -I"$work_dir/source/libfprint" \
  $(pkg-config --cflags libfprint-2 gusb) \
  "$repo_dir/tools/goodix5503_libfprint_smoke.c" \
  -L"$work_dir/build/libfprint" \
  -Wl,-rpath,"$work_dir/build/libfprint" \
  -o "$repo_dir/.tools/goodix5503-libfprint-smoke" \
  $(pkg-config --libs libfprint-2)

sigfm_object="$repo_dir/.tools/.goodix5503-sigfm.o"
sensitive_variant_object="$repo_dir/.tools/.goodix5503-sensitive-variant.o"
sigfm_test="$repo_dir/.tools/.goodix5503-sigfm-test"
sigfm_core_test="$repo_dir/.tools/.goodix5503-sigfm-core-test"
sensitive_test="$repo_dir/.tools/.goodix5503-sensitive-test"
c++ -std=c++17 -Wall -Wextra -Werror -O2 \
  -I"$repo_dir/libfprint/sigfm" \
  "${opencv_cflags[@]}" \
  -c "$repo_dir/libfprint/sigfm/sigfm.cpp" -o "$sigfm_object"
c++ -std=c++17 -Wall -Wextra -Werror -O2 \
  -I"$repo_dir/libfprint/sigfm" \
  "${opencv_cflags[@]}" \
  "$repo_dir/libfprint/tests/test-goodix5503-sigfm.cpp" "$sigfm_object" \
  -o "$sigfm_test" \
  "${opencv_libs[@]}"
"$sigfm_test"
cc -std=c11 -Wall -Wextra -Werror -O2 \
  -I"$work_dir/source/libfprint" \
  $(pkg-config --cflags glib-2.0) \
  -c "$work_dir/source/libfprint/fpi-sensitive-data.c" \
  -o "$sensitive_variant_object"
c++ -std=c++17 -Wall -Wextra -Werror -O2 \
  -I"$work_dir/build/libfprint" \
  -I"$work_dir/source/libfprint" \
  -I"$work_dir/source/libfprint/nbis/include" \
  -I"$work_dir/source/libfprint/nbis/libfprint-include" \
  -I"$repo_dir/libfprint/sigfm" \
  $(pkg-config --cflags libfprint-2 glib-2.0) \
  "${opencv_cflags[@]}" \
  "$repo_dir/libfprint/tests/test-goodix5503-sigfm-core.cpp" \
  "$sensitive_variant_object" \
  -L"$work_dir/build/libfprint" \
  -Wl,-rpath,"$work_dir/build/libfprint" \
  -o "$sigfm_core_test" \
  $(pkg-config --libs libfprint-2 glib-2.0) \
  "${opencv_libs[@]}"
"$sigfm_core_test"
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address -O1 \
  -I"$work_dir/source/libfprint" \
  -I"$repo_dir/tools" \
  $(pkg-config --cflags glib-2.0) \
  "$repo_dir/tools/goodix5503_sensitive.c" \
  "$repo_dir/libfprint/tests/test-goodix5503-sensitive.c" \
  -o "$sensitive_test" $(pkg-config --libs glib-2.0)
ASAN_OPTIONS=detect_leaks=1 "$sensitive_test"
rm -f "$sigfm_object" "$sensitive_variant_object" "$sigfm_test" \
  "$sigfm_core_test" "$sensitive_test"
printf 'Built development driver in %s\n' "$work_dir/build"
