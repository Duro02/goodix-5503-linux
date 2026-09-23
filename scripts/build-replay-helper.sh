#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build_dir="$repo_dir/.tools/libfprint-goodix5503"
if [[ ! -f "$build_dir/build/libfprint/libfprint-2.so.2.0.0" ]]; then
  printf 'Build the development driver first with scripts/build-libfprint-driver.sh\n' >&2
  exit 1
fi
if pkg-config --exists opencv5; then
  opencv_pkg=opencv5
  opencv_features=-lopencv_features
else
  opencv_pkg=opencv4
  opencv_features=-lopencv_features2d
fi
c++ -std=c++17 -Wall -Wextra -Werror -O2 \
  -I"$repo_dir/libfprint/sigfm" -I"$repo_dir/libfprint/drivers" \
  -I"$build_dir/source/libfprint" -I"$build_dir/build/libfprint" \
  -I"$build_dir/source/libfprint/nbis/include" \
  -I"$build_dir/source/libfprint/nbis/libfprint-include" \
  $(pkg-config --cflags libfprint-2 "$opencv_pkg" openssl) \
  "$repo_dir/tools/goodix5503_replay.cpp" \
  "$repo_dir/libfprint/sigfm/sigfm.cpp" \
  -L"$build_dir/build/libfprint" -Wl,-rpath,"$build_dir/build/libfprint" \
  -o "$repo_dir/.tools/goodix5503-replay" \
  $(pkg-config --libs libfprint-2 openssl) \
  -lopencv_core "$opencv_features" -lopencv_imgproc -lopencv_flann -lm
printf 'Built %s\n' "$repo_dir/.tools/goodix5503-replay"
