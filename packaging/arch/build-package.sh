#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
build_root="$repo_dir/.tools/arch-package-build"
pkgdest="$repo_dir/.tools/packages"
source_date_epoch=1785018985
package_glob='libfprint-goodix5503-1.94.100-17-x86_64.pkg.tar.zst'

"$repo_dir/scripts/test-libfprint-proto.sh"

rm -rf -- "$build_root"
mkdir -p -- "$build_root/common" "$pkgdest"
overlay="$build_root/common/goodix5503-overlay.tar"
mkdir -p -- "$build_root/common/overlay"
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
  -cf "$build_root/common/overlay-input.tar" -C "$repo_dir" \
  libfprint/patches/sigfm-core-v1.94.100.patch \
  libfprint/sigfm \
  libfprint/drivers/goodix5503.c \
  libfprint/drivers/goodix5503-proto.c \
  libfprint/drivers/goodix5503-proto.h \
  libfprint/drivers/goodix5503-config.c \
  libfprint/drivers/goodix5503-config.h \
  libfprint/drivers/goodix5503-security.c \
  libfprint/drivers/goodix5503-security.h \
  libfprint/drivers/goodix5503-image.c \
  libfprint/drivers/goodix5503-image.h \
  libfprint/drivers/goodix5503-tls.c \
  libfprint/drivers/goodix5503-tls.h \
  libfprint/tests/test-goodix5503-sigfm-core.cpp \
  libfprint/tests/test-goodix5503-sigfm-detection.c \
  libfprint/tests/test-goodix5503-sigfm-gallery.cpp
tar -xf "$build_root/common/overlay-input.tar" -C "$build_root/common/overlay"
rm -f -- "$build_root/common/overlay-input.tar"
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
  -cf "$overlay" -C "$build_root/common" overlay
overlay_sha=$(sha256sum "$overlay" | cut -d' ' -f1)

build_once() {
  local label=$1
  local stage="$build_root/run"

  rm -rf -- "$stage"
  mkdir -p -- "$stage/out" "$build_root/results"
  cp -- "$repo_dir/packaging/arch/PKGBUILD" "$stage/PKGBUILD"
  cp -- "$overlay" "$stage/goodix5503-overlay.tar"
  sed -i "s/OVERLAY_SHA256/$overlay_sha/" "$stage/PKGBUILD"
  cp -- /etc/makepkg.conf "$stage/makepkg.conf"
  printf '\nSOURCE_DATE_EPOCH=%s\n' "$source_date_epoch" >> "$stage/makepkg.conf"
  (
    cd "$stage"
    SOURCE_DATE_EPOCH=$source_date_epoch \
    SRCDEST="$build_root/sources" PKGDEST="$stage/out" \
      makepkg --config "$stage/makepkg.conf" \
              --cleanbuild --clean --force --noconfirm
  )
  local package="$stage/out/$package_glob"
  [[ -f $package ]]
  "$repo_dir/packaging/arch/audit-package.sh" "$package" "$source_date_epoch"
  cp -- "$package" "$build_root/results/$label.pkg.tar.zst"
  sha256sum "$package" > "$build_root/results/$label.sha256"
}

build_once first
build_once second
first_hash=$(cut -d' ' -f1 < "$build_root/results/first.sha256")
second_hash=$(cut -d' ' -f1 < "$build_root/results/second.sha256")
if [[ $first_hash != "$second_hash" ]]; then
  printf 'package reproducibility failure: %s != %s\n' \
    "$first_hash" "$second_hash" >&2
  exit 1
fi

rm -f -- "$pkgdest"/libfprint-goodix5503-*.pkg.tar.*
cp -- "$build_root/results/second.pkg.tar.zst" "$pkgdest/$package_glob"
"$repo_dir/packaging/arch/audit-package.sh" \
  "$pkgdest/$package_glob" "$source_date_epoch"
"$repo_dir/packaging/arch/test-audit-package.sh" \
  "$pkgdest/$package_glob" "$source_date_epoch"

installed_helper="$repo_dir/.tools/goodix5503-installed-lib-validate"
cc -std=c11 -Wall -Wextra -Werror -O2 \
  -DGOODIX5503_REQUIRE_INSTALLED_LIBFPRINT \
  $(pkg-config --cflags libfprint-2 gusb) \
  "$repo_dir/tools/goodix5503_libfprint_smoke.c" \
  -o "$installed_helper" \
  $(pkg-config --libs libfprint-2) -ldl
if readelf -d "$installed_helper" | grep -Eq 'RPATH|RUNPATH'; then
  printf 'installed-library validator contains RPATH/RUNPATH\n' >&2
  exit 1
fi
ldd "$installed_helper" | grep -Eq \
  'libfprint-2\.so\.2 => /usr/lib/libfprint-2\.so\.2 '
"$installed_helper" --check-installed-library

printf 'REPRODUCIBLE PACKAGE SHA-256: %s\n' "$second_hash"
printf 'Package artifact: %s\n' "$pkgdest/$package_glob"
printf 'Installed-library validator: %s\n' "$installed_helper"
