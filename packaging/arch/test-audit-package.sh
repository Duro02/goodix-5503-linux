#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 ]]; then
  printf 'usage: %s PACKAGE SOURCE_DATE_EPOCH\n' "$0" >&2
  exit 2
fi
package=$(realpath -- "$1")
epoch=$2
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

reset_root () {
  rm -rf -- "$tmp/root"
  mkdir "$tmp/root"
  bsdtar -xf "$package" -C "$tmp/root"
}

make_archive () {
  local output=$1
  shift
  bsdtar --uid 0 --gid 0 -cf "$output" -C "$tmp/root" \
    .BUILDINFO .MTREE .PKGINFO usr "$@"
}

expect_rejected () {
  local archive=$1
  local expected=$2
  if "$script_dir/audit-package.sh" "$archive" "$epoch" \
       >"$tmp/audit.out" 2>"$tmp/audit.err"; then
    printf 'unsafe audit fixture was accepted: %s\n' "$expected" >&2
    exit 1
  fi
  grep -q "$expected" "$tmp/audit.err"
}

reset_root
mkfifo "$tmp/root/usr/share/audit-fixture.pipe"
make_archive "$tmp/fifo.tar"
expect_rejected "$tmp/fifo.tar" 'unsafe archive entry type'

for target in /etc/passwd ../libfprint-2.so.2 'libfprint-2.so.2 extra'; do
  reset_root
  rm -- "$tmp/root/usr/lib/libfprint-2.so"
  ln -s "$target" "$tmp/root/usr/lib/libfprint-2.so"
  make_archive "$tmp/bad-link.tar"
  expect_rejected "$tmp/bad-link.tar" 'unsafe or unexpected symlink'
done

reset_root
make_archive "$tmp/duplicate-link.tar" usr/lib/libfprint-2.so
expect_rejected "$tmp/duplicate-link.tar" 'duplicate archive path'

reset_root
ln "$tmp/root/.PKGINFO" "$tmp/root/usr/share/audit-fixture-hardlink"
make_archive "$tmp/hardlink.tar"
expect_rejected "$tmp/hardlink.tar" 'unsafe archive entry type'

python - "$package" "$tmp/path-alias.tar" <<'PY'
from io import BytesIO
import sys
import tarfile

with tarfile.open(sys.argv[1], "r:*") as source, \
     tarfile.open(sys.argv[2], "w") as target:
    for member in source:
        data = source.extractfile(member) if member.isreg() else None
        target.addfile(member, data)
    alias = tarfile.TarInfo("usr/lib/./libfprint-2.so")
    alias.uid = alias.gid = 0
    alias.mode = 0o644
    alias.size = 1
    target.addfile(alias, BytesIO(b"x"))
PY
expect_rejected "$tmp/path-alias.tar" 'noncanonical archive path'

printf 'ARCHIVE NEGATIVE TESTS PASSED\n'
