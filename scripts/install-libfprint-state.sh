#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_file="$repo_dir/artifacts/device-backup/new-pairing-psk.bin"
target_dir=/var/lib/fprint/goodix5503
target_file=$target_dir/psk.bin

python - "$source_file" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise SystemExit("prepared PSK has an unsafe owner or type")
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size != 32:
        raise SystemExit("prepared PSK must be a single-link 0600 32-byte file")
finally:
    os.close(fd)
PY

pkexec /usr/bin/env \
  GOODIX_SOURCE="$source_file" \
  GOODIX_UID="$(id -u)" \
  GOODIX_TARGET_DIR="$target_dir" \
  GOODIX_TARGET="$target_file" \
  /usr/bin/bash -c '
set -euo pipefail
umask 077
[[ $EUID -eq 0 ]]
[[ ! -L $GOODIX_SOURCE ]]
[[ $(stat -Lc %u "$GOODIX_SOURCE") == "$GOODIX_UID" ]]
[[ $(stat -Lc %a "$GOODIX_SOURCE") == 600 ]]
[[ $(stat -Lc %s "$GOODIX_SOURCE") == 32 ]]
[[ ! -L $GOODIX_TARGET_DIR ]]
/usr/bin/install -d -m 0700 -o root -g root -- "$GOODIX_TARGET_DIR"
[[ $(stat -Lc %u:%g:%a "$GOODIX_TARGET_DIR") == 0:0:700 ]]
if [[ -e $GOODIX_TARGET || -L $GOODIX_TARGET ]]; then
  [[ ! -L $GOODIX_TARGET ]]
  [[ $(stat -Lc %u:%g:%a:%s "$GOODIX_TARGET") == 0:0:600:32 ]]
  /usr/bin/cmp -s -- "$GOODIX_SOURCE" "$GOODIX_TARGET" || {
    echo "refusing to replace different Goodix host PSK state" >&2
    exit 1
  }
  exit 0
fi
tmp=$GOODIX_TARGET_DIR/.psk.bin.new.$$
trap '\''rm -f -- "$tmp"'\'' EXIT
/usr/bin/install -m 0600 -o root -g root -- "$GOODIX_SOURCE" "$tmp"
/usr/bin/cmp -s -- "$GOODIX_SOURCE" "$tmp"
/usr/bin/mv -n -- "$tmp" "$GOODIX_TARGET"
[[ $(stat -Lc %u:%g:%a:%s "$GOODIX_TARGET") == 0:0:600:32 ]]
/usr/bin/cmp -s -- "$GOODIX_SOURCE" "$GOODIX_TARGET"
'

printf 'Prepared root-owned libfprint host state at %s\n' "$target_file"
