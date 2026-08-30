#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 ]]; then
  printf 'usage: %s PACKAGE SOURCE_DATE_EPOCH\n' "$0" >&2
  exit 2
fi
package=$1
epoch=$2
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

python - "$package" <<'PY'
from pathlib import PurePosixPath
import stat
import sys
import tarfile

package = sys.argv[1]
expected_links = {
    "usr/lib/libfprint-2.so": "libfprint-2.so.2",
    "usr/lib/libfprint-2.so.2": "libfprint-2.so.2.0.0",
}
seen = set()
links = {}
with tarfile.open(package, "r:*") as archive:
    for member in archive:
        name = member.name
        path = PurePosixPath(name)
        canonical = path.as_posix()
        if name != canonical:
            raise SystemExit(f"noncanonical archive path: {name}")
        if canonical in seen:
            raise SystemExit(f"duplicate archive path: {name}")
        seen.add(canonical)
        if (path.is_absolute() or ".." in path.parts or
            not (name in {".BUILDINFO", ".MTREE", ".PKGINFO", "usr", "usr/"}
                 or name.startswith("usr/"))):
            raise SystemExit(f"unsafe or unexpected package path: {name}")
        if member.uid != 0 or member.gid != 0:
            raise SystemExit(f"non-root archive owner: {name}")
        mode = stat.S_IMODE(member.mode)
        if member.isdir():
            if mode != 0o755:
                raise SystemExit(f"bad directory mode: {name}")
        elif member.issym():
            if mode != 0o777:
                raise SystemExit(f"bad symlink mode: {name}")
            if expected_links.get(name) != member.linkname:
                raise SystemExit(f"unsafe or unexpected symlink: {name}")
            links[name] = member.linkname
        elif member.isreg():
            if mode not in {0o644, 0o755}:
                raise SystemExit(f"bad file mode: {name}")
        else:
            raise SystemExit(f"unsafe archive entry type: {name}")
        if member.pax_headers:
            raise SystemExit(f"unexpected extended archive metadata: {name}")
if links != expected_links:
    raise SystemExit("required library symlinks are missing or duplicated")
PY

bsdtar -xOf "$package" .MTREE | gzip -dc > "$tmp/mtree"
if grep -Eiq '(^|[[:space:]])(capability|capabilities|xattr|flags)=' "$tmp/mtree"; then
  printf 'package mtree contains capabilities, xattrs, or file flags\n' >&2
  exit 1
fi

bsdtar -xf "$package" -C "$tmp"
if command -v getcap >/dev/null && [[ -n $(getcap -r "$tmp/usr" 2>/dev/null) ]]; then
  printf 'package payload contains file capabilities\n' >&2
  exit 1
fi

pkginfo=$tmp/.PKGINFO
buildinfo=$tmp/.BUILDINFO
hwdb=$tmp/usr/lib/udev/hwdb.d/60-autosuspend-libfprint-2.hwdb
library=$tmp/usr/lib/libfprint-2.so.2.0.0
grep -qx 'pkgname = libfprint-goodix5503' "$pkginfo"
grep -qx 'pkgver = 1.94.100-14' "$pkginfo"
grep -qx 'provides = libfprint=1.94.100' "$pkginfo"
grep -qx 'provides = libfprint-2.so=2-64' "$pkginfo"
grep -qx "builddate = $epoch" "$pkginfo"
grep -qx "builddate = $epoch" "$buildinfo"

python - "$hwdb" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
marker = '# Supported by libfprint driver goodix5503\n'
entry = marker + 'usb:v27C6p5503*\n ID_AUTOSUSPEND=1\n ID_PERSIST=0\n'
assert text.count(marker) == 1
assert text.count('usb:v27C6p5503*') == 1
assert entry in text
parts = text.split('# Known unsupported devices', 1)
assert len(parts) == 2 and 'usb:v27C6p5503*' not in parts[1]
PY

readelf -d "$library" > "$tmp/dynamic"
grep -q 'SONAME.*libfprint-2.so.2' "$tmp/dynamic"
if grep -Eq 'RPATH|RUNPATH' "$tmp/dynamic"; then
  printf 'installed library contains RPATH/RUNPATH\n' >&2
  exit 1
fi
needed=$(sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' "$tmp/dynamic")
# GNU ld may elide the direct flann NEEDED entry with --as-needed because the
# features module owns that dependency; require the modules directly used here.
for dependency in libopencv_core.so.500 libopencv_features.so.500 libopencv_imgproc.so.500; do
  grep -qx "$dependency" <<< "$needed"
done
if grep -Eq 'opencv_(world|dnn|highgui|video|videoio|calib3d|objdetect)|vtk|hdf' <<< "$needed"; then
  printf 'unexpected direct image/ML dependency\n' >&2
  exit 1
fi
if nm -D --defined-only "$library" | grep -Eiq 'sigfm|goodix5503'; then
  printf 'private Goodix/SIGFM symbol exported from public library\n' >&2
  exit 1
fi
ldd -r "$library" > "$tmp/ldd"
if grep -q 'not found' "$tmp/ldd"; then
  cat "$tmp/ldd" >&2
  exit 1
fi

printf 'ARCHIVE AUDIT PASSED\n'
printf 'Direct dependencies:\n%s\n' "$needed"
