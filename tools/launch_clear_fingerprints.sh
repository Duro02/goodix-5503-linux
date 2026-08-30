#!/usr/bin/env bash
set -euo pipefail
exec pkexec env \
  XDG_RUNTIME_DIR=/run/user/1000 \
  WAYLAND_DISPLAY=wayland-1 \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
  HOME=/root \
  /usr/bin/foot --title='清空指纹' /usr/bin/bash \
    /home/duro/Projects/goodix-5503-linux/tools/clear_fingerprints.sh
