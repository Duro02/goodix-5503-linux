#!/usr/bin/env bash
set -euo pipefail
exec pkexec env \
  XDG_RUNTIME_DIR=/run/user/1000 \
  WAYLAND_DISPLAY=wayland-1 \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
  HOME=/root \
  /usr/bin/foot --title='指纹取证2' /usr/bin/bash \
    /home/duro/Projects/goodix-5503-linux/tools/run_fprintd_debug2.sh
