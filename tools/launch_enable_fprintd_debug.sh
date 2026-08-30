#!/usr/bin/env bash
set -euo pipefail
exec pkexec env XDG_RUNTIME_DIR=/run/user/1000 WAYLAND_DISPLAY=wayland-1 HOME=/root \
  /usr/bin/foot --title='开启指纹调试' /usr/bin/bash \
    /home/duro/Projects/goodix-5503-linux/tools/enable_fprintd_debug.sh
