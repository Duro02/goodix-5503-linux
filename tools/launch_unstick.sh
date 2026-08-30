#!/usr/bin/env bash
set -euo pipefail
exec pkexec env XDG_RUNTIME_DIR=/run/user/1000 WAYLAND_DISPLAY=wayland-1 HOME=/root \
  /usr/bin/foot --title='解除指纹服务卡死' /usr/bin/bash \
    /home/duro/Projects/goodix-5503-linux/tools/unstick_fprintd.sh
