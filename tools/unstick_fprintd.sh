#!/usr/bin/env bash
# 解除 fprintd 卡死的设备认领:重启服务即可。
set -uo pipefail
systemctl restart fprintd.service
sleep 1
echo "fprintd 状态: $(systemctl is-active fprintd.service)"
echo "完成,按回车关闭。"
read -r _
