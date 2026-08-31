#!/usr/bin/env bash
# fprintd 调试输出重定向到文件(journald 限流会丢行,文件不会)。
set -uo pipefail
mkdir -p /etc/systemd/system/fprintd.service.d
cat > /etc/systemd/system/fprintd.service.d/debug.conf <<'UNIT'
[Service]
Environment=G_MESSAGES_DEBUG=all
StandardOutput=append:/var/log/fprintd-debug.log
StandardError=append:/var/log/fprintd-debug.log
UNIT
systemctl daemon-reload
systemctl restart fprintd.service
sleep 1
echo "fprintd: $(systemctl is-active fprintd.service), 日志: /var/log/fprintd-debug.log"
read -r _
