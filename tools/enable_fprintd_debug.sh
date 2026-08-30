#!/usr/bin/env bash
# 打开 fprintd 调试日志(drop-in),之后复现的每次验证都会完整记录到 journal。
set -uo pipefail

repo=/home/duro/Projects/goodix-5503-linux
logdir=$repo/.tools/logs
mkdir -p "$logdir"
log=$logdir/fprintd-dropline-$(date +%Y%m%d-%H%M%S).log
exec > >(tee -a "$log") 2>&1
chown 1000:1000 "$log" 2>/dev/null || true

mkdir -p /etc/systemd/system/fprintd.service.d
cat > /etc/systemd/system/fprintd.service.d/debug.conf <<'EOF'
[Service]
Environment=G_MESSAGES_DEBUG=all
EOF
systemctl daemon-reload
systemctl restart fprintd.service
sleep 1
systemctl is-active fprintd
echo "调试日志已启用。"
echo "现在请测试:1) 锁屏按 2 次  2) 随便开个 sudo 按指纹 2 次"
echo "完成后按回车,我会关闭提示(调试保持开启)。"
read -r _
