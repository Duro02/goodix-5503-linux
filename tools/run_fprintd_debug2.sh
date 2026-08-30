#!/usr/bin/env bash
# root 窗口:固定 tee 目录;取证 fprintd 存储的模板;两次 fprintd-verify 带调试。
set -uo pipefail

repo=/home/duro/Projects/goodix-5503-linux
logdir=$repo/.tools/logs
mkdir -p "$logdir"
log=$logdir/fprintd-debug2-$(date +%Y%m%d-%H%M%S).log

echo "════════ 步骤说明 ════════" | tee "$log"
echo "1. 脚本自动:停系统 fprintd → 启动调试版 → 复制你的模板文件 → 2 次验证" | tee -a "$log"
echo "2. 每次验证提示后,把【录入过的手指】按上约 1 秒再移开" | tee -a "$log"
echo "3. 结束后按回车关闭" | tee -a "$log"
echo | tee -a "$log"

systemctl stop fprintd.service 2>/dev/null || true
sleep 0.5

echo "════ 存储的指纹文件 ════" | tee -a "$log"
find /var/lib/fprint -type f -printf '%p  %s 字节\n' 2>&1 | tee -a "$log"
mkdir -p "$logdir/print-copy"
find /var/lib/fprint -type f -exec cp --preserve=timestamps {} "$logdir/print-copy/" \; 2>&1 | tee -a "$log"
for f in /var/lib/fprint/*/*/*; do
  echo "--- $f 前 16 字节 ---" | tee -a "$log"
  xxd -l 16 "$f" 2>&1 | tee -a "$log"
done
echo | tee -a "$log"

echo "—— 启动调试版 fprintd ——" | tee -a "$log"
G_MESSAGES_DEBUG=all /usr/lib/fprintd >> "$log" 2>&1 &
FP_PID=$!
sleep 1.5

for i in 1 2; do
  echo "════ 第 $i/2 次验证:请按上【录入过的】手指 ════" | tee -a "$log"
  timeout 25 fprintd-verify duro 2>&1 | tee -a "$log"
  echo "(退出码 $?)" | tee -a "$log"
  sleep 1
done

echo "—— 收尾 ———" | tee -a "$log"
kill "$FP_PID" 2>/dev/null
for _ in 1 2 3 4 5; do kill -0 "$FP_PID" 2>/dev/null || break; sleep 0.5; done
kill -9 "$FP_PID" 2>/dev/null
wait "$FP_PID" 2>/dev/null
systemctl start fprintd.service 2>/dev/null || true
chown -R 1000:1000 "$logdir/print-copy" 2>/dev/null || true
chown 1000:1000 "$log" 2>/dev/null || true
echo "完成。按回车关闭窗口。" | tee -a "$log"
read -r _
