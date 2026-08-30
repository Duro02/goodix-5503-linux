#!/usr/bin/env bash
# root 窗口内执行:安装 -14 包,前台跑 debug 版 fprintd,连续验证 3 次。
set -uo pipefail

repo=/home/duro/Projects/goodix-5503-linux
package=$repo/.tools/packages/libfprint-goodix5503-1.94.100-14-x86_64.pkg.tar.zst
log=$repo/.tools/logs/fprintd-debug-$(date +%Y%m%d-%H%M%S).log

echo "════════ 中文步骤说明 ════════" | tee "$log"
echo "1. 脚本会先安装新包并停掉系统 fprintd,再手动启动调试版 fprintd" | tee -a "$log"
echo "2. 之后自动进行 3 次验证:每次提示后,把【之前录入的手指】按上" | tee -a "$log"
echo "   传感器,保持 1 秒左右再移开;每次最多等 25 秒" | tee -a "$log"
echo "3. 3 次结束后脚本会自动收尾,按回车关闭窗口" | tee -a "$log"
echo | tee -a "$log"

pacman -U --noconfirm -- "$package" 2>&1 | tee -a "$log"
systemctl stop fprintd.service 2>/dev/null || true
sleep 0.5

echo "—— 启动调试版 fprintd(前台)——" | tee -a "$log"
G_MESSAGES_DEBUG=all /usr/lib/fprintd 2>&1 | tee -a "$log" &
FP_PID=$!
sleep 1.5

echo "存储的指纹文件(大小可判断模板是否完整):" | tee -a "$log"
ls -la /var/lib/fprint/duro/goodix5503/*/ 2>&1 | tee -a "$log"
echo | tee -a "$log"

for i in 1 2 3; do
  echo "════ 第 $i/3 次验证:请按上【录入过的】手指 ════" | tee -a "$log"
  timeout 25 fprintd-verify duro 2>&1 | tee -a "$log"
  echo "(fprintd-verify 退出码 $?,上一次结果见上一行)" | tee -a "$log"
  sleep 1
done

echo "—— 验证结束,关闭调试 fprintd ——" | tee -a "$log"
kill "$FP_PID" 2>/dev/null
wait "$FP_PID" 2>/dev/null
systemctl start fprintd.service 2>/dev/null || true
chown 1000:1000 "$log" 2>/dev/null || true

{
  echo
  echo "════════ 收尾 ════════"
  echo "日志: $log"
  echo "按回车关闭窗口。"
} | tee -a "$log"
read -r _
