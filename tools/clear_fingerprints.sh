#!/usr/bin/env bash
# 清空当前用户的所有指纹模板,并确认结果。
set -uo pipefail
repo=/home/duro/Projects/goodix-5503-linux
mkdir -p "$repo/.tools/logs"
log=$repo/.tools/logs/clear-$(date +%Y%m%d-%H%M%S).log
exec > >(tee -a "$log") 2>&1
chown 1000:1000 "$log" 2>/dev/null || true

echo "—— 等待 pam 指纹会话释放(2 秒)……"
sleep 2
echo "—— 删除 duro 的全部指纹模板 ——"
fprintd-delete duro
status=$?
echo "(fprintd-delete 退出码 $status)"
echo
echo "—— 剩余指纹列表 ——"
fprintd-list duro
echo
echo "—— /var/lib/fprint/duro 剩余文件 ——"
find /var/lib/fprint/duro -type f -printf '%p  %s 字节\n' 2>/dev/null
echo
echo "完成。现在可以去 omarchy 菜单重新跑『指纹设置』了(启动时输密码,不再要指纹)。"
echo "按回车关闭窗口。"
read -r _
