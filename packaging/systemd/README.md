# systemd 部署配件

这份目录包含让驱动"开箱即用"所需的 systemd 配置。全部是可选的，但**强烈建议安装**，否则会遇到两个已知问题：

1. **挂起恢复后指纹失效**（libfprint 上游 issue #731 同类）：唤醒后 fprintd 的 USB 打开可能卡死，所有解锁都失败。解决方案：唤醒后自动重启 fprintd。
2. **开机后第一次解锁冷启动几秒**：传感器校准只发生在第一次认证时。解决方案：登录后后台预热一次。

## 安装

```bash
# 1) fprintd drop-ins(常驻 + 日志 + 诊断开关)
sudo install -d -m 0755 /etc/systemd/system/fprintd.service.d
sudo install -m 0644 packaging/systemd/fprintd.service.d/*.conf \
  /etc/systemd/system/fprintd.service.d/
sudo systemctl daemon-reload
sudo systemctl restart fprintd.service

# 2) 挂起恢复后自动重启 fprintd(修挂起后卡死)
sudo install -m 0755 packaging/systemd/goodix5503-fprintd-restart.sh \
  /usr/lib/systemd/system-sleep/goodix5503-fprintd-restart

# 3) 用户级预热(登录后后台完成一次冷校准,首次解锁免等)
install -m 0644 packaging/systemd/goodix-warmup.service \
  ~/.config/systemd/user/goodix-warmup.service
systemctl --user daemon-reload
systemctl --user enable --now goodix-warmup.service
```

## drop-in 说明

| 文件 | 作用 | 必需 |
|---|---|---|
| `keep-running.conf` | `fprintd --no-timeout` 常驻，warm 会话跨解锁存活（即点即用） | **必需** |
| `10-goodix-no-core.conf` | `LimitCORE=0`，防核心转储泄露密钥 | 建议 |
| `debug.conf` | fprintd 调试日志与分数输出到 `/var/log/fprintd-debug.log` | 可选（诊断） |
| `dump.conf` | `GOODIX5503_DUMP_DIR=/run/goodix-dump` 指纹图像落盘开关（需配合 tmpfiles 建目录，见下） | 可选（诊断） |
| `quality.conf` | `GOODIX5503_QUALITY_GATE=1` 录入质量门（废图拒绝重按） | 建议 |

诊断类开关（debug/dump）平时可以删掉对应 drop-in 关闭；quality 和 keep-running 建议常开。

## 关于 dump 目录

`dump.conf` 指向 `/run/goodix-dump`（tmpfs，重启即失）。如需每次开机自动重建：

```bash
sudo install -d -m 0755 /usr/lib/tmpfiles.d
printf 'd /run/goodix-dump 0770 root %s -\n' "$USER" | sudo tee /usr/lib/tmpfiles.d/goodix5503.conf
```

指纹图像是敏感数据：`/run/goodix-dump` 权限 0770（仅 root 与当前用户），分析完请删除文件。