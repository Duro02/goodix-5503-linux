# systemd 部署配件

本目录包含 Goodix 5503 的运行时 systemd 配置。它们不负责 PSK 配对，也不会写传感器。

Arch 包 `libfprint-goodix5503` 会自动安装：

- fprintd `--no-timeout` 常驻 drop-in；
- `LimitCORE=0` drop-in；
- suspend/resume 后重启 fprintd 的 system-sleep hook；
- 可选的用户级登录预热 unit（只安装，不自动启用）。

包升级后运行一次 `goodix-5503-setup` 会停止并重新启动 fprintd；若不运行 setup，请手动重启 fprintd 以加载新 drop-in。

## 从源码手工安装安全默认项

不要使用 `*.conf` 通配符：`debug.conf`、`dump.conf` 和 `quality.conf` 不是默认配置。

```bash
sudo install -d -m 0755 /etc/systemd/system/fprintd.service.d
sudo install -m 0644 packaging/systemd/fprintd.service.d/keep-running.conf \
  /etc/systemd/system/fprintd.service.d/20-goodix5503-keep-running.conf
sudo install -m 0644 packaging/systemd/fprintd.service.d/10-goodix-no-core.conf \
  /etc/systemd/system/fprintd.service.d/10-goodix5503-no-core.conf
sudo install -m 0755 packaging/systemd/goodix5503-fprintd-restart.sh \
  /usr/lib/systemd/system-sleep/goodix5503-fprintd-restart
sudo systemctl daemon-reload
sudo systemctl restart fprintd.service
```

## 可选的用户登录预热

预热可把开机后的第一次冷校准提前到登录后后台完成。unit 使用 systemd 的 `%u`，没有硬编码用户名。

```bash
install -d -m 0755 ~/.config/systemd/user
install -m 0644 packaging/systemd/goodix-warmup.service \
  ~/.config/systemd/user/goodix-warmup.service
systemctl --user daemon-reload
systemctl --user enable --now goodix-warmup.service
```

## drop-in 说明

| 文件 | 作用 | 默认安装 |
|---|---|---|
| `keep-running.conf` | `fprintd --no-timeout`，保留 warm TLS/校准状态 | 是 |
| `10-goodix-no-core.conf` | `LimitCORE=0`，避免 PSK、图像和特征进入 core dump | 是 |
| `debug.conf` | fprintd 调试日志与分数输出到 `/var/log/fprintd-debug.log` | 否，仅诊断 |
| `dump.conf` | 将指纹图像写入 `GOODIX5503_DUMP_DIR` | 否，仅诊断 |
| `quality.conf` | 启用实验性录入质量门 | 否，实验性 |

热模型已由驱动设置为禁用（`temp_hot_seconds = -1`），无需 systemd 配置。

## 指纹图像 dump（仅诊断）

`dump.conf` 指向 `/run/goodix-dump`。确需诊断时可创建 tmpfs 目录：

```bash
sudo install -d -m 0755 /usr/lib/tmpfiles.d
printf 'd /run/goodix-dump 0770 root %s -\n' "$USER" | \
  sudo tee /usr/lib/tmpfiles.d/goodix5503.conf
```

指纹图像是敏感数据。只在短时诊断中启用，分析完成后立即删除 dump 和对应 drop-in，并重启 fprintd。
