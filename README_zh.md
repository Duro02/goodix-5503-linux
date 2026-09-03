# goodix-5503-linux

[English](README.md)

在 Linux 上使用联想/惠普等笔记本常见的 Goodix `27c6:5503` 指纹传感器的驱动。这个仓库最初是逆向工程项目，现在驱动已经完成，并在开发者自己的机器上安装、日常使用。

## 功能

- **按下即识别**：开机或挂起后的第一次认证需要几秒校准，之后只要电脑不重启，每次解锁都是即时的（约 100 毫秒完成准备，手指按下后 60 毫秒内出图）。
- **录入引导**：默认需要 24 次有效按压，建议每次换位置和角度；过于重复或质量太差的按压不会计数，需要重按；最后一次录完，要抬起手指才提示完成。
- **安全**：指纹图像只在本机处理，模板存在本机；没有发现过用其他手指误识别的情况（测试次数有限，见下文"限制"）。

## 限制

- **识别率**：同一根手指并不是每次都能一次通过——实测约一半的概率需要按第二次，重按基本都能过。失败的原因是按压变形（力度、角度）超出匹配算法的容差，属于算法参数问题，记录在 `docs/libfprint-driver-plan.md`。
- **只支持这一种设备组合**：传感器 `27c6:5503`、固件 `GF3258_RTSEC_APP_10063`、IAP `MILAN_RTSEC_IAP_10027`。其他固件或 IAP 版本不支持。
- **不刷固件、运行时不改 PSK**：日常驱动与 probe 只读配对状态。只有用户显式运行 `goodix-5503-setup` 并确认 Windows 指纹配对会失效时，setup 才会执行一次固定 PSK 配对写入和立即回读校验。

## 安装

前提是系统已经有可用的 `fprintd`/PAM 环境。在 Arch 上先安装构建与 setup 依赖，再构建定制 libfprint：

```bash
sudo pacman -S --needed base-devel git meson ninja gobject-introspection \
  cairo opencv libgudev libgusb openssl pixman python python-pip curl innoextract
bash packaging/arch/build-package.sh
sudo pacman -U --noconfirm --overwrite "*" .tools/packages/libfprint-goodix5503-*.pkg.tar.zst
```

安装包会同时部署 fprintd 常驻/no-core drop-in、挂起恢复重启 hook，并提供可选的登录预热 user service；不会静默生成或写入 PSK。

### PSK 配对（首次使用必须检查）

主机和传感器必须持有同一个 32 字节 PSK，否则驱动无法建立 TLS，单独安装 libfprint 包没有用。setup 会先只读检查 `/var/lib/fprint/goodix5503/psk.bin` 与设备状态：已经匹配时不写任何内容；不匹配时会明确警告原 Windows 指纹配对将失效，并要求用户输入确认后才生成随机 PSK、备份可读旧记录、执行一次固定写入、立即回读验证并原子安装 root-owned `0600` 主机密钥。

先安装 setup 工具并执行一次检查。必须以桌面用户运行，不要在命令前加 `sudo`；程序只会对几个固定 helper 调用 sudo：

```bash
python -m venv .venv
.venv/bin/pip install -e '.[whitebox]'
.venv/bin/goodix-5503-setup
```

如果显示 `already-paired-no-write`，说明现有 PSK 可以直接使用，不需要执行其他配对命令。如果提示缺少固定版本的官方编码器，则执行：

```bash
bash scripts/download-windows-drivers.sh
bash scripts/extract-windows-drivers.sh
.venv/bin/goodix-5503-setup
```

全新 Linux 安装通常没有主机 PSK，因此一般会走第二种流程。setup 会警告 Windows 指纹配对将失效，并要求输入指定文字；没有确认就不会生成密钥、备份或写入传感器。

PSK 写入不是包安装脚本的一部分，不会在升级时重复执行。写入结果不明确时不会自动重试。保留 `artifacts/device-backup/` 下仅用户可读的文件并重新运行 setup；它会保留原始备份、验证准备好的密钥，并先判断传感器是否已经提交该密钥。

## 使用

录入指纹：

```bash
sudo fprintd-enroll $USER
```

之后系统锁屏（SDDM/omarchy/GNOME 等）在 PAM 里配了 fprintd 的都可以用指纹解锁。为了让驱动在多次解锁之间保持"热"状态（即点即用），fprintd 需要常驻。Arch 包已经把 `--no-timeout` drop-in 安装到 `/usr/lib/systemd/system/fprintd.service.d/`；从源码手工部署时见 `packaging/systemd/README.md`。

## 安全与探测


探测器只允许以下命令：

- `NOP`：唤醒/同步设备；
- `FIRMWARE_VERSION`：读取应用固件版本；
- `GET_IAP_VERSION`：读取 IAP 版本；
- `PRESET_PSK_READ`：可选，只读取官方 R-family 的 `0xbb020007` 校验记录和 `0xbb010002` DPAPI 记录。`0xbb010003` 是已由历史硬件试验证明不可读的 MCU 白盒写入输入，当前备份命令不会再次读取它。检查模式只报告元数据；显式备份模式保存不透明原始记录，但绝不把记录内容或明文密钥输出到终端。

默认 probe CLI 仍会阻止固件、PSK、配置、reset、寄存器写入和图像采集。仓库内另有边界固定的配对与实验性 runtime 模块；它们不通过 probe CLI 暴露通用 raw-command 接口。固件/IAP 与任意 protected-record 写入仍属于禁止或单独审批的持久操作。

“非持久性”不代表完全没有风险：probe 仍会向 USB 设备发送查询命令。固件异常时，设备可能暂时无响应，需要重启或彻底关机后恢复。probe 不会修改 Flash、PSK 或 IAP；只有单独确认的 setup 流程能执行一次有界 PSK 写入。

## 探测硬件


以下命令只使用 probe 的固定只读命令集：

```bash
sudo .venv/bin/goodix-5503-probe
sudo .venv/bin/goodix-5503-probe --check-psk-state
sudo .venv/bin/goodix-5503-probe --inspect-protected-record
sudo .venv/bin/goodix-5503-probe --backup-protected-record
sudo .venv/bin/goodix-5503-probe --backup-rollback-set
```

默认不会查询任何 PSK 状态。受保护记录操作会先设置并验证 `PR_SET_DUMPABLE=0`，同时设置 `RLIMIT_CORE=0`；任一步失败都会在 USB 访问前终止。检查模式只输出长度和 SHA-256。备份模式读取完成后会先关闭 USB 会话，再永久放弃 sudo root 权限；降权后会重新设置并验证 non-dumpable 状态，随后才以原用户身份执行文件系统操作。root 身份的文件写入会被拒绝。记录通过 `0600` 临时文件、`fsync` 和排他硬链接提交，已有文件只允许逐字节验证一致，绝不会覆盖。可读备份包含 `0xbb010002` 和 `0xbb020007`。硬件实测表明 `0xbb010003` 对读取返回状态 `0x01`；它是写入时由 MCU 消费的白盒配对输入，无法备份。备份目录权限为 `0700` 且已被 Git 忽略，所有可变内存副本在使用后覆盖。这意味着重配后可以验证旧状态，但不能完整恢复原 PSK。

## systemd 部署配件

仓库附带 systemd 配置（`packaging/systemd/`）：fprintd 常驻、禁止 core dump、唤醒自动重启（修复挂起恢复后的认领竞态，对应上游 libfprint #731）和可选登录预热。Arch 包自动安装前三项与预热 unit 文件，但不会替用户启用 user service。调试日志、指纹图像 dump 和实验性质量门不会默认安装。手工部署说明见 `packaging/systemd/README.md`。

## 开发

- `src/goodix5503/`：只读 probe，以及需要明确确认的 PSK 配对 setup 工具
- `libfprint/`：C 驱动源码、SIGFM 匹配算法、针对 libfprint 的 patch
- 测试（不需要硬件）：`PYTHONPATH=src python -m unittest discover -s tests -v`

匹配参数与模板格式是版本化的：任何改动特征提取、匹配语义或判定阈值的修改都必须同步 bump 模板格式版本，否则旧模板会被拒绝加载。具体约束见 `docs/libfprint-driver-plan.md`。

## 上游参考与许可

这个项目站在以下开源工作的肩膀上：

- [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint)（LGPL-2.1-or-later）：驱动框架、状态机、录入/验证流程。构建时固定在其上游提交 `80a4b5ec...`，本仓库不包含 libfprint 代码。
- [goodix-fp-linux-dev/goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump)（[MIT](https://github.com/goodix-fp-linux-dev/goodix-fp-dump/blob/master/LICENSE)，参考提交 `cc43bb3b`、`718ee3c1`）：5503 协议帧格式（`0xa0` 外框、校验和、命令集），只参考接口，不复制其代码。
- [goodix-fp-linux-dev/libfprint SIGFM 分支](https://github.com/goodix-fp-linux-dev/libfprint/tree/0x00002a/libfprint-sigfm)（LGPL-2.1-or-later，参考提交 `7ebe0c80`）：SIFT + CLAHE + mutual/geometric matching 在 libfprint 里的接线方式；`sigfm.cpp/hpp` 保留了上游原始版权头（2022 年三位作者），随本仓库以 LGPL 分发。
- [AndyHazz/goodix53x5-libfprint](https://github.com/AndyHazz/goodix53x5-libfprint)（参考提交 `309d4c69`）：该仓库**没有 LICENSE 文件**，我们只参考了它把 SIGFM 用于 Goodix 传感器的集成思路，没有复制它的任何代码；本项目自有的驱动、协议、TLS、配置和持久格式都是独立实现的。

本项目采用 `LGPL-2.1-or-later`。Windows 官方驱动二进制、设备凭据（PSK/备份/模板）和本机指纹图像不随仓库分发。