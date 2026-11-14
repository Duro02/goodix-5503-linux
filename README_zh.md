# goodix-5503-linux

[English](README.md)

在 Linux 上使用联想/惠普等笔记本常见的 Goodix `27c6:5503` 指纹传感器的驱动。驱动基于逆向工程实现，正在开发者自己的机器上日常测试，识别稳定性仍在改进。

## 功能

- **快速采图**：冷激活需要几秒校准；传感器状态保留时，通常约 100 毫秒完成准备、检测到按下后约 55 毫秒出图。失败后快速重试复用已确认的抬指基线和背景，避免重新校准碰上下一次按压；USB 重连仍需重新冷激活。
- **从零录入**：分四组采集 40 次有效按压，选出 24 张模板，再用 8 次新按压检查，至少通过 6 次才完成。检查样本不进入模板；近乎重复的样本不计数，录入质量门默认开启，最后要抬起手指才提示完成。见[首次录入设计与验证](docs/fresh-enrollment-2026-09-22.md)。
- **安全**：指纹图像只在本机处理，模板存在本机；没有发现过用其他手指误识别的情况（测试次数有限，见下文"限制"）。

## 限制

- **识别率**：受控按压与锁屏快速重试的表现可能差很多。1.94.100-41 修复了重试校准缺陷，相同模板的真实锁屏回切对照可重复改善；后续也发现替换模板会损失一部分旧覆盖。仍有按压失败。见[录入对照实验](docs/recognition-experiment-2026-09-22.md)和[锁屏差异排查](docs/recognition-runtime-gap-2026-09-22.md)，小样本结果不代表长期成功率。
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

继续在系统原有的指纹设置中录入即可，标准 fprintd 客户端会使用驱动内的采集、筛选和检查。需要额外的动作与节奏提示时，可选用命令行引导：

```bash
goodix5503-enroll --finger right-index-finger
```

全程使用同一根手指，约需 49 次按压：先做一次 fprintd 查重，再分组采样 40 次，最后按平时解锁的习惯检查 8 次。质量不合格或近乎重复的采样需要重试，每次等就绪提示再按。检查少于 6 次通过就不完成录入，需要重新采集更丰富的自然位置。通过这轮短检查不等于保证长期解锁成功率。

`1.94.100-45` 的引导要求使用平时解锁的力度，每次把整只手放回键盘或鼠标处，再等通知重新抬手；提示间隔至少 2.5 秒，每组之后停顿至少 6 秒，约需 3–5 分钟。这个间隔只约束提示，不能阻止提前按压。2026-09-23 从零录入后的五轮独立锁屏均一次通过，9 次错指均拒绝；样本仍小，不能视为长期成功率，见[完整结果](docs/fresh-enrollment-2026-09-22.md)。

引导程序通过标准 fprintd 接口工作，需要权限时使用桌面授权；`--no-notify` 可改为仅终端提示。已有手指默认禁止覆盖；使用 `--replace` 才允许重录，因为 fprintd 开始重录就会删除该手指的旧模板，取消后不会恢复。普通的 `fprintd-enroll -f right-index-finger "$USER"` 也使用驱动里的筛选和检查，但没有引导程序的分组提示和覆盖保护。fprintd 显示 49 阶段，其中第一步是查重，驱动本身有 48 阶段。

可选引导默认使用简短英文，需要中文可指定 `--language zh`。安装包不新增独立应用或菜单入口。原系统指纹设置保持原有界面，不会显示可选引导的定时提示。

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
- 离线 Python 回归测试（不需要 PyUSB 或硬件）：
  `python3 tests/run_offline_tests.py`

离线运行器会在导入包之前以惰性的内存 stub 替换 PyUSB。任何未被 mock 的
USB 枚举、接口认领、传输或释放都会立即令测试失败。它包含固件保护与使用
fake endpoint 的协议测试；未安装可选 Unicorn 时，白盒测试会跳过。该命令
不会运行 probe CLI，也不会打开物理设备。

C 驱动的固件 gate 也由该运行器进行源码级检查；它验证拒绝顺序，而不是执行
C callback 或单独的 Python IAP 分类。本 checkout 仅包含 Goodix
overlay，不包含 pinned libfprint 构建树和私有头文件，因而不能构建隔离的
compiled-driver 测试。所需的隔离 Meson/GUsb 环境见
[compiled-test feasibility note](docs/firmware-guard-compiled-test-feasibility.md)；
不得以合成 harness 或硬件 probe 代替。

匹配参数与模板格式是版本化的：任何改动特征提取、匹配语义或判定阈值的修改都必须同步 bump 模板格式版本，否则旧模板会被拒绝加载。具体约束见 `docs/libfprint-driver-plan.md`。

## 上游参考与许可

这个项目站在以下开源工作的肩膀上：

- [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint)（LGPL-2.1-or-later）：驱动框架、状态机、录入/验证流程。构建时固定在其上游提交 `80a4b5ec...`，本仓库不包含 libfprint 代码。
- [goodix-fp-linux-dev/goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump)（[MIT](https://github.com/goodix-fp-linux-dev/goodix-fp-dump/blob/master/LICENSE)，参考提交 `cc43bb3b`、`718ee3c1`）：5503 协议帧格式（`0xa0` 外框、校验和、命令集），只参考接口，不复制其代码。
- [goodix-fp-linux-dev/libfprint SIGFM 分支](https://github.com/goodix-fp-linux-dev/libfprint/tree/0x00002a/libfprint-sigfm)（LGPL-2.1-or-later，参考提交 `7ebe0c80`）：SIFT + CLAHE + mutual/geometric matching 在 libfprint 里的接线方式；`sigfm.cpp/hpp` 保留了上游原始版权头（2022 年三位作者），随本仓库以 LGPL 分发。
- [AndyHazz/goodix53x5-libfprint](https://github.com/AndyHazz/goodix53x5-libfprint)（参考提交 `309d4c69`）：该仓库**没有 LICENSE 文件**，我们只参考了它把 SIGFM 用于 Goodix 传感器的集成思路，没有复制它的任何代码；本项目自有的驱动、协议、TLS、配置和持久格式都是独立实现的。

本项目采用 `LGPL-2.1-or-later`。Windows 官方驱动二进制、设备凭据（PSK/备份/模板）和本机指纹图像不随仓库分发。
