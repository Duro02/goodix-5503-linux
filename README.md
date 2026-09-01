# goodix-5503-linux

在 Linux 上使用联想/惠普等笔记本常见的 Goodix `27c6:5503` 指纹传感器的驱动。这个仓库最初是逆向工程项目，现在驱动已经完成，并在开发者自己的机器上安装、日常使用。

## 功能

- **按下即识别**：开机或挂起后的第一次认证需要几秒校准，之后只要电脑不重启，每次解锁都是即时的（约 100 毫秒完成准备，手指按下后 60 毫秒内出图）。
- **录入引导**：默认录入 12 次，建议每次换位置和角度；按得太差的次会被要求重按；最后一次录完，要抬起手指才提示完成。
- **安全**：指纹图像只在本机处理，模板存在本机；没有发现过用其他手指误识别的情况（测试次数有限，见下文"限制"）。

## 限制

- **识别率**：同一根手指并不是每次都能一次通过——实测约一半的概率需要按第二次，重按基本都能过。失败的原因是按压变形（力度、角度）超出匹配算法的容差，属于算法参数问题，记录在 `docs/libfprint-driver-plan.md`。
- **只支持这一种设备组合**：传感器 `27c6:5503` + 官方固件 `GF3258_RTSEC_APP_10063`。其他固件版本的设备不支持。
- **不刷固件、不改 PSK**：驱动的探测工具只读；设备上已有的 Windows 配对密钥不会被改动。

## 安装

在 Arch 上构建安装（需要 `opencv`、`gobject-introspection`）：

```bash
bash packaging/arch/build-package.sh
sudo pacman -U --noconfirm --overwrite "*" .tools/packages/libfprint-goodix5503-*.pkg.tar.zst
```

驱动是 libfprint 的一个插件，安装后 `fprintd` 自动就能识别设备。

## 使用

录入指纹：

```bash
sudo fprintd-enroll $USER
```

之后系统锁屏（SDDM/omarchy/GNOME 等）在 PAM 里配了 fprintd 的都可以用指纹解锁。为了让驱动在多次解锁之间保持"热"状态（即点即用），fprintd 需要常驻：

```bash
sudo systemctl edit fprintd.service
# 加入:
# [Service]
# ExecStart=
# ExecStart=/usr/lib/fprintd --no-timeout
```

## 安全与探测


探测器只允许以下命令：

- `NOP`：唤醒/同步设备；
- `FIRMWARE_VERSION`：读取应用固件版本；
- `GET_IAP_VERSION`：读取 IAP 版本；
- `PRESET_PSK_READ`：可选，只读取官方 R-family 的 `0xbb020007` 校验记录和 `0xbb010002` DPAPI 记录。`0xbb010003` 是已由历史硬件试验证明不可读的 MCU 白盒写入输入，当前备份命令不会再次读取它。检查模式只报告元数据；显式备份模式保存不透明原始记录，但绝不把记录内容或明文密钥输出到终端。

默认 probe CLI 仍会阻止固件、PSK、配置、reset、寄存器写入和图像采集。仓库内另有边界固定的配对与实验性 runtime 模块；它们不通过 probe CLI 暴露通用 raw-command 接口。固件/IAP 与任意 protected-record 写入仍属于禁止或单独审批的持久操作。

“非持久性”不代表完全没有风险：程序仍会向 USB 设备发送查询命令。固件异常时，设备可能暂时无响应，需要重启或彻底关机后恢复。但它不会主动修改 Flash、PSK 或 IAP。

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

## 开发

- `src/goodix5503/`：Python 探测与实验工具（只读，不碰固件/PSK）
- `libfprint/`：C 驱动源码、SIGFM 匹配算法、针对 libfprint 的 patch
- 测试（不需要硬件）：`PYTHONPATH=src python -m unittest discover -s tests -v`

匹配参数与模板格式是版本化的：任何改动特征提取、匹配语义或判定阈值的修改都必须同步 bump 模板格式版本，否则旧模板会被拒绝加载。具体约束见 `docs/libfprint-driver-plan.md`。

## Windows 官方驱动分析


已下载并校验与机型 `21A2`、设备 `27c6:5503` 精确匹配的 Lenovo 官方 Windows 10/11 驱动。专有二进制保存在 Git 忽略的 `artifacts/windows-driver/`，不会提交或分发。

静态分析结论见 [`docs/windows-driver-analysis.md`](docs/windows-driver-analysis.md)。分析确认该设备会把 TLS 加密的指纹图像传给主机，并由主机侧算法完成特征提取和匹配。

本机只读探测结果见 [`docs/device-state.md`](docs/device-state.md)：设备已运行官方 `10063` 固件，并存在与社区开发密钥不同的 PSK 状态。因此不会刷写固件或覆盖 PSK。

PSK/TLS 逆向结论见 [`docs/psk-tls-analysis.md`](docs/psk-tls-analysis.md)：官方驱动存在 Windows DPAPI 回退路径和条件式 enclave 路径。旧系统使用了哪条路径尚未证明；设备哈希本身不能恢复随机 PSK，而 enclave 能否在隔离 Windows 环境中复用现有受保护记录仍待验证。

## 上游参考与许可

这个项目站在以下开源工作的肩膀上：

- [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint)（LGPL-2.1-or-later）：驱动框架、状态机、录入/验证流程。构建时固定在其上游提交 `80a4b5ec...`，本仓库不包含 libfprint 代码。
- [goodix-fp-linux-dev/goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump)（[MIT](https://github.com/goodix-fp-linux-dev/goodix-fp-dump/blob/master/LICENSE)，参考提交 `cc43bb3b`、`718ee3c1`）：5503 协议帧格式（`0xa0` 外框、校验和、命令集），只参考接口，不复制其代码。
- [goodix-fp-linux-dev/libfprint SIGFM 分支](https://github.com/goodix-fp-linux-dev/libfprint/tree/0x00002a/libfprint-sigfm)（LGPL-2.1-or-later，参考提交 `7ebe0c80`）：SIFT + CLAHE + mutual/geometric matching 在 libfprint 里的接线方式；`sigfm.cpp/hpp` 保留了上游原始版权头（2022 年三位作者），随本仓库以 LGPL 分发。
- [AndyHazz/goodix53x5-libfprint](https://github.com/AndyHazz/goodix53x5-libfprint)（参考提交 `309d4c69`）：该仓库**没有 LICENSE 文件**，我们只参考了它把 SIGFM 用于 Goodix 传感器的集成思路，没有复制它的任何代码；本项目自有的驱动、协议、TLS、配置和持久格式都是独立实现的。

本项目采用 `LGPL-2.1-or-later`。Windows 官方驱动二进制、设备凭据（PSK/备份/模板）和本机指纹图像不随仓库分发。