# goodix-5503-linux

面向 Goodix `27c6:5503` 指纹传感器的实验性 Linux 驱动研究项目。目前只包含一个**非持久性元数据探测器**，还不是可供 `fprintd` 或 PAM 使用的驱动。

## 当前安全边界

探测器只允许以下命令：

- `NOP`：唤醒/同步设备；
- `FIRMWARE_VERSION`：读取应用固件版本；
- `GET_IAP_VERSION`：读取 IAP 版本；
- `PRESET_PSK_READ`：可选，仅允许官方 R-family 的三个固定只读选择器：`0xbb020007` 校验记录、`0xbb010002` DPAPI 记录和 `0xbb010003` MCU 白盒记录。检查模式只报告元数据；显式备份模式保存不透明原始记录，但绝不把记录内容或明文密钥输出到终端。

下列功能没有实现，并会被命令白名单阻止：

- 擦除或写入固件；
- 修改 PSK；
- 上传传感器配置；
- MCU/传感器 reset；
- 写寄存器；
- 指纹采集。

“非持久性”不代表完全没有风险：程序仍会向 USB 设备发送查询命令。固件异常时，设备可能暂时无响应，需要重启或彻底关机后恢复。但它不会主动修改 Flash、PSK 或 IAP。

## 安装开发环境

```bash
cd ~/Projects/goodix-5503-linux
python -m venv .venv
.venv/bin/pip install -e .
```

## 测试（不会访问硬件）

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## 探测硬件

暂时不要自行执行；首次硬件探测应在确认代码审查结果后进行。

```bash
sudo .venv/bin/goodix-5503-probe
sudo .venv/bin/goodix-5503-probe --check-psk-state
sudo .venv/bin/goodix-5503-probe --inspect-protected-record
sudo .venv/bin/goodix-5503-probe --backup-protected-record
sudo .venv/bin/goodix-5503-probe --backup-rollback-set
```

默认不会查询任何 PSK 状态。受保护记录操作会先设置并验证 `PR_SET_DUMPABLE=0`，同时设置 `RLIMIT_CORE=0`；任一步失败都会在 USB 访问前终止。检查模式只输出长度和 SHA-256。备份模式读取完成后会先关闭 USB 会话，再永久放弃 sudo root 权限；降权后会重新设置并验证 non-dumpable 状态，随后才以原用户身份执行文件系统操作。root 身份的文件写入会被拒绝。记录通过 `0600` 临时文件、`fsync` 和排他硬链接提交，已有文件只允许逐字节验证一致，绝不会覆盖。完整回滚集包含 `0xbb010002`、`0xbb010003` 和 `0xbb020007` 三个文件。备份目录权限为 `0700` 且已被 Git 忽略，所有可变内存副本在使用后覆盖。`--backup-rollback-set` 仍须通过独立审查后才能首次运行。

## 上游参考与许可证

协议帧格式参考：

- [goodix-fp-linux-dev/goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump)
- 参考提交：`cc43bb3b3154a0bccc0412ae024013c7e1923139`
- `5503` 初始实现提交：`718ee3c1c06fe88e93ab7694d299cb5ad9d185c4`

本项目采用 `LGPL-2.1-or-later`。在能够无刷写地稳定采集图像以前，不会接入 `fprintd/PAM`。

## Windows 官方驱动分析

已下载并校验与机型 `21A2`、设备 `27c6:5503` 精确匹配的 Lenovo 官方 Windows 10/11 驱动。专有二进制保存在 Git 忽略的 `artifacts/windows-driver/`，不会提交或分发。

静态分析结论见 [`docs/windows-driver-analysis.md`](docs/windows-driver-analysis.md)。分析确认该设备会把 TLS 加密的指纹图像传给主机，并由主机侧算法完成特征提取和匹配。

本机只读探测结果见 [`docs/device-state.md`](docs/device-state.md)：设备已运行官方 `10063` 固件，并存在与社区开发密钥不同的 PSK 状态。因此不会刷写固件或覆盖 PSK。

PSK/TLS 逆向结论见 [`docs/psk-tls-analysis.md`](docs/psk-tls-analysis.md)：官方驱动存在 Windows DPAPI 回退路径和条件式 enclave 路径。旧系统使用了哪条路径尚未证明；设备哈希本身不能恢复随机 PSK，而 enclave 能否在隔离 Windows 环境中复用现有受保护记录仍待验证。
