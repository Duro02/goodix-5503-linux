# goodix-5503-linux

面向 Goodix `27c6:5503` 指纹传感器的实验性 Linux 驱动研究项目。仓库包含只读探测、已验证的配对/TLS与配置派生代码、标准 libfprint SIGFM enrollment/matching 路径，以及已实现但尚未授权安装或写入的持久模板格式。`fprintd`、PAM 和桌面集成仍未完成。

工程范围与避免过度设计的规则见 [`docs/engineering-scope.md`](docs/engineering-scope.md)。

## 当前安全边界

探测器只允许以下命令：

- `NOP`：唤醒/同步设备；
- `FIRMWARE_VERSION`：读取应用固件版本；
- `GET_IAP_VERSION`：读取 IAP 版本；
- `PRESET_PSK_READ`：可选，只读取官方 R-family 的 `0xbb020007` 校验记录和 `0xbb010002` DPAPI 记录。`0xbb010003` 是已由历史硬件试验证明不可读的 MCU 白盒写入输入，当前备份命令不会再次读取它。检查模式只报告元数据；显式备份模式保存不透明原始记录，但绝不把记录内容或明文密钥输出到终端。

默认 probe CLI 仍会阻止固件、PSK、配置、reset、寄存器写入和图像采集。仓库内另有边界固定的配对与实验性 runtime 模块；它们不通过 probe CLI 暴露通用 raw-command 接口。固件/IAP 与任意 protected-record 写入仍属于禁止或单独审批的持久操作。

“非持久性”不代表完全没有风险：程序仍会向 USB 设备发送查询命令。固件异常时，设备可能暂时无响应，需要重启或彻底关机后恢复。但它不会主动修改 Flash、PSK 或 IAP。

## 安装开发环境

```bash
cd ~/Projects/goodix-5503-linux
python -m venv .venv
.venv/bin/pip install -e .
```

启用 Goodix SIGFM 的开发版构建需要 Arch 的 `opencv` 包；构建时只链接
`core`、`features`、`flann` 和 `imgproc` 四个必要模块。未启用 `goodix5503`
时使用无 OpenCV 依赖的 C stub。构建脚本仅接受干净的 libfprint v1.94.10
提交 `0c97a47d8ef405cd577b87058c1e89cae9d242e7`。

SIGFM 持久格式 v3 固定对应本设备字节流的 `64×80` 线性解释，以及当前的
方向 TX-off subtraction、3%–97% normalization、饱和区稳定化、CLAHE、
SIFT 参数(sift_nfeatures=512, 恢复每个关键点的 SIFT 主方向, 不再强制直立描述子)、mutual/geometric matcher
(distance_match=0.90, min_match=3)和阈值 150。任何会改变 feature 或匹配
语义的方向、预处理、descriptor、matcher 或阈值变化都必须提升格式版本。
该格式仅完成离线实现与畸形输入测试；尚未授权写入任何用户模板，也未安装到
系统 libfprint/fprintd。

## 测试（不会访问硬件）

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

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

## 上游参考与许可证

协议帧格式参考：

- [goodix-fp-linux-dev/goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump)
- 参考提交：`cc43bb3b3154a0bccc0412ae024013c7e1923139`
- `5503` 初始实现提交：`718ee3c1c06fe88e93ab7694d299cb5ad9d185c4`
- [goodix-fp-linux-dev/libfprint SIGFM branch](https://github.com/goodix-fp-linux-dev/libfprint/tree/0x00002a/libfprint-sigfm)，参考提交 `7ebe0c809b4d1df3400e84299a4ec4acdea84590`
- [AndyHazz/goodix53x5-libfprint](https://github.com/AndyHazz/goodix53x5-libfprint)，采用其 SIGFM/CLAHE 和 mutual/geometric matching，并在本项目中加入有版本、严格有界且清零临时副本的 libfprint 私有持久格式；参考提交 `309d4c6999a1cdce172c1ca1ee81387b5078d38f`

本项目采用 `LGPL-2.1-or-later`。在能够无刷写地稳定采集图像以前，不会接入 `fprintd/PAM`。

## Windows 官方驱动分析

已下载并校验与机型 `21A2`、设备 `27c6:5503` 精确匹配的 Lenovo 官方 Windows 10/11 驱动。专有二进制保存在 Git 忽略的 `artifacts/windows-driver/`，不会提交或分发。

静态分析结论见 [`docs/windows-driver-analysis.md`](docs/windows-driver-analysis.md)。分析确认该设备会把 TLS 加密的指纹图像传给主机，并由主机侧算法完成特征提取和匹配。

本机只读探测结果见 [`docs/device-state.md`](docs/device-state.md)：设备已运行官方 `10063` 固件，并存在与社区开发密钥不同的 PSK 状态。因此不会刷写固件或覆盖 PSK。

PSK/TLS 逆向结论见 [`docs/psk-tls-analysis.md`](docs/psk-tls-analysis.md)：官方驱动存在 Windows DPAPI 回退路径和条件式 enclave 路径。旧系统使用了哪条路径尚未证明；设备哈希本身不能恢复随机 PSK，而 enclave 能否在隔离 Windows 环境中复用现有受保护记录仍待验证。
