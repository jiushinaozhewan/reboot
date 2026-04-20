# Reboot

> 面向 Windows 局域网环境的远程电源管理工具，提供被控端 `reboot-agent.exe` 与控制端 `reboot-client.exe`。

[![Release](https://img.shields.io/github/v/release/jiushinaozhewan/reboot)](https://github.com/jiushinaozhewan/reboot/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## 项目概览

Reboot 用于在局域网内对 Windows 设备执行：

- 远程关机
- 远程重启
- Wake-on-LAN 开机
- 多目标批量管理
- 每目标独立密钥认证

当前版本重点加强了稳定性、取证能力和多目标易用性：

- `reboot-agent.exe`
  - 修复托盘菜单在输入配置后假死的问题
  - 输入对话框改为独立 helper 进程，去掉黑框并降低瞬时资源占用
  - 新增可开关的调试日志，默认关闭，调试时再写 `log.txt`
- `reboot-client.exe`
  - 支持每目标独立密钥并本地加密保存
  - 修复目标密钥输入框串行联动与异常显示问题
  - 新增网段端口自动扫描，扫描到的 IP 自动填入目标列表
  - 新增可开关的调试日志，默认关闭

## 功能特性

### 安全

- HMAC-SHA256 预共享密钥认证
- 请求时间戳校验与重放保护
- 可选 IP 白名单
- 请求限流与认证失败封禁
- 控制端密钥本地保护存储

### 被控端 Agent

- 托盘常驻运行
- 可修改监听端口
- 可显示/修改认证密钥
- 可配置开机自启
- 可切换调试日志输出
- 管理员权限下调用 Windows 原生关机/重启 API

### 控制端 Client

- 1-200 个目标的批量管理
- 每目标独立别名 / IP / 端口 / 广播地址 / MAC / 密钥
- 自动端口扫描并填充目标列表
- 批量测试连接 / 关机 / 重启 / Wake-on-LAN
- MAC 自动获取，失败时支持 ARP 回退
- 可切换调试日志输出

## 系统要求

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Windows 10 / Windows 11 优先，Windows 7 SP1 及以上可尝试 |
| 架构 | x86_64 |
| Agent 权限 | 需要管理员权限运行 |
| 网络 | 控制端与被控端网络可达，Agent 默认监听 TCP `7890` |

## 下载与构建

### 直接下载

前往 [GitHub Releases](https://github.com/jiushinaozhewan/reboot/releases) 下载：

- `reboot-agent.exe`
- `reboot-client.exe`

### 从源码构建

```powershell
git clone https://github.com/jiushinaozhewan/reboot.git
cd reboot
cargo build --release
```

生成物位于：

- `target/release/reboot-agent.exe`
- `target/release/reboot-client.exe`

## 快速开始

### 1. 部署 Agent

1. 将 `reboot-agent.exe` 复制到被控端。
2. 以管理员身份首次运行。
3. 记录或复制首次生成的认证密钥。
4. 按需配置：
   - 监听端口
   - 开机启动
   - 调试日志

建议放行防火墙端口：

```powershell
New-NetFirewallRule -DisplayName "Reboot Agent" -Direction Inbound -Protocol TCP -LocalPort 7890 -Action Allow
```

### 2. 配置 Client

1. 运行 `reboot-client.exe`。
2. 设置目标数量，或通过“自动扫描”发现目标。
3. 为每个目标填写：
   - 别名
   - IP
   - 端口
   - 广播地址（可选）
   - MAC 地址（可手动填，也可连接后自动获取）
   - 目标密钥
4. 点击“保存配置”。

### 3. 执行操作

常用流程：

1. 先点“测试连接”
2. 确认目标状态为“已连接”
3. 再执行“关机”或“重启”
4. 若目标已保存 MAC，可使用“开机 (WoL)”

## 自动扫描

客户端新增自动扫描区，支持：

- 输入单个 IPv4 地址，例如 `10.0.0.130`
- 输入 CIDR 网段，例如 `10.0.0.0/24`
- 指定端口后扫描

行为说明：

- 扫描到的可连接 IP 会按顺序填入目标列表
- 如果结果条目多于当前目标数量，会自动新增目标条目
- 扫描范围上限为 1024 个地址，避免误扫过大网段

## 日志与取证

Agent 与 Client 现在都支持可开关的文件日志：

- 默认关闭，不写磁盘，减少日常资源占用
- 需要调试时手动打开“调试日志”
- 日志文件写入程序同目录：
  - `log.txt`

建议取证方式：

1. 打开 Client 的“调试日志”
2. 打开 Agent 的“调试日志”
3. 复现一次问题
4. 同时收集两端 `log.txt`

## 配置文件

### Agent

- 路径：`%APPDATA%\reboot-agent\config.enc`
- 特点：本地加密存储

主要配置项：

- `port`
- `psk_hex`
- `allowed_ips`
- `rate_limit`
- `log_enabled`

### Client

- 路径：`%APPDATA%\reboot-client\config.toml`
- 特点：目标列表明文结构化保存，目标密钥单独加密保护

主要配置项：

- `target_count`
- `targets`
- `log_enabled`

## Wake-on-LAN 使用说明

被控端要成功 WoL，需要同时满足：

1. BIOS/UEFI 已开启 Wake-on-LAN
2. 网卡电源管理允许魔术包唤醒
3. Windows 快速启动已关闭
4. 控制端到目标广播网络可达

## 常见问题

### 1. 测试连接成功，但关机/重启失败

优先检查：

- Agent 是否以管理员身份运行
- 目标密钥是否与对应 Agent 一致
- Agent 是否因认证失败触发限流/封禁
- 两端是否同时开启调试日志并已收集 `log.txt`

### 2. WoL 唤醒失败

优先检查：

- BIOS/UEFI 设置
- 网卡电源管理
- 快速启动
- MAC 地址是否正确
- 广播地址是否需要手动指定

### 3. 自动扫描没有发现目标

优先检查：

- 输入网段是否正确
- 扫描端口是否与 Agent 实际监听端口一致
- 防火墙是否放行
- 目标主机是否在线

## 项目结构

```text
reboot/
├─ agent/                  # 被控端
├─ client/                 # 控制端
├─ common/                 # 协议/加密/错误定义
├─ MULTI_TARGET_GUIDE.md   # 多目标使用说明
├─ CHANGELOG.md            # 更新记录
└─ README.md
```

## 开发命令

```powershell
cargo test
cargo build --release
cargo build -p reboot-agent --release
cargo build -p reboot-client --release
```

## 许可证

MIT

## 说明

本项目仅用于合法、受授权的远程电源管理场景。请勿将其用于未授权控制或任何违法用途。
