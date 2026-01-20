# Reboot - 远程电源管理系统

[![Release](https://img.shields.io/github/v/release/jiushinaozhewan/reboot)](https://github.com/jiushinaozhewan/reboot/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

一个安全、轻量的远程电源管理工具，支持远程关机、重启和 Wake-on-LAN 功能。

## 功能特性

- **远程关机** - 安全地远程关闭目标计算机
- **远程重启** - 远程重启目标计算机
- **Wake-on-LAN** - 通过网络唤醒处于关机状态的计算机
- **PSK 认证** - 使用预共享密钥 (HMAC-SHA256) 确保通信安全
- **防重放攻击** - 时间戳验证 (±60秒) + 请求 ID 去重
- **速率限制** - 防止暴力破解 (默认 10 请求/分钟/IP)
- **IP 白名单** - 可选的 IP 访问控制

## 系统要求

### 运行环境

| 组件 | 要求 |
|------|------|
| 操作系统 | Windows 7 SP1 及以上 |
| 架构 | x86_64 (64位) |
| 权限 | 被控端需要管理员权限 |
| 网络 | 被控端需开放 TCP 端口 (默认 7890) |

### 编译环境 (仅开发者)

| 工具 | 版本要求 |
|------|----------|
| Rust | 1.70.0 及以上 |
| Cargo | 随 Rust 安装 |
| Visual Studio Build Tools | 2019 或更高 (Windows) |

## 快速开始

### 方式一：下载预编译版本 (推荐)

1. 前往 [Releases](https://github.com/jiushinaozhewan/reboot/releases) 页面
2. 下载最新版本的 `reboot-agent.exe` 和 `reboot-client.exe`

### 方式二：从源码编译

```bash
# 克隆仓库
git clone https://github.com/jiushinaozhewan/reboot.git
cd reboot

# 编译 Release 版本
cargo build --release

# 可执行文件位于
# target/release/reboot-agent.exe
# target/release/reboot-client.exe
```

## 部署指南

### 被控端 (Agent) 部署

1. **复制程序**
   ```
   将 reboot-agent.exe 复制到被控计算机
   ```

2. **首次运行配置**
   - 以管理员身份运行 `reboot-agent.exe`
   - 首次运行会自动创建配置向导
   - 设置监听端口和预共享密钥 (PSK)

3. **配置防火墙**
   ```powershell
   # 以管理员身份运行 PowerShell
   New-NetFirewallRule -DisplayName "Reboot Agent" -Direction Inbound -Protocol TCP -LocalPort 7890 -Action Allow
   ```

4. **设置开机自启 (可选)**
   - 将 `reboot-agent.exe` 的快捷方式放入启动文件夹
   - 或使用任务计划程序创建开机任务

### 控制端 (Client) 部署

1. **复制程序**
   ```
   将 reboot-client.exe 复制到控制计算机
   ```

2. **直接运行**
   - 双击运行 `reboot-client.exe`
   - 无需管理员权限

## 使用方法

### 控制端操作

1. **启动程序** - 运行 `reboot-client.exe`

2. **连接被控端**
   - 输入被控端 IP 地址 (如 `192.168.1.100`)
   - 输入端口号 (默认 `7890`)
   - 输入预共享密钥 (与被控端配置一致)
   - 点击「连接」

3. **执行操作**
   - 点击「关机」- 远程关闭被控端
   - 点击「重启」- 远程重启被控端
   - 点击「唤醒」- 发送 WoL 魔术包唤醒被控端

### Wake-on-LAN 设置

要使用 WoL 唤醒功能，需要在被控端进行以下配置：

1. **BIOS 设置**
   - 进入 BIOS 设置界面
   - 找到「Power Management」或「电源管理」
   - 启用「Wake on LAN」或「网络唤醒」

2. **网卡设置**
   ```
   设备管理器 → 网络适配器 → 右键属性 → 电源管理
   ☑ 允许此设备唤醒计算机
   ☑ 只允许魔术数据包唤醒计算机
   ```

3. **关闭快速启动 (Windows 10/11)**
   ```
   控制面板 → 电源选项 → 选择电源按钮的功能 → 更改当前不可用的设置
   ☐ 取消勾选「启用快速启动」
   ```

## 配置文件

### 被控端配置

配置文件位置：`%APPDATA%\reboot-agent\config.enc` (加密存储)

配置项：
- `port` - 监听端口 (默认: 7890)
- `psk` - 预共享密钥
- `rate_limit` - 速率限制 (默认: 10 请求/分钟)
- `ip_whitelist` - IP 白名单 (可选)

### 控制端配置

配置文件位置：`%APPDATA%\reboot-client\config.toml` (明文存储)

配置项：
- `last_host` - 上次连接的主机地址
- `last_port` - 上次连接的端口
- `saved_mac` - 保存的 MAC 地址 (用于 WoL)

## 项目结构

```
reboot/
├── common/          # 共享库
│   └── src/
│       ├── protocol.rs   # 通信协议定义
│       ├── crypto.rs     # 加密工具
│       └── errors.rs     # 错误类型
├── agent/           # 被控端
│   └── src/
│       ├── main.rs       # 入口点
│       ├── server.rs     # TCP 服务器
│       ├── executor.rs   # 命令执行器
│       ├── config.rs     # 配置管理
│       ├── security.rs   # 安全模块
│       └── tray.rs       # 系统托盘
├── client/          # 控制端
│   └── src/
│       ├── main.rs       # 入口点
│       ├── ui.rs         # 图形界面
│       ├── connection.rs # 连接管理
│       ├── config.rs     # 配置管理
│       └── wol.rs        # Wake-on-LAN
└── Cargo.toml       # 工作空间配置
```

## 安全说明

1. **预共享密钥 (PSK)** - 请使用强密码，建议 16 位以上随机字符
2. **网络安全** - 建议仅在内网使用，或通过 VPN 连接
3. **防火墙** - 仅开放必要端口，建议配合 IP 白名单使用
4. **定期更新** - 关注项目更新，及时升级到最新版本

## 常见问题

### Q: 连接超时怎么办？
A: 检查以下项目：
- 被控端防火墙是否开放端口
- IP 地址和端口是否正确
- 被控端 Agent 是否正在运行

### Q: WoL 唤醒失败？
A: 确认以下设置：
- BIOS 中已启用 Wake-on-LAN
- 网卡电源管理已配置正确
- 已关闭 Windows 快速启动
- 控制端与被控端在同一局域网

### Q: 关机命令执行失败？
A: 确保被控端以管理员权限运行 Agent

## 开发相关

```bash
# 运行测试
cargo test

# 代码检查
cargo clippy --all-targets

# 格式化代码
cargo fmt

# 构建单个组件
cargo build -p reboot-agent --release
cargo build -p reboot-client --release
```

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 贡献

欢迎提交 Issue 和 Pull Request！

---

**注意**：本工具仅供合法用途，请勿用于未经授权的远程控制。使用者需自行承担使用风险。
