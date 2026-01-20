# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

远程电源管理系统 - 支持远程关机、重启和 Wake-on-LAN 功能的 Rust 应用。

### 组件

| 组件 | 目录 | 描述 |
|------|------|------|
| **common** | `common/` | 共享协议、加密工具、错误类型 |
| **agent** | `agent/` | 被控端：系统托盘服务，接收远程指令 |
| **client** | `client/` | 控制端：iced GUI，发送指令 |

## 常用命令

```bash
# 构建全部
cargo build --release

# 构建单个组件
cargo build -p reboot-agent --release
cargo build -p reboot-client --release

# 运行测试
cargo test

# 运行单个 crate 测试
cargo test -p common

# 检查代码
cargo clippy --all-targets

# 格式化
cargo fmt
```

## 架构要点

### 通信协议 (`common/src/protocol.rs`)

- 使用 MessagePack 序列化
- 消息格式：4字节长度前缀 + MessagePack 数据
- `CommandRequest` / `CommandResponse` 结构
- PSK 认证 (HMAC-SHA256)

### 被控端 Agent

- 无窗口模式，仅系统托盘 (`#![windows_subsystem = "windows"]`)
- 配置加密存储于 `%APPDATA%\reboot-agent\config.enc`
- 使用硬件指纹派生加密密钥

### 控制端 Client

- iced 0.13 GUI 框架
- 配置明文存储于 `%APPDATA%\reboot-client\config.toml`
- 首次连接自动保存 MAC 地址用于 WoL

### 安全机制

- 时间戳防重放 (±60秒)
- 请求 ID 去重
- 速率限制 (默认 10 req/min/IP)
- 可选 IP 白名单

## 关键依赖

- `tokio` - 异步运行时
- `iced` - GUI (客户端)
- `tray-icon` + `winit` - 系统托盘 (被控端)
- `aes-gcm` - 配置加密
- `windows` crate - Windows API

## 注意事项

- Agent 需要管理员权限执行关机命令
- WoL 需要目标机器 BIOS 中启用 Wake-on-LAN
- 防火墙需放行 Agent 监听端口 (默认 7890)
