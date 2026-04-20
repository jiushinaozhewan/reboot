# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-04-20

### Added

- Agent 增加可开关的调试日志，默认关闭，调试时写入程序目录 `log.txt`
- Client 增加可开关的调试日志，默认关闭，调试时写入程序目录 `log.txt`
- Client 增加网段端口自动扫描，可自动填充目标 IP 并按需扩容目标条目
- Client 支持每目标独立密钥的加密保存与恢复

### Changed

- README 全面重写，更新为当前真实功能、部署方式和取证流程
- 工作区版本提升到 `1.1.0`
- Agent 输入对话框改为独立 helper 流程，降低资源占用并去掉黑框
- Agent / Client 调试取证流程统一为可手动启停日志

### Fixed

- 修复 Agent 托盘菜单在端口设置、显示密钥、修改密钥之间切换后出现假死的问题
- 修复 Agent 本地输入对话框阻塞动作线程，导致后续菜单命令无响应的问题
- 修复 Client 目标密钥输入框显示异常与多行输入状态串用问题
- 修复 Client 多目标配置在密钥、MAC、连接取证方面的稳定性问题
- 改善时间容忍、认证失败提示和连接结果处理
