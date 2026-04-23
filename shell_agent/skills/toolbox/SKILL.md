---
name: toolbox
description: 渗透测试工具速查技能。用于按场景选择工具与最小命令集。
allowed-tools: Bash, Read, Write
---

# 工具速查

## 使用原则

- 工具仅服务于当前验证目标，不做无关扫描。
- 优先输出最小可执行命令，附预期结果与失败回退方案。

## 常见映射

- 侦察：nmap / whatweb / ffuf
- 漏洞验证：sqlmap / nuclei / 手工 PoC
- 抓包复核：burp / mitmproxy
