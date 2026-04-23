---
name: file-inclusion
description: 文件包含与路径遍历漏洞检测与验证技能。
allowed-tools: Bash, Read, Write
---

# 文件包含/路径遍历

## 触发时机

- 文件读取、模板加载、语言包切换、下载接口。

## 验证流程

1. 路径构造与编码绕过测试。
2. 目标文件特征内容验证（如 `/etc/passwd` 标记行）。
3. 平台差异验证（Linux/Windows）。

## 误报防护

- 仅状态码变化不算验证成功。
