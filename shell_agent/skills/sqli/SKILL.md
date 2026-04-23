---
name: sqli
description: SQL 注入漏洞检测与验证技能。
allowed-tools: Bash, Read, Write
---

# SQL 注入（SQLi）

## 触发时机

- 参数化查询入口、搜索接口、ID 查询接口等。

## 验证流程

1. 报错型线索识别。
2. 布尔盲注差异验证。
3. 时间盲注稳定性验证。

## 误报防护

- 至少满足一种可重复差异证据，不凭单次报错确认。
