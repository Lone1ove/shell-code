---
name: xss
description: 跨站脚本漏洞检测与验证技能。
allowed-tools: Bash, Read, Write
---

# XSS

## 触发时机

- 用户输入可被页面回显或进入前端脚本上下文。

## 验证流程

1. 识别上下文：HTML/属性/JS/URL。
2. 构造上下文匹配 payload。
3. 证明可执行，而非仅回显。

## 误报防护

- 仅字符串反射不视为 XSS 成功。
