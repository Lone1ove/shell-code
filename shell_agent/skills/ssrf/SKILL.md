---
name: ssrf
description: 服务端请求伪造漏洞检测与验证技能。
allowed-tools: Bash, Read, Write
---

# SSRF

## 触发时机

- 系统存在 URL 拉取、回调、预览、Webhook、抓取功能。

## 验证流程

1. 外部可控回连验证。
2. 内网/云元数据访问验证。
3. 响应特征与请求证据绑定。

## 误报防护

- 仅返回通用错误页不视为 SSRF 成功。
