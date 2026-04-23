---
name: modern-web
description: 现代 Web 场景技能，覆盖 GraphQL、JWT、Request Smuggling、Prototype Pollution、WebSocket、OAuth/OIDC 等非传统漏洞面。
allowed-tools: Bash, Read, Write
---

# 现代 Web 场景

适用于传统 `SQLi/XSS/RCE` 之外的协议层、框架层和 API 层问题。

## 触发时机

- 目标暴露 `GraphQL`、`/graphql`、`graphiql`、`WebSocket`、`JWT`、`OAuth`、`OIDC` 等明确线索。
- 请求头、响应头、前端脚本或接口文档中出现现代 Web 协议或中间件特征。

## 重点方向

- `GraphQL`：schema/introspection、对象级鉴权、批量查询滥用、字段级越权
- `JWT`：`alg=none`、算法混淆、`jku/x5u/jwk/kid` 注入
- `Request Smuggling`：`Content-Length` / `Transfer-Encoding` 冲突
- `Prototype Pollution`：`__proto__`、`constructor.prototype`
- `WebSocket / OAuth / OIDC`：会话绑定、跨站 WebSocket、重定向与 token 流程错误

## 使用原则

- 必须先确认目标确实使用了对应协议或框架，再加载本 skill。
- 优先做最小化、低破坏验证，避免把现代 Web 特征误归到传统漏洞类型。
- 若没有明确现代 Web 指示器，不应把本 skill 注入到上下文中污染推理。
