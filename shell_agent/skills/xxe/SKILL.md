---
name: xxe
description: XML 外部实体注入（XXE）漏洞的识别、验证与误报防护规则。
allowed-tools: Bash, Read, Write
---

# XML 外部实体注入（XXE）

适用于 SOAP、REST XML 接口、自定义 XML 解析器及相关上传/导入功能。

## 触发时机

- 目标明确接收 XML。
- 响应中出现 DTD、ENTITY、XML parser、SAX/DOM 报错或文件读取迹象。

## 验证流程

1. 先确认接口真实走 XML 解析逻辑。
2. 构造低风险外部实体或本地文件读取探测。
3. 以文件内容、实体展开结果或外联证据作为确认依据。
4. 若是 XMLDecoder / 反序列化链，不要误归类为 XXE，应转入对应 RCE 家族。

## 误报防护

- 普通 XML 解析失败或 `<!DOCTYPE html>` 页面内容不能确认为 XXE。
- 仅因请求里出现 `<!ENTITY`，但响应无实体解析证据，不算已验证。

## 报告要求

- 记录 XML 入口、关键实体定义、命中的文件或回连证据。
- 明确区分 XXE、XMLDecoder 和通用反序列化问题。
