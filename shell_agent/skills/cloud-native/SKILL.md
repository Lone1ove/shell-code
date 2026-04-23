---
name: cloud-native
description: 云原生与容器场景技能，覆盖 Kubernetes、Kubelet、etcd、ServiceAccount、元数据服务与容器逃逸等风险面。
allowed-tools: Bash, Read, Write
---

# 云原生与容器场景

适用于 `Kubernetes`、`Docker`、云主机元数据服务及容器化部署环境。

## 触发时机

- 目标暴露 `k8s`、`kubelet`、`etcd`、`docker.sock`、`serviceaccount`、`169.254.169.254` 等明确线索。
- 响应头、目录结构、挂载路径或错误信息显示目标运行在容器或云环境中。

## 重点方向

- `Kubernetes API Server / Kubelet / etcd` 暴露
- `ServiceAccount token` 滥用与权限提升
- 元数据服务访问，如 `169.254.169.254`
- `Docker` / 容器逃逸、`docker.sock` 暴露

## 使用原则

- 仅在出现容器、K8s 或云环境指示器时启用。
- 先确认环境边界，再做最小化验证，避免把普通 Web 目标错误带入云原生推理。
- 对云原生结果同样要求确定性证据，不能只因“看起来像 K8s”就直接确认风险。
