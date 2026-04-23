# API 配置说明

本项目当前支持两类模型接口：

1. `OpenAI-compatible`
   - 代码走 `langchain_openai.ChatOpenAI`
   - 适用于大多数“兼容 OpenAI 格式”的平台
2. `DeepSeek-compatible`
   - 代码走 `langchain_deepseek.ChatDeepSeek`
   - 适用于 `DeepSeek` 官方和部分兼容 `DeepSeek` 的平台

结论先说：

- `GPT / GLM / MiniMax / 大多数 OpenRouter 路由模型` 可以直接接
- `DeepSeek` 官方可以直接接
- `Claude 官方 Anthropic API` 当前 **不能直接接**
  - 因为本项目没有直接使用 `Anthropic SDK`
  - 如果你想用 `Claude`，推荐走 `OpenRouter` 这类 OpenAI-compatible 网关

## 1. 主模型必填项

```env
LLM_PROVIDER=GLM
LLM_BASE_URL=https://api.siliconflow.cn/v1
LLM_API_KEY=sk-xxx
LLM_MODEL_NAME=Pro/zai-org/GLM-5
```

说明：

- `LLM_PROVIDER`
  - 推荐值：`GLM`、`openai`、`deepseek`
  - 实际代码判断：
    - `deepseek` / `lkeap` 走 `ChatDeepSeek`
    - 其他值默认都走 `ChatOpenAI`
- `LLM_BASE_URL`
  - 你所使用平台的 API 根地址
- `LLM_API_KEY`
  - 对应平台 API Key
- `LLM_MODEL_NAME`
  - 平台实际模型名

## 2. 顾问模型可选项

如果你要单独给顾问模型配置接口，填写：

```env
ADVISOR_PROVIDER=MiniMax
ADVISOR_BASE_URL=https://api.siliconflow.cn/v1
ADVISOR_API_KEY=sk-xxx
ADVISOR_MODEL_NAME=Pro/MiniMaxAI/MiniMax-M2.5
```

如果不填 `ADVISOR_*`，顾问模型会回退复用主模型配置。

## 3. 主流模型示例

下面给的是“本项目可直接接入”的常见示例。

### 3.1 GPT 官方 OpenAI

```env
LLM_PROVIDER=openai
LLM_BASE_URL=https://api.openai.com/v1
LLM_API_KEY=sk-xxx
LLM_MODEL_NAME=gpt-4.1-mini
```

如果你想主模型用 GPT、顾问模型也用 GPT：

```env
ADVISOR_PROVIDER=openai
ADVISOR_BASE_URL=https://api.openai.com/v1
ADVISOR_API_KEY=sk-xxx
ADVISOR_MODEL_NAME=gpt-4.1-mini
```

### 3.2 Claude 通过 OpenRouter

注意：这不是 `Anthropic` 官方接口，而是通过 `OpenRouter` 以 OpenAI-compatible 方式接入。

```env
LLM_PROVIDER=openai
LLM_BASE_URL=https://openrouter.ai/api/v1
LLM_API_KEY=sk-or-xxx
LLM_MODEL_NAME=anthropic/claude-3.5-sonnet
```

顾问模型也可以单独配成 Claude：

```env
ADVISOR_PROVIDER=openai
ADVISOR_BASE_URL=https://openrouter.ai/api/v1
ADVISOR_API_KEY=sk-or-xxx
ADVISOR_MODEL_NAME=anthropic/claude-3.5-sonnet
```

### 3.3 Claude 官方 Anthropic

当前项目 **不建议直接这样配**。

原因：

- 本项目没有直接对接 `Anthropic SDK`
- 当前代码默认只支持 `OpenAI-compatible` 和 `DeepSeek-compatible`

如果你一定要用 `Claude`，建议：

1. 走 `OpenRouter`
2. 或你自己的 OpenAI-compatible 网关

### 3.4 DeepSeek 官方

```env
LLM_PROVIDER=deepseek
LLM_BASE_URL=https://api.deepseek.com/v1
LLM_API_KEY=sk-xxx
LLM_MODEL_NAME=deepseek-chat
```

如果顾问模型也用 DeepSeek：

```env
ADVISOR_PROVIDER=deepseek
ADVISOR_BASE_URL=https://api.deepseek.com/v1
ADVISOR_API_KEY=sk-xxx
ADVISOR_MODEL_NAME=deepseek-chat
```

### 3.5 腾讯云 LKEAP 上的 DeepSeek

```env
LLM_PROVIDER=deepseek
LLM_BASE_URL=https://api.lkeap.cloud.tencent.com/v1
LLM_API_KEY=sk-xxx
LLM_MODEL_NAME=deepseek-v3.1-terminus
```

### 3.6 GLM 通过 SiliconFlow

这是你当前项目最常见的接法。

```env
LLM_PROVIDER=GLM
LLM_BASE_URL=https://api.siliconflow.cn/v1
LLM_API_KEY=sk-xxx
LLM_MODEL_NAME=Pro/zai-org/GLM-5
```

### 3.7 MiniMax 通过 SiliconFlow

适合做顾问模型：

```env
ADVISOR_PROVIDER=MiniMax
ADVISOR_BASE_URL=https://api.siliconflow.cn/v1
ADVISOR_API_KEY=sk-xxx
ADVISOR_MODEL_NAME=Pro/MiniMaxAI/MiniMax-M2.5
```

### 3.8 Qwen 通过 OpenAI-compatible 网关

如果你的平台提供 Qwen 的 OpenAI-compatible 接口，可以这样配：

```env
LLM_PROVIDER=openai
LLM_BASE_URL=https://your-openai-compatible-endpoint/v1
LLM_API_KEY=sk-xxx
LLM_MODEL_NAME=qwen-plus
```

### 3.9 Gemini 通过 OpenAI-compatible 网关

如果你的平台把 Gemini 包装成 OpenAI-compatible 接口，也可以直接这样接：

```env
LLM_PROVIDER=openai
LLM_BASE_URL=https://your-openai-compatible-endpoint/v1
LLM_API_KEY=sk-xxx
LLM_MODEL_NAME=gemini-1.5-pro
```

## 4. 推荐组合

### 方案 A：你当前项目推荐组合

```env
LLM_PROVIDER=GLM
LLM_BASE_URL=https://api.siliconflow.cn/v1
LLM_API_KEY=sk-xxx
LLM_MODEL_NAME=Pro/zai-org/GLM-5

ADVISOR_PROVIDER=MiniMax
ADVISOR_BASE_URL=https://api.siliconflow.cn/v1
ADVISOR_API_KEY=sk-xxx
ADVISOR_MODEL_NAME=Pro/MiniMaxAI/MiniMax-M2.5
```

### 方案 B：GPT 主攻 + Claude 顾问

```env
LLM_PROVIDER=openai
LLM_BASE_URL=https://api.openai.com/v1
LLM_API_KEY=sk-xxx
LLM_MODEL_NAME=gpt-4.1-mini

ADVISOR_PROVIDER=openai
ADVISOR_BASE_URL=https://openrouter.ai/api/v1
ADVISOR_API_KEY=sk-or-xxx
ADVISOR_MODEL_NAME=anthropic/claude-3.5-sonnet
```

### 方案 C：DeepSeek 主攻 + MiniMax 顾问

```env
LLM_PROVIDER=deepseek
LLM_BASE_URL=https://api.deepseek.com/v1
LLM_API_KEY=sk-xxx
LLM_MODEL_NAME=deepseek-chat

ADVISOR_PROVIDER=MiniMax
ADVISOR_BASE_URL=https://api.siliconflow.cn/v1
ADVISOR_API_KEY=sk-xxx
ADVISOR_MODEL_NAME=Pro/MiniMaxAI/MiniMax-M2.5
```

## 5. 快速联通性测试

你可以先用这个命令测试主模型接口是否通：

```bash
uv run python - <<'PY'
from dotenv import load_dotenv
import os, requests
load_dotenv('.env')
url = os.getenv('LLM_BASE_URL','').rstrip('/') + '/models'
key = os.getenv('LLM_API_KEY','')
r = requests.get(url, headers={'Authorization': f'Bearer {key}'}, timeout=20)
print('status=', r.status_code)
print(r.text[:300])
PY
```

如果返回：

```text
status=200
```

说明你的 `base_url + key` 基本可用。

## 6. 常见问题

### 6.1 `Claude` 为什么不能直接写 `api.anthropic.com`

因为当前项目代码没有直接走 `Anthropic SDK`，而是：

- `ChatOpenAI`
- `ChatDeepSeek`

所以 `Claude` 官方接口不能直接按本项目当前方式接入。

### 6.2 `LLM_PROVIDER` 一定要写标准厂商名吗

不一定。  
当前代码里只有：

- `deepseek`
- `lkeap`

会走 `ChatDeepSeek`。  
其他值默认都会按 `OpenAI-compatible` 处理。

所以像下面这些写法都能工作：

```env
LLM_PROVIDER=GLM
LLM_PROVIDER=MiniMax
LLM_PROVIDER=openai
```

前提是你的 `LLM_BASE_URL` 确实兼容 OpenAI 格式。

### 6.3 配完以后项目还是报 Key 错误

优先检查：

1. `.env` 是否还保留了占位符
2. `LLM_BASE_URL` 是否写到了正确的 `/v1`
3. `LLM_MODEL_NAME` 是否和平台实际模型名一致
4. 是否把顾问模型单独配错了
