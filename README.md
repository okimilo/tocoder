# ToCodex Proxy

一个独立的 Python 中转服务，把 ToCodex 的签名鉴权包装成两套常见接口：

- OpenAI 风格：`/v1/chat/completions`、`/v1/models`
- OpenAI Responses 子集：`/v1/responses`
- Anthropic 风格：`/anthropic/v1/messages`、`/anthropic/v1/messages/count_tokens`

这个服务的目标是让你把支持自定义 LLM 网关的客户端指向本地代理，而不是直接改 ToCodex 本身。

## 适配范围

- `chat.completions`：基本透传，支持流式。
- `responses`：做了一个实用子集，覆盖文本输出和 function tool call。适合接 OpenAI 兼容网关场景。
- `anthropic messages`：支持文本、base64 图片、`tool_use`、`tool_result`，并把它们转成 ToCodex 的 OpenAI 兼容请求。

暂不覆盖：

- OpenAI Responses 里的 computer use、image generation、file search 等高级 item。
- Anthropic 的 Bedrock / Vertex 专用接口。

## 目录

- [app.py](./app.py)
- [requirements.txt](./requirements.txt)
- [.env.example](./.env.example)

## 运行

```bash
cd tocodex_proxy
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app:app --host 127.0.0.1 --port 8787
```

服务起来后：

- OpenAI 兼容基地址：`http://127.0.0.1:8787/v1`
- Anthropic 兼容基地址：`http://127.0.0.1:8787/anthropic`

## 配置

默认会优先使用 `.env` 里的 `TOCODEX_API_KEY`。如果你不想在代理里固定 key，也可以把它留空，然后由客户端把认证头传进来：

- OpenAI 风格：`Authorization: Bearer <key>`
- Anthropic 风格：`X-Api-Key: <key>` 或 `Authorization: Bearer <key>`

关键环境变量：

- `TOCODEX_BASE_URL`：上游地址，默认 `https://api.tocodex.com`
- `TOCODEX_API_KEY`：固定上游 key，可空
- `TOCODEX_HMAC_SECRET`：ToCodex 请求签名用的密钥
- `TOCODEX_APP_VERSION`：签名头里的 `X-Roo-App-Version`
- `TOCODEX_DEFAULT_MODEL`：客户端没传 `model` 时的默认模型

## 客户端接法

### OpenAI 兼容客户端

把 base URL 指向：

```text
http://127.0.0.1:8787/v1
```

如果客户端要求 API key，就填：

- 代理里已经固定 `TOCODEX_API_KEY`：任意非空占位值
- 代理里没固定 key：填真实 ToCodex key

### Claude Code

Anthropic 官方文档说明 Claude Code 支持 `ANTHROPIC_BASE_URL` 指向一个 provider-compatible gateway。这个代理对应的值应设为：

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic
export ANTHROPIC_API_KEY=dummy
```

如果你没有在代理里写死 `TOCODEX_API_KEY`，那这里把 `ANTHROPIC_API_KEY` 换成真实 ToCodex key 即可。

这个结论基于 Anthropic 官方 Claude Code 网关文档与 settings 文档。

### Codex

最近的 Codex CLI 自定义 OpenAI provider 场景已经会打到 `/v1/responses`。这个代理已经实现了一个可用的 `responses` 子集，所以它的 OpenAI base URL 直接指向：

```text
http://127.0.0.1:8787/v1
```

具体怎么在 Codex CLI 里配置自定义 provider，取决于你当前的 Codex 版本；但只要它允许你指定 OpenAI-compatible base URL，就可以接这个代理。

这个判断是基于 OpenAI `responses` 官方接口文档，以及 openai/codex 公开 issue 里对自定义 `openai_base_url` 和 `/v1/responses` 的实际行为描述。

## 验证

### OpenAI models

```bash
curl -sS http://127.0.0.1:8787/v1/models \
  -H "Authorization: Bearer YOUR_TOCODEX_KEY"
```

### OpenAI chat.completions

```bash
curl -sS http://127.0.0.1:8787/v1/chat/completions \
  -H "Authorization: Bearer YOUR_TOCODEX_KEY" \
  -H "Content-Type: application/json" \
  --data '{
    "model": "gpt-5.4",
    "messages": [
      {"role": "user", "content": "回一句 pong"}
    ],
    "stream": false
  }'
```

### Anthropic messages

```bash
curl -sS http://127.0.0.1:8787/anthropic/v1/messages \
  -H "x-api-key: YOUR_TOCODEX_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  --data '{
    "model": "gpt-5.4",
    "max_tokens": 512,
    "messages": [
      {"role": "user", "content": "回一句 pong"}
    ]
  }'
```

## 备注

- ToCodex 的签名逻辑和默认请求头，是按当前扩展打包代码里 `roo / ToCodex` 实现还原的。
- 如果 ToCodex 后面改了 `X-ToCodex-Sig` 规则或 `X-Roo-App-Version` 校验方式，你只需要改 [app.py](./app.py) 里的 `signed_tocodex_headers()`。
