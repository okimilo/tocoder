from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse


LOG = logging.getLogger("tocodex_proxy")


def configure_logging() -> None:
    level_name = os.getenv("TOCODEX_PROXY_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


def env_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def json_dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def safe_json_loads(raw: str | None) -> Any:
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def parse_bearer_token(value: str | None) -> str | None:
    if not value:
        return None
    prefix = "bearer "
    if value.lower().startswith(prefix):
        return value[len(prefix):].strip() or None
    return value.strip() or None


def normalize_base_url(url: str) -> str:
    normalized = url.rstrip("/")
    if normalized.endswith("/v1"):
        normalized = normalized[:-3]
    return normalized


@dataclass(slots=True)
class Settings:
    tocodex_base_url: str
    tocodex_hmac_secret: str
    tocodex_api_key: str | None
    tocodex_referer: str
    tocodex_title: str
    tocodex_app_version: str
    default_model: str | None
    timeout_seconds: float
    tls_verify: bool
    anthropic_version: str

    # 客户端指纹模拟
    device_id: str
    machine_id: str
    platform: str
    os: str
    client_version: str

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            tocodex_base_url=normalize_base_url(os.getenv("TOCODEX_BASE_URL", "https://api.tocodex.com")),
            tocodex_hmac_secret=os.getenv("TOCODEX_HMAC_SECRET", "tc-hmac-s3cr3t-k3y-2026-tocodex-platform"),
            tocodex_api_key=os.getenv("TOCODEX_API_KEY") or None,
            tocodex_referer=os.getenv("TOCODEX_REFERER", "https://app.tocodex.com/"),
            tocodex_title=os.getenv("TOCODEX_TITLE", "ToCodex"),
            tocodex_app_version=os.getenv("TOCODEX_APP_VERSION", "3.1.3"),
            default_model=os.getenv("TOCODEX_DEFAULT_MODEL") or None,
            timeout_seconds=float(os.getenv("TOCODEX_TIMEOUT_SECONDS", "600")),
            tls_verify=env_bool("TOCODEX_TLS_VERIFY", True),
            anthropic_version=os.getenv("ANTHROPIC_VERSION", "2023-06-01"),
            device_id=env_str("TOCODEX_DEVICE_ID", "windows-server-2016-abc123-def456-7890"),
            machine_id=env_str("TOCODEX_MACHINE_ID", "machine-xyz789-abc123"),
            platform=env_str("TOCODEX_PLATFORM", "Windows"),
            os=env_str("TOCODEX_OS", "Windows 10"),
            client_version=env_str("TOCODEX_CLIENT_VERSION", "1.0.0"),
        )


configure_logging()
load_env_file(Path(__file__).with_name(".env"))
SETTINGS = Settings.from_env()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    timeout = httpx.Timeout(timeout=SETTINGS.timeout_seconds, connect=10.0)
    # 简化版，不加 proxies，避免兼容性问题
    async with httpx.AsyncClient(
        timeout=timeout,
        verify=SETTINGS.tls_verify
    ) as client:
        app.state.http = client
        yield


app = FastAPI(
    title="ToCodex Proxy",
    version="0.1.0",
    lifespan=lifespan,
)

app.state.responses_sessions = {}


# ==================== 优化后的 Headers（核心） ====================
def signed_tocodex_headers(
    path: str,
    api_key: str | None,
    *,
    task_id: str | None = None,
    session_id: str | None = None,
) -> dict[str, str]:
    headers = {
        "Host": "api.tocodex.com",
        "Content-Type": "application/json",
        "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.109 Safari/537.36 ToCodex-Client/{SETTINGS.client_version}",
        "X-Session-ID": session_id or f"550e8400-e29b-41d4-a716-{uuid.uuid4().hex[:12]}",
        "X-Device-ID": SETTINGS.device_id,
        "X-Machine-ID": SETTINGS.machine_id,
        "X-Client-Version": SETTINGS.client_version,
        "X-Mode": "architect",
        "X-Platform": SETTINGS.platform,
        "X-OS": SETTINGS.os,
        "X-Client-Name": "ToCodex-Client",
        "Referer": SETTINGS.tocodex_referer,
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }

    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    # HMAC 签名（必须）
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())
    sign_raw = f"{timestamp}:{nonce}:POST:{path}"
    signature = hmac.new(
        SETTINGS.tocodex_hmac_secret.encode("utf-8"),
        sign_raw.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    headers.update({
        "X-Roo-App-Version": SETTINGS.tocodex_app_version,
        "X-ToCodex-Timestamp": timestamp,
        "X-ToCodex-Nonce": nonce,
        "X-ToCodex-Sig": signature,
    })

    if task_id:
        headers["X-Roo-Task-ID"] = task_id

    return headers


def make_error_message(payload: Any, fallback: str) -> str:
    if isinstance(payload, dict):
        if isinstance(payload.get("error"), dict):
            nested = payload["error"].get("message")
            if isinstance(nested, str) and nested:
                return nested
        if isinstance(payload.get("message"), str) and payload["message"]:
            return payload["message"]
    if isinstance(payload, str) and payload:
        return payload
    return fallback


def anthropic_error_payload(status_code: int, payload: Any) -> dict[str, Any]:
    error_type = {
        400: "invalid_request_error",
        401: "authentication_error",
        403: "permission_error",
        404: "not_found_error",
        429: "rate_limit_error",
    }.get(status_code, "api_error")
    return {
        "type": "error",
        "error": {
            "type": error_type,
            "message": make_error_message(payload, "Upstream ToCodex request failed."),
        },
    }


def tocodex_base_headers(api_key: str | None) -> dict[str, str]:
    headers = {
        "HTTP-Referer": SETTINGS.tocodex_referer,
        "X-Title": SETTINGS.tocodex_title,
        "User-Agent": f"ToCodex/{SETTINGS.tocodex_app_version}",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def signed_tocodex_headers(
    path: str,
    api_key: str | None,
    *,
    task_id: str | None = None,
) -> dict[str, str]:
    headers = tocodex_base_headers(api_key)
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())
    sign_raw = f"{timestamp}:{nonce}:POST:{path}"
    signature = hmac.new(
        SETTINGS.tocodex_hmac_secret.encode("utf-8"),
        sign_raw.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    headers.update(
        {
            "X-Roo-App-Version": SETTINGS.tocodex_app_version,
            "X-ToCodex-Timestamp": timestamp,
            "X-ToCodex-Nonce": nonce,
            "X-ToCodex-Sig": signature,
        }
    )
    if task_id:
        headers["X-Roo-Task-ID"] = task_id
    return headers


def upstream_url(path: str) -> str:
    return f"{SETTINGS.tocodex_base_url}{path}"


def resolve_upstream_api_key(request: Request) -> str | None:
    if SETTINGS.tocodex_api_key:
        return SETTINGS.tocodex_api_key
    auth_header = request.headers.get("authorization")
    bearer = parse_bearer_token(auth_header)
    if bearer:
        return bearer
    x_api_key = request.headers.get("x-api-key")
    if x_api_key:
        return x_api_key.strip()
    return None


def ensure_model(model: str | None) -> str:
    if model:
        return model
    if SETTINGS.default_model:
        return SETTINGS.default_model
    raise HTTPException(
        status_code=400,
        detail="Request is missing model and TOCODEX_DEFAULT_MODEL is not set.",
    )


def media_type_from_headers(headers: httpx.Headers, fallback: str) -> str:
    return headers.get("content-type", fallback).split(";")[0].strip()


def openai_error_payload(message: str, error_type: str = "api_error") -> dict[str, Any]:
    return {"error": {"message": message, "type": error_type}}


def openai_bad_gateway_response(message: str) -> JSONResponse:
    return JSONResponse(
        status_code=502,
        content=openai_error_payload(message, "bad_gateway_error"),
    )


async def make_upstream_response(response: httpx.Response) -> Response:
    body = await response.aread()
    return Response(
        content=body,
        status_code=response.status_code,
        media_type=media_type_from_headers(response.headers, "application/json"),
    )


async def stream_raw_upstream(response: httpx.Response) -> AsyncIterator[bytes]:
    try:
        async for chunk in response.aiter_raw():
            yield chunk
    finally:
        await response.aclose()


def anthropic_sse(event: str, payload: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json_dumps(payload)}\n\n".encode("utf-8")


def openai_sse(payload: dict[str, Any]) -> bytes:
    return f"data: {json_dumps(payload)}\n\n".encode("utf-8")


async def iter_openai_sse_payloads(response: httpx.Response) -> AsyncIterator[dict[str, Any]]:
    async for line in response.aiter_lines():
        if not line or not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            return
        try:
            yield json.loads(data)
        except json.JSONDecodeError:
            LOG.warning("Ignoring malformed upstream SSE line: %s", data)


def flatten_content_to_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if not isinstance(item, dict):
                continue
            item_type = item.get("type")
            if item_type in {"text", "input_text", "output_text"}:
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
            elif item_type == "tool_result":
                parts.append(flatten_content_to_text(item.get("content")))
            elif item_type == "function_call_output":
                parts.append(flatten_content_to_text(item.get("output")))
            elif item_type in {"image", "input_image"}:
                parts.append("[image]")
            elif item_type in {"input_file", "file"}:
                filename = item.get("filename")
                parts.append(f"[file:{filename or 'unknown'}]")
        return "\n".join(part for part in parts if part)
    if isinstance(content, dict):
        return flatten_content_to_text(content.get("content"))
    return str(content)


def normalize_openai_content(content: Any) -> str | list[dict[str, Any]] | None:
    if content is None:
        return None
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return flatten_content_to_text(content)

    parts: list[dict[str, Any]] = []
    for item in content:
        if isinstance(item, str):
            parts.append({"type": "text", "text": item})
            continue
        if not isinstance(item, dict):
            continue
        item_type = item.get("type")
        if item_type in {"text", "input_text", "output_text"}:
            text = item.get("text")
            if isinstance(text, str):
                parts.append({"type": "text", "text": text})
        elif item_type in {"image", "input_image"}:
            image_url = item.get("image_url")
            if isinstance(image_url, str):
                parts.append({"type": "image_url", "image_url": {"url": image_url}})
            elif isinstance(image_url, dict) and image_url.get("url"):
                parts.append({"type": "image_url", "image_url": {"url": image_url["url"]}})
            else:
                source = item.get("source") or {}
                if source.get("type") == "base64":
                    media_type = source.get("media_type", "image/png")
                    data = source.get("data", "")
                    parts.append(
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:{media_type};base64,{data}"},
                        }
                    )
        elif item_type == "tool_result":
            tool_text = flatten_content_to_text(item.get("content"))
            if tool_text:
                parts.append({"type": "text", "text": tool_text})
        elif item_type == "function_call_output":
            tool_text = flatten_content_to_text(item.get("output"))
            if tool_text:
                parts.append({"type": "text", "text": tool_text})
        elif item_type in {"input_file", "file"}:
            filename = item.get("filename")
            parts.append({"type": "text", "text": f"[file:{filename or 'unknown'}]"})
    if not parts:
        return None
    if len(parts) == 1 and parts[0]["type"] == "text":
        return parts[0]["text"]
    return parts


def normalize_openai_message(message: dict[str, Any]) -> dict[str, Any]:
    role = message.get("role", "user")
    if role == "developer":
        role = "system"
    normalized: dict[str, Any] = {"role": role}
    if "content" in message:
        normalized["content"] = normalize_openai_content(message.get("content"))
    if message.get("tool_calls") is not None:
        normalized["tool_calls"] = message["tool_calls"]
    if message.get("tool_call_id") is not None:
        normalized["tool_call_id"] = message["tool_call_id"]
    elif message.get("call_id") is not None:
        normalized["tool_call_id"] = message["call_id"]
    if message.get("name") is not None:
        normalized["name"] = message["name"]
    return normalized


def anthropic_system_to_text(system: Any) -> str:
    if isinstance(system, str):
        return system
    if isinstance(system, list):
        return "\n".join(
            item.get("text", "")
            for item in system
            if isinstance(item, dict) and item.get("type") == "text"
        )
    return ""


def anthropic_user_content_to_openai_messages(content: Any) -> list[dict[str, Any]]:
    if isinstance(content, str):
        return [{"role": "user", "content": content}]
    if not isinstance(content, list):
        return [{"role": "user", "content": flatten_content_to_text(content)}]

    user_parts: list[dict[str, Any]] = []
    tool_messages: list[dict[str, Any]] = []

    for block in content:
        if not isinstance(block, dict):
            continue
        block_type = block.get("type")
        if block_type == "text":
            text = block.get("text")
            if isinstance(text, str) and text:
                user_parts.append({"type": "text", "text": text})
        elif block_type == "image":
            source = block.get("source") or {}
            if source.get("type") == "base64":
                media_type = source.get("media_type", "image/png")
                data = source.get("data", "")
                user_parts.append(
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:{media_type};base64,{data}"},
                    }
                )
        elif block_type == "tool_result":
            tool_call_id = block.get("tool_use_id") or new_id("call")
            tool_text = flatten_content_to_text(block.get("content"))
            tool_messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call_id,
                    "content": tool_text,
                }
            )

    messages: list[dict[str, Any]] = []
    if user_parts:
        if len(user_parts) == 1 and user_parts[0]["type"] == "text":
            messages.append({"role": "user", "content": user_parts[0]["text"]})
        else:
            messages.append({"role": "user", "content": user_parts})
    messages.extend(tool_messages)
    return messages


def anthropic_assistant_content_to_openai_message(content: Any) -> dict[str, Any]:
    if isinstance(content, str):
        return {"role": "assistant", "content": content}
    if not isinstance(content, list):
        return {"role": "assistant", "content": flatten_content_to_text(content)}

    text_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        block_type = block.get("type")
        if block_type == "text":
            text = block.get("text")
            if isinstance(text, str) and text:
                text_parts.append(text)
        elif block_type == "tool_use":
            tool_calls.append(
                {
                    "id": block.get("id") or new_id("call"),
                    "type": "function",
                    "function": {
                        "name": block.get("name") or "tool",
                        "arguments": json_dumps(block.get("input", {})),
                    },
                }
            )
    message: dict[str, Any] = {
        "role": "assistant",
        "content": "\n".join(text_parts) if text_parts else None,
    }
    if tool_calls:
        message["tool_calls"] = tool_calls
    return message


def anthropic_tools_to_openai_tools(tools: Any) -> list[dict[str, Any]]:
    if not isinstance(tools, list):
        return []
    converted: list[dict[str, Any]] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        converted.append(
            {
                "type": "function",
                "function": {
                    "name": tool.get("name", "tool"),
                    "description": tool.get("description") or "",
                    "parameters": tool.get("input_schema") or tool.get("parameters") or {},
                },
            }
        )
    return converted


def anthropic_tool_choice_to_openai(choice: Any) -> Any:
    if choice is None:
        return None
    if isinstance(choice, str):
        return {"auto": "auto", "any": "required", "none": "none"}.get(choice, choice)
    if not isinstance(choice, dict):
        return choice
    choice_type = choice.get("type")
    if choice_type == "auto":
        return "auto"
    if choice_type == "any":
        return "required"
    if choice_type == "none":
        return "none"
    if choice_type == "tool":
        return {
            "type": "function",
            "function": {"name": choice.get("name", "tool")},
        }
    return choice


def anthropic_request_to_openai_payload(payload: dict[str, Any]) -> dict[str, Any]:
    messages: list[dict[str, Any]] = []
    system_text = anthropic_system_to_text(payload.get("system"))
    if system_text:
        messages.append({"role": "system", "content": system_text})

    for message in payload.get("messages", []):
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        if role == "user":
            messages.extend(anthropic_user_content_to_openai_messages(message.get("content")))
        elif role == "assistant":
            messages.append(anthropic_assistant_content_to_openai_message(message.get("content")))

    body: dict[str, Any] = {
        "model": ensure_model(payload.get("model")),
        "messages": messages,
        "stream": bool(payload.get("stream")),
        "max_tokens": payload.get("max_tokens"),
        "temperature": payload.get("temperature"),
        "stop": payload.get("stop_sequences"),
    }
    tools = anthropic_tools_to_openai_tools(payload.get("tools"))
    if tools:
        body["tools"] = tools
    tool_choice = anthropic_tool_choice_to_openai(payload.get("tool_choice"))
    if tool_choice is not None:
        body["tool_choice"] = tool_choice
    return {key: value for key, value in body.items() if value is not None}


def openai_finish_reason_to_anthropic(reason: str | None) -> str | None:
    mapping = {
        "stop": "end_turn",
        "tool_calls": "tool_use",
        "function_call": "tool_use",
        "length": "max_tokens",
        "content_filter": "stop_sequence",
    }
    return mapping.get(reason or "", "end_turn" if reason else None)


def openai_response_to_anthropic(payload: dict[str, Any], requested_model: str) -> dict[str, Any]:
    choice = (payload.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    content: list[dict[str, Any]] = []

    text = message.get("content")
    if isinstance(text, str) and text:
        content.append({"type": "text", "text": text})

    for tool_call in message.get("tool_calls") or []:
        function = tool_call.get("function") or {}
        parsed_arguments = safe_json_loads(function.get("arguments"))
        content.append(
            {
                "type": "tool_use",
                "id": tool_call.get("id") or new_id("toolu"),
                "name": function.get("name") or "tool",
                "input": parsed_arguments if isinstance(parsed_arguments, dict) else {},
            }
        )

    usage = payload.get("usage") or {}
    return {
        "id": payload.get("id") or new_id("msg"),
        "type": "message",
        "role": "assistant",
        "model": payload.get("model") or requested_model,
        "content": content,
        "stop_reason": openai_finish_reason_to_anthropic(choice.get("finish_reason")),
        "stop_sequence": None,
        "usage": {
            "input_tokens": int(usage.get("prompt_tokens") or 0),
            "output_tokens": int(usage.get("completion_tokens") or 0),
        },
    }


def openai_models_to_anthropic_models(payload: dict[str, Any]) -> dict[str, Any]:
    models = payload.get("data") or []
    converted = []
    for model in models:
        if not isinstance(model, dict):
            continue
        model_id = model.get("id")
        if not model_id:
            continue
        converted.append(
            {
                "type": "model",
                "id": model_id,
                "display_name": model_id,
                "created_at": "1970-01-01T00:00:00Z",
            }
        )
    return {
        "data": converted,
        "first_id": converted[0]["id"] if converted else None,
        "last_id": converted[-1]["id"] if converted else None,
        "has_more": False,
    }


def estimate_tokens_from_text(text: str) -> int:
    if not text:
        return 0
    return max(1, math.ceil(len(text.encode("utf-8")) / 3))


def estimate_anthropic_input_tokens(payload: dict[str, Any]) -> int:
    total = 0
    total += estimate_tokens_from_text(anthropic_system_to_text(payload.get("system")))
    for message in payload.get("messages", []):
        if isinstance(message, dict):
            total += estimate_tokens_from_text(flatten_content_to_text(message.get("content")))
            total += 6
    if isinstance(payload.get("tools"), list):
        total += estimate_tokens_from_text(json_dumps(payload["tools"]))
    return total


def responses_content_to_openai_content(content: Any) -> str | list[dict[str, Any]] | None:
    return normalize_openai_content(content)


def responses_item_to_openai_messages(item: dict[str, Any]) -> list[dict[str, Any]]:
    item_type = item.get("type")
    role = item.get("role")

    if item_type == "function_call_output":
        return [
            {
                "role": "tool",
                "tool_call_id": item.get("call_id") or item.get("id") or new_id("call"),
                "content": flatten_content_to_text(item.get("output")),
            }
        ]

    if item_type == "function_call":
        return [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": item.get("call_id") or item.get("id") or new_id("call"),
                        "type": "function",
                        "function": {
                            "name": item.get("name") or "tool",
                            "arguments": item.get("arguments") or "{}",
                        },
                    }
                ],
            }
        ]

    if item_type == "reasoning":
        summary = item.get("summary")
        summary_text = flatten_content_to_text(summary)
        if summary_text:
            return [{"role": "assistant", "content": summary_text}]
        return []

    if item_type == "message" or role:
        normalized = normalize_openai_message(item)
        return [normalized]

    content = responses_content_to_openai_content(item)
    return [{"role": "user", "content": content}] if content is not None else []


def responses_top_level_input_to_messages(input_value: Any) -> list[dict[str, Any]]:
    if isinstance(input_value, str):
        return [{"role": "user", "content": input_value}]
    if not isinstance(input_value, list):
        return [{"role": "user", "content": flatten_content_to_text(input_value)}]

    messages: list[dict[str, Any]] = []
    for item in input_value:
        if isinstance(item, dict):
            messages.extend(responses_item_to_openai_messages(item))
        else:
            messages.append({"role": "user", "content": str(item)})
    return messages


def responses_tool_choice_to_openai(choice: Any) -> Any:
    if choice is None:
        return None
    if isinstance(choice, str):
        return choice
    if not isinstance(choice, dict):
        return choice
    if choice.get("type") == "function":
        return {
            "type": "function",
            "function": {"name": choice.get("name", "tool")},
        }
    if choice.get("type") == "tool":
        return {
            "type": "function",
            "function": {"name": choice.get("name", "tool")},
        }
    return choice


def responses_tools_to_openai_tools(tools: Any) -> list[dict[str, Any]]:
    if not isinstance(tools, list):
        return []
    converted: list[dict[str, Any]] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        if tool.get("type") not in {None, "function"}:
            continue
        converted.append(
            {
                "type": "function",
                "function": {
                    "name": tool.get("name", "tool"),
                    "description": tool.get("description") or "",
                    "parameters": tool.get("parameters") or tool.get("input_schema") or {},
                },
            }
        )
    return converted


def responses_request_to_openai_payload(payload: dict[str, Any]) -> dict[str, Any]:
    messages: list[dict[str, Any]] = []
    instructions = payload.get("instructions")
    if isinstance(instructions, str) and instructions:
        messages.append({"role": "system", "content": instructions})

    if isinstance(payload.get("messages"), list):
        messages.extend(normalize_openai_message(message) for message in payload["messages"])
    else:
        messages.extend(responses_top_level_input_to_messages(payload.get("input", "")))

    body: dict[str, Any] = {
        "model": ensure_model(payload.get("model")),
        "messages": messages,
        "stream": bool(payload.get("stream")),
        "max_tokens": payload.get("max_output_tokens"),
        "temperature": payload.get("temperature"),
        "parallel_tool_calls": payload.get("parallel_tool_calls"),
    }
    tools = responses_tools_to_openai_tools(payload.get("tools"))
    if tools:
        body["tools"] = tools
    tool_choice = responses_tool_choice_to_openai(payload.get("tool_choice"))
    if tool_choice is not None:
        body["tool_choice"] = tool_choice
    return {key: value for key, value in body.items() if value is not None}


def assistant_chat_message_from_openai_payload(payload: dict[str, Any]) -> dict[str, Any]:
    choice = (payload.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    assistant_message: dict[str, Any] = {
        "role": "assistant",
        "content": message.get("content"),
    }
    if message.get("tool_calls"):
        assistant_message["tool_calls"] = message["tool_calls"]
    return assistant_message


def get_responses_history(response_id: str | None) -> list[dict[str, Any]]:
    if not response_id:
        return []
    history = app.state.responses_sessions.get(response_id)
    if isinstance(history, list):
        return [dict(item) for item in history]
    return []


def store_responses_history(
    response_id: str,
    request_messages: list[dict[str, Any]],
    assistant_message: dict[str, Any],
) -> None:
    app.state.responses_sessions[response_id] = [*request_messages, assistant_message]


def openai_finish_reason_to_responses_status(reason: str | None) -> str:
    return "completed" if reason != "length" else "incomplete"


def openai_response_to_responses(payload: dict[str, Any], requested_model: str) -> dict[str, Any]:
    choice = (payload.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    output: list[dict[str, Any]] = []
    output_text = ""

    if isinstance(message.get("content"), str) and message["content"]:
        output_text = message["content"]
        output.append(
            {
                "id": new_id("msg"),
                "type": "message",
                "status": "completed",
                "role": "assistant",
                "content": [
                    {
                        "type": "output_text",
                        "text": message["content"],
                        "annotations": [],
                    }
                ],
            }
        )

    for tool_call in message.get("tool_calls") or []:
        function = tool_call.get("function") or {}
        output.append(
            {
                "id": new_id("fc"),
                "type": "function_call",
                "status": "completed",
                "call_id": tool_call.get("id") or new_id("call"),
                "name": function.get("name") or "tool",
                "arguments": function.get("arguments") or "{}",
            }
        )

    usage = payload.get("usage") or {}
    return {
        "id": payload.get("id") or new_id("resp"),
        "object": "response",
        "created_at": int(time.time()),
        "status": openai_finish_reason_to_responses_status(choice.get("finish_reason")),
        "model": payload.get("model") or requested_model,
        "output": output,
        "output_text": output_text,
        "usage": {
            "input_tokens": int(usage.get("prompt_tokens") or 0),
            "output_tokens": int(usage.get("completion_tokens") or 0),
            "total_tokens": int(usage.get("total_tokens") or 0),
        },
    }


async def anthropic_stream_from_openai(
    response: httpx.Response,
    requested_model: str,
) -> AsyncIterator[bytes]:
    text_block_index: int | None = None
    text_parts: list[str] = []
    finish_reason: str | None = None
    usage: dict[str, Any] = {}
    next_block_index = 0
    tool_states: dict[int, AnthropicToolStreamState] = {}
    started = False

    try:
        async for payload in iter_openai_sse_payloads(response):
            if not started:
                started = True
                yield anthropic_sse(
                    "message_start",
                    {
                        "type": "message_start",
                        "message": {
                            "id": new_id("msg"),
                            "type": "message",
                            "role": "assistant",
                            "model": requested_model,
                            "content": [],
                            "stop_reason": None,
                            "stop_sequence": None,
                            "usage": {"input_tokens": 0, "output_tokens": 0},
                        },
                    },
                )

            choice = (payload.get("choices") or [{}])[0]
            delta = choice.get("delta") or {}
            if payload.get("usage"):
                usage = payload["usage"]
            if choice.get("finish_reason"):
                finish_reason = openai_finish_reason_to_anthropic(choice.get("finish_reason"))

            text_delta = delta.get("content")
            if isinstance(text_delta, str) and text_delta:
                if text_block_index is None:
                    text_block_index = next_block_index
                    next_block_index += 1
                    yield anthropic_sse(
                        "content_block_start",
                        {
                            "type": "content_block_start",
                            "index": text_block_index,
                            "content_block": {"type": "text", "text": ""},
                        },
                    )
                text_parts.append(text_delta)
                yield anthropic_sse(
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": text_block_index,
                        "delta": {"type": "text_delta", "text": text_delta},
                    },
                )

            for tool_call in delta.get("tool_calls") or []:
                upstream_index = int(tool_call.get("index") or 0)
                state = tool_states.setdefault(upstream_index, AnthropicToolStreamState())
                if tool_call.get("id"):
                    state.call_id = tool_call["id"]
                function = tool_call.get("function") or {}
                if function.get("name"):
                    state.name = function["name"]
                argument_delta = function.get("arguments") or ""
                if argument_delta:
                    state.arguments_parts.append(argument_delta)
                    if state.started:
                        yield anthropic_sse(
                            "content_block_delta",
                            {
                                "type": "content_block_delta",
                                "index": state.block_index,
                                "delta": {
                                    "type": "input_json_delta",
                                    "partial_json": argument_delta,
                                },
                            },
                        )
                    else:
                        state.buffered_argument_parts.append(argument_delta)

                if not state.started and state.name:
                    state.started = True
                    state.block_index = next_block_index
                    next_block_index += 1
                    yield anthropic_sse(
                        "content_block_start",
                        {
                            "type": "content_block_start",
                            "index": state.block_index,
                            "content_block": {
                                "type": "tool_use",
                                "id": state.call_id,
                                "name": state.name,
                                "input": {},
                            },
                        },
                    )
                    for buffered_delta in state.buffered_argument_parts:
                        yield anthropic_sse(
                            "content_block_delta",
                            {
                                "type": "content_block_delta",
                                "index": state.block_index,
                                "delta": {
                                    "type": "input_json_delta",
                                    "partial_json": buffered_delta,
                                },
                            },
                        )
                    state.buffered_argument_parts.clear()

        if not started:
            yield anthropic_sse(
                "message_start",
                {
                    "type": "message_start",
                    "message": {
                        "id": new_id("msg"),
                        "type": "message",
                        "role": "assistant",
                        "model": requested_model,
                        "content": [],
                        "stop_reason": "end_turn",
                        "stop_sequence": None,
                        "usage": {"input_tokens": 0, "output_tokens": 0},
                    },
                },
            )

        started_blocks: list[tuple[int, str]] = []
        if text_block_index is not None:
            started_blocks.append((text_block_index, "text"))
        for state in tool_states.values():
            if state.started and state.block_index is not None:
                started_blocks.append((state.block_index, "tool"))

        for block_index, _block_type in sorted(started_blocks, key=lambda item: item[0]):
            yield anthropic_sse(
                "content_block_stop",
                {"type": "content_block_stop", "index": block_index},
            )

        yield anthropic_sse(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {
                    "stop_reason": finish_reason or "end_turn",
                    "stop_sequence": None,
                },
                "usage": {"output_tokens": int((usage.get("completion_tokens") or 0))},
            },
        )
        yield anthropic_sse("message_stop", {"type": "message_stop"})
    finally:
        await response.aclose()


async def responses_stream_from_openai(
    response: httpx.Response,
    requested_model: str,
    request_messages: list[dict[str, Any]],
) -> AsyncIterator[bytes]:
    response_id = new_id("resp")
    created_at = int(time.time())
    sequence = 1
    text_parts: list[str] = []
    message_item_id = new_id("msg")
    message_output_index: int | None = None
    message_started = False
    text_content_started = False
    finish_reason: str | None = None
    usage: dict[str, Any] = {}
    tool_states: dict[int, ResponsesToolStreamState] = {}
    next_output_index = 0

    def next_sequence() -> int:
        nonlocal sequence
        current = sequence
        sequence += 1
        return current

    def current_response(status: str, output: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "id": response_id,
            "object": "response",
            "created_at": created_at,
            "status": status,
            "model": requested_model,
            "output": output,
            "output_text": "".join(text_parts),
        }

    try:
        yield openai_sse(
            {
                "type": "response.created",
                "response": current_response("in_progress", []),
                "sequence_number": next_sequence(),
            }
        )

        async for payload in iter_openai_sse_payloads(response):
            choice = (payload.get("choices") or [{}])[0]
            delta = choice.get("delta") or {}
            if payload.get("usage"):
                usage = payload["usage"]
            if choice.get("finish_reason"):
                finish_reason = choice.get("finish_reason")

            text_delta = delta.get("content")
            if isinstance(text_delta, str) and text_delta:
                if not message_started:
                    message_started = True
                    message_output_index = next_output_index
                    next_output_index += 1
                    yield openai_sse(
                        {
                            "type": "response.output_item.added",
                            "output_index": message_output_index,
                            "item": {
                                "id": message_item_id,
                                "status": "in_progress",
                                "type": "message",
                                "role": "assistant",
                                "content": [],
                            },
                            "sequence_number": next_sequence(),
                        }
                    )
                if not text_content_started:
                    text_content_started = True
                    yield openai_sse(
                        {
                            "type": "response.content_part.added",
                            "item_id": message_item_id,
                            "output_index": message_output_index,
                            "content_index": 0,
                            "part": {
                                "type": "output_text",
                                "text": "",
                                "annotations": [],
                            },
                            "sequence_number": next_sequence(),
                        }
                    )
                text_parts.append(text_delta)
                yield openai_sse(
                    {
                        "type": "response.output_text.delta",
                        "item_id": message_item_id,
                        "output_index": message_output_index,
                        "content_index": 0,
                        "delta": text_delta,
                        "sequence_number": next_sequence(),
                    }
                )

            for tool_call in delta.get("tool_calls") or []:
                upstream_index = int(tool_call.get("index") or 0)
                state = tool_states.setdefault(upstream_index, ResponsesToolStreamState())
                if tool_call.get("id"):
                    state.call_id = tool_call["id"]
                function = tool_call.get("function") or {}
                if function.get("name"):
                    state.name = function["name"]
                argument_delta = function.get("arguments") or ""
                if argument_delta:
                    state.arguments_parts.append(argument_delta)
                    if state.started:
                        yield openai_sse(
                            {
                                "type": "response.function_call_arguments.delta",
                                "item_id": state.item_id,
                                "output_index": state.output_index,
                                "delta": argument_delta,
                                "sequence_number": next_sequence(),
                            }
                        )
                    else:
                        state.buffered_argument_parts.append(argument_delta)

                if not state.started and state.name:
                    state.started = True
                    state.output_index = next_output_index
                    next_output_index += 1
                    yield openai_sse(
                        {
                            "type": "response.output_item.added",
                            "output_index": state.output_index,
                            "item": {
                                "id": state.item_id,
                                "status": "in_progress",
                                "type": "function_call",
                                "call_id": state.call_id,
                                "name": state.name,
                                "arguments": "",
                            },
                            "sequence_number": next_sequence(),
                        }
                    )
                    for buffered_delta in state.buffered_argument_parts:
                        yield openai_sse(
                            {
                                "type": "response.function_call_arguments.delta",
                                "item_id": state.item_id,
                                "output_index": state.output_index,
                                "delta": buffered_delta,
                                "sequence_number": next_sequence(),
                            }
                        )
                    state.buffered_argument_parts.clear()

        output_items: list[tuple[int, dict[str, Any]]] = []
        assistant_message: dict[str, Any] = {
            "role": "assistant",
            "content": None,
        }
        if text_parts or not tool_states:
            if message_output_index is None:
                message_output_index = next_output_index
                next_output_index += 1
            assistant_message["content"] = "".join(text_parts)
            message_item = {
                "id": message_item_id,
                "status": "completed",
                "type": "message",
                "role": "assistant",
                "content": [
                    {
                        "type": "output_text",
                        "text": "".join(text_parts),
                        "annotations": [],
                    }
                ],
            }
            if text_content_started:
                yield openai_sse(
                    {
                        "type": "response.output_text.done",
                        "item_id": message_item_id,
                        "output_index": message_output_index,
                        "content_index": 0,
                        "text": "".join(text_parts),
                        "sequence_number": next_sequence(),
                    }
                )
                yield openai_sse(
                    {
                        "type": "response.content_part.done",
                        "item_id": message_item_id,
                        "output_index": message_output_index,
                        "content_index": 0,
                        "part": {
                            "type": "output_text",
                            "text": "".join(text_parts),
                            "annotations": [],
                        },
                        "sequence_number": next_sequence(),
                    }
                )
            yield openai_sse(
                {
                    "type": "response.output_item.done",
                    "output_index": message_output_index,
                    "item": message_item,
                    "sequence_number": next_sequence(),
                }
            )
            output_items.append((message_output_index, message_item))

        for state in tool_states.values():
            if not state.started or state.output_index is None:
                continue
            assistant_message.setdefault("tool_calls", [])
            assistant_message["tool_calls"].append(
                {
                    "id": state.call_id,
                    "type": "function",
                    "function": {
                        "name": state.name or "tool",
                        "arguments": "".join(state.arguments_parts),
                    },
                }
            )
            item = {
                "id": state.item_id,
                "status": "completed",
                "type": "function_call",
                "call_id": state.call_id,
                "name": state.name or "tool",
                "arguments": "".join(state.arguments_parts),
            }
            yield openai_sse(
                {
                    "type": "response.function_call_arguments.done",
                    "item_id": state.item_id,
                    "output_index": state.output_index,
                    "name": state.name or "tool",
                    "arguments": "".join(state.arguments_parts),
                    "sequence_number": next_sequence(),
                }
            )
            yield openai_sse(
                {
                    "type": "response.output_item.done",
                    "output_index": state.output_index,
                    "item": item,
                    "sequence_number": next_sequence(),
                }
            )
            output_items.append((state.output_index, item))

        ordered_output = [item for _index, item in sorted(output_items, key=lambda pair: pair[0])]
        completed_response = current_response(
            openai_finish_reason_to_responses_status(finish_reason),
            ordered_output,
        )
        completed_response["usage"] = {
            "input_tokens": int(usage.get("prompt_tokens") or 0),
            "output_tokens": int(usage.get("completion_tokens") or 0),
            "total_tokens": int(usage.get("total_tokens") or 0),
        }
        yield openai_sse(
            {
                "type": "response.completed",
                "response": completed_response,
                "sequence_number": next_sequence(),
            }
        )
        store_responses_history(response_id, request_messages, assistant_message)
    finally:
        await response.aclose()


async def proxy_streaming_request(
    request: Request,
    *,
    upstream_path: str,
    upstream_body: dict[str, Any],
    stream_transformer: str,
    request_messages: list[dict[str, Any]] | None = None,
) -> Response:
    api_key = resolve_upstream_api_key(request)
    headers = signed_tocodex_headers(
        upstream_path,
        api_key,
        task_id=request.headers.get("x-roo-task-id"),
    )
    client: httpx.AsyncClient = request.app.state.http
    upstream_request = client.build_request(
        "POST",
        upstream_url(upstream_path),
        json=upstream_body,
        headers=headers,
    )
    upstream_response = await client.send(upstream_request, stream=True)
    if upstream_response.status_code >= 400:
        body = await upstream_response.aread()
        await upstream_response.aclose()
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = body.decode("utf-8", errors="replace")
        if stream_transformer == "anthropic":
            return JSONResponse(
                status_code=upstream_response.status_code,
                content=anthropic_error_payload(upstream_response.status_code, payload),
                headers={"anthropic-version": SETTINGS.anthropic_version},
            )
        return Response(
            content=body,
            status_code=upstream_response.status_code,
            media_type=media_type_from_headers(upstream_response.headers, "application/json"),
        )

    if stream_transformer == "raw":
        return StreamingResponse(
            stream_raw_upstream(upstream_response),
            media_type="text/event-stream",
        )
    if stream_transformer == "anthropic":
        return StreamingResponse(
            anthropic_stream_from_openai(upstream_response, upstream_body["model"]),
            media_type="text/event-stream",
            headers={"anthropic-version": SETTINGS.anthropic_version},
        )
    if stream_transformer == "responses":
        return StreamingResponse(
            responses_stream_from_openai(
                upstream_response,
                upstream_body["model"],
                request_messages or upstream_body.get("messages", []),
            ),
            media_type="text/event-stream",
        )
    raise HTTPException(status_code=500, detail="Unknown stream transformer.")


async def proxy_json_request(
    request: Request,
    *,
    upstream_path: str,
    upstream_body: dict[str, Any],
) -> httpx.Response:
    api_key = resolve_upstream_api_key(request)
    headers = signed_tocodex_headers(
        upstream_path,
        api_key,
        task_id=request.headers.get("x-roo-task-id"),
    )
    client: httpx.AsyncClient = request.app.state.http
    return await client.post(
        upstream_url(upstream_path),
        headers=headers,
        json=upstream_body,
    )


@app.get("/")
async def index() -> dict[str, Any]:
    return {
        "service": "tocodex-proxy",
        "openai_base_url": "/v1",
        "anthropic_base_url": "/anthropic",
        "upstream_base_url": SETTINGS.tocodex_base_url,
    }


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"ok": True, "upstream_base_url": SETTINGS.tocodex_base_url}


@app.get("/v1/models")
@app.get("/openai/v1/models")
async def openai_models(request: Request) -> Response:
    try:
        api_key = resolve_upstream_api_key(request)
        client: httpx.AsyncClient = request.app.state.http
        response = await client.get(
            upstream_url("/v1/models"),
            headers=tocodex_base_headers(api_key),
        )
        return await make_upstream_response(response)
    except httpx.HTTPError as exc:
        LOG.exception("Upstream /v1/models request failed")
        return openai_bad_gateway_response(f"ToCodex upstream error: {exc}")


@app.get("/anthropic/v1/models")
async def anthropic_models(request: Request) -> Response:
    try:
        api_key = resolve_upstream_api_key(request)
        client: httpx.AsyncClient = request.app.state.http
        response = await client.get(
            upstream_url("/v1/models"),
            headers=tocodex_base_headers(api_key),
        )
        body = await response.aread()
        if response.status_code >= 400:
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                payload = body.decode("utf-8", errors="replace")
            return JSONResponse(
                status_code=response.status_code,
                content=anthropic_error_payload(response.status_code, payload),
                headers={"anthropic-version": SETTINGS.anthropic_version},
            )
        payload = json.loads(body)
        return JSONResponse(
            status_code=200,
            content=openai_models_to_anthropic_models(payload),
            headers={"anthropic-version": SETTINGS.anthropic_version},
        )
    except httpx.HTTPError as exc:
        LOG.exception("Upstream anthropic models request failed")
        return JSONResponse(
            status_code=502,
            content=anthropic_error_payload(502, f"ToCodex upstream error: {exc}"),
            headers={"anthropic-version": SETTINGS.anthropic_version},
        )


@app.post("/v1/chat/completions")
@app.post("/openai/v1/chat/completions")
async def openai_chat_completions(request: Request) -> Response:
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="JSON body must be an object.")
        payload["model"] = ensure_model(payload.get("model"))
        if payload.get("stream"):
            return await proxy_streaming_request(
                request,
                upstream_path="/v1/chat/completions",
                upstream_body=payload,
                stream_transformer="raw",
            )
        response = await proxy_json_request(
            request,
            upstream_path="/v1/chat/completions",
            upstream_body=payload,
        )
        return await make_upstream_response(response)
    except httpx.HTTPError as exc:
        LOG.exception("Upstream chat.completions request failed")
        return openai_bad_gateway_response(f"ToCodex upstream error: {exc}")


@app.post("/v1/responses")
@app.post("/openai/v1/responses")
async def openai_responses(request: Request) -> Response:
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="JSON body must be an object.")

        prior_messages = get_responses_history(payload.get("previous_response_id"))
        openai_payload = responses_request_to_openai_payload(payload)
        if prior_messages:
            openai_payload["messages"] = [*prior_messages, *openai_payload["messages"]]

        if openai_payload.get("stream"):
            return await proxy_streaming_request(
                request,
                upstream_path="/v1/chat/completions",
                upstream_body=openai_payload,
                stream_transformer="responses",
                request_messages=openai_payload["messages"],
            )

        response = await proxy_json_request(
            request,
            upstream_path="/v1/chat/completions",
            upstream_body=openai_payload,
        )
        body = await response.aread()
        if response.status_code >= 400:
            return Response(
                content=body,
                status_code=response.status_code,
                media_type=media_type_from_headers(response.headers, "application/json"),
            )
        upstream_payload = json.loads(body)
        response_payload = openai_response_to_responses(upstream_payload, openai_payload["model"])
        store_responses_history(
            response_payload["id"],
            openai_payload["messages"],
            assistant_chat_message_from_openai_payload(upstream_payload),
        )
        return JSONResponse(
            status_code=200,
            content=response_payload,
        )
    except httpx.HTTPError as exc:
        LOG.exception("Upstream responses request failed")
        return openai_bad_gateway_response(f"ToCodex upstream error: {exc}")


@app.post("/anthropic/v1/messages")
async def anthropic_messages(request: Request) -> Response:
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="JSON body must be an object.")

        openai_payload = anthropic_request_to_openai_payload(payload)
        if openai_payload.get("stream"):
            return await proxy_streaming_request(
                request,
                upstream_path="/v1/chat/completions",
                upstream_body=openai_payload,
                stream_transformer="anthropic",
            )

        response = await proxy_json_request(
            request,
            upstream_path="/v1/chat/completions",
            upstream_body=openai_payload,
        )
        body = await response.aread()
        if response.status_code >= 400:
            try:
                upstream_payload = json.loads(body)
            except json.JSONDecodeError:
                upstream_payload = body.decode("utf-8", errors="replace")
            return JSONResponse(
                status_code=response.status_code,
                content=anthropic_error_payload(response.status_code, upstream_payload),
                headers={"anthropic-version": SETTINGS.anthropic_version},
            )
        upstream_payload = json.loads(body)
        return JSONResponse(
            status_code=200,
            content=openai_response_to_anthropic(upstream_payload, openai_payload["model"]),
            headers={"anthropic-version": SETTINGS.anthropic_version},
        )
    except httpx.HTTPError as exc:
        LOG.exception("Upstream anthropic messages request failed")
        return JSONResponse(
            status_code=502,
            content=anthropic_error_payload(502, f"ToCodex upstream error: {exc}"),
            headers={"anthropic-version": SETTINGS.anthropic_version},
        )


@app.post("/anthropic/v1/messages/count_tokens")
async def anthropic_count_tokens(request: Request) -> Response:
    payload = await request.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object.")
    return JSONResponse(
        status_code=200,
        content={"input_tokens": estimate_anthropic_input_tokens(payload)},
        headers={"anthropic-version": SETTINGS.anthropic_version},
    )
