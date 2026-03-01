"""
OpenAI-compatible provider for hcaptcha-challenger.

Implements the ChatProvider protocol defined in hcaptcha_challenger,
allowing any OpenAI v1/chat/completions compatible API to solve hCaptcha challenges.

Environment variable:
    HCAPTCHA_OPENAI:  Comma-separated string in one of two formats:
        - "api_key,model"                 (uses default https://api.openai.com/v1)
        - "api_key,base_url,model"        (custom endpoint)
    Examples:
        HCAPTCHA_OPENAI=sk-xxx,gpt-5.2
        HCAPTCHA_OPENAI=sk-xxx,https://your-proxy.com/v1,gpt-5.2
"""

import asyncio
import base64
import json
import os
import re
from pathlib import Path
from typing import List, Type, TypeVar

import httpx
from pydantic import BaseModel

ResponseT = TypeVar("ResponseT", bound=BaseModel)

_DEFAULT_BASE_URL = "https://api.openai.com/v1"

# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

def get_openai_config() -> dict | None:
    """Parse ``HCAPTCHA_OPENAI`` from env var or ``.env`` file.

    Returns a dict with api_key / base_url / model, or None if not configured.
    """
    raw = (os.getenv("HCAPTCHA_OPENAI") or "").strip()

    # Also try reading from .env file if not in system env
    if not raw:
        for env_path in (Path(".env"), Path(__file__).resolve().parent.parent / ".env"):
            if env_path.is_file():
                try:
                    for line in env_path.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if line.startswith("#") or "=" not in line:
                            continue
                        key, _, val = line.partition("=")
                        if key.strip() == "HCAPTCHA_OPENAI":
                            raw = val.strip().strip("'\"")
                            break
                except Exception:
                    pass
            if raw:
                break

    if not raw:
        return None

    parts = [p.strip() for p in raw.split(",")]

    if len(parts) == 2:
        api_key, model = parts
        base_url = _DEFAULT_BASE_URL
    elif len(parts) == 3:
        api_key, base_url, model = parts
    else:
        return None

    if not api_key or not model:
        return None

    return {"api_key": api_key, "base_url": base_url.rstrip("/"), "model": model}


# ---------------------------------------------------------------------------
# OpenAI Provider
# ---------------------------------------------------------------------------

class OpenAIProvider:
    """OpenAI v1/chat/completions provider for hcaptcha-challenger.

    Implements the ``ChatProvider`` protocol so it can be used as a drop-in
    replacement for ``GeminiProvider`` inside any ``Reasoner`` subclass.
    """

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str = "https://api.openai.com/v1",
    ):
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._response: dict | None = None

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _image_to_base64_url(image_path: Path) -> str:
        """Convert a local image to a ``data:`` URI usable by the vision API."""
        raw = image_path.read_bytes()
        b64 = base64.b64encode(raw).decode()
        mime_map = {
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".webp": "image/webp",
        }
        mime = mime_map.get(image_path.suffix.lower(), "image/png")
        return f"data:{mime};base64,{b64}"

    @staticmethod
    def _schema_to_prompt(schema_cls: Type[BaseModel]) -> str:
        """Return a compact JSON Schema string suitable for a system prompt."""
        return json.dumps(schema_cls.model_json_schema(), ensure_ascii=False)

    # -- ChatProvider protocol -----------------------------------------------

    async def generate_with_images(
        self,
        *,
        images: List[Path],
        response_schema: Type[ResponseT],
        user_prompt: str | None = None,
        description: str | None = None,
        **kwargs,
    ) -> ResponseT:
        """Call the OpenAI chat/completions endpoint with vision.

        Satisfies the ``ChatProvider`` protocol required by
        ``hcaptcha_challenger.tools.internal.base.Reasoner``.
        """

        # ---------- build messages ----------
        messages: list[dict] = []

        # System message: description + schema guidance
        sys_parts: list[str] = []
        if description:
            sys_parts.append(description)
        sys_parts.append(
            "You MUST respond with a single valid JSON object matching this schema:\n"
            f"{self._schema_to_prompt(response_schema)}\n"
            "Do NOT include any markdown fences, explanation, or text outside the JSON."
        )
        messages.append({"role": "system", "content": "\n\n".join(sys_parts)})

        # User message: images + optional text
        content: list[dict] = []
        for img in images:
            if img and Path(img).exists():
                content.append({
                    "type": "image_url",
                    "image_url": {
                        "url": self._image_to_base64_url(Path(img)),
                        "detail": "high",
                    },
                })
        if user_prompt:
            content.append({"type": "text", "text": user_prompt})
        if not content:
            content.append({"type": "text", "text": "Please analyze the image(s)."})
        messages.append({"role": "user", "content": content})

        # ---------- call API with retry ----------
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                data = await self._call_api(messages)
                self._response = data

                text = data["choices"][0]["message"]["content"]
                parsed = self._extract_json(text)
                return response_schema(**parsed)
            except (httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException) as exc:
                last_error = exc
                status = getattr(getattr(exc, "response", None), "status_code", 0)
                # retry on 429 / 5xx / network errors
                if status and status not in (429, 500, 502, 503, 504):
                    raise
                wait = 3 * (attempt + 1)
                print(f"⚠️ OpenAI request failed (attempt {attempt+1}/3), retrying in {wait}s: {exc}")
                await asyncio.sleep(wait)
            except Exception:
                raise

        raise RuntimeError(f"OpenAI request failed after 3 attempts: {last_error}")

    async def _call_api(self, messages: list[dict]) -> dict:
        """Perform the actual HTTP request."""
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload: dict = {
            "model": self._model,
            "messages": messages,
            "max_tokens": 4096,
        }
        # Try using json_object response_format for better JSON compliance
        payload["response_format"] = {"type": "json_object"}

        async with httpx.AsyncClient(timeout=90.0) as client:
            resp = await client.post(
                f"{self._base_url}/chat/completions",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    def _extract_json(text: str) -> dict:
        """Parse JSON from the model response, handling various formats."""
        text = text.strip()

        # 1) Direct JSON parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 2) Fenced code block
        m = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if m:
            try:
                return json.loads(m.group(1).strip())
            except json.JSONDecodeError:
                pass

        # 3) Find first { ... } block
        depth = 0
        start = -1
        for i, ch in enumerate(text):
            if ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and start >= 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        start = -1

        raise ValueError(f"Cannot extract JSON from response: {text[:500]}")

    def cache_response(self, path: Path) -> None:
        """Cache the last raw API response to a file."""
        if not self._response:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(self._response, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Monkey-patch helper
# ---------------------------------------------------------------------------

def patch_agent_with_openai(agent) -> bool:
    """Replace all Gemini providers inside an ``AgentV`` with ``OpenAIProvider``.

    Call this right after creating the ``AgentV`` instance:

        agent = AgentV(page=page, agent_config=config)
        patch_agent_with_openai(agent)

    Returns True if patching was applied, False if OpenAI config is missing.
    """
    cfg = get_openai_config()
    if not cfg:
        return False

    provider = OpenAIProvider(
        api_key=cfg["api_key"],
        model=cfg["model"],
        base_url=cfg["base_url"],
    )

    arm = agent.robotic_arm
    # Replace the provider in every reasoner
    for attr in (
        "_challenge_router",
        "_image_classifier",
        "_spatial_path_reasoner",
        "_spatial_point_reasoner",
    ):
        reasoner = getattr(arm, attr, None)
        if reasoner is not None:
            reasoner._provider = provider

    print(
        f"ℹ️ hCaptcha: Using OpenAI-compatible provider "
        f"(model={cfg['model']})"
    )
    return True
