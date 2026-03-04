# -*- coding: utf-8 -*-
"""
hcaptcha-challenger 运行时补丁：支持 OpenAI 兼容接口。

所有修改通过 monkey-patch 在运行时注入，不修改 site-packages。
调用 apply_patches() 即可完成全部适配。
"""
import base64
import json
import os
import re
from pathlib import Path
from typing import List, Type, TypeVar

from loguru import logger
from pydantic import BaseModel
from tenacity import retry, stop_after_attempt, wait_fixed

ResponseT = TypeVar("ResponseT", bound=BaseModel)

_PATCHES_APPLIED = False


# ============================================================
# OpenAIProvider
# ============================================================

def _image_to_data_url(image_path: Path) -> str:
	suffix = image_path.suffix.lower()
	mime_map = {
		".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
		".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
	}
	mime_type = mime_map.get(suffix, "image/png")
	b64 = base64.b64encode(image_path.read_bytes()).decode("utf-8")
	return f"data:{mime_type};base64,{b64}"


def _strip_think_tags(text: str) -> str:
	return re.sub(r"<think>[\s\S]*?</think>", "", text).strip()


def _extract_json(text: str, schema_cls: Type[ResponseT]) -> ResponseT:
	text = _strip_think_tags(text)
	last_validation_error = None

	def _try_parse(raw: str) -> ResponseT | None:
		nonlocal last_validation_error
		try:
			return schema_cls(**json.loads(raw))
		except json.JSONDecodeError:
			return None
		except (TypeError, ValueError) as e:
			last_validation_error = e
			return None

	result = _try_parse(text)
	if result is not None:
		return result

	for match in re.findall(r"```(?:json)?\s*([\s\S]*?)```", text):
		result = _try_parse(match.strip())
		if result is not None:
			return result

	brace_start = text.find("{")
	brace_end = text.rfind("}")
	if brace_start != -1 and brace_end > brace_start:
		result = _try_parse(text[brace_start: brace_end + 1])
		if result is not None:
			return result

	if last_validation_error:
		raise ValueError(
			f"JSON parsed OK but schema validation failed: {last_validation_error}\n"
			f"Expected schema: {schema_cls.__name__}\nResponse: {text[:300]}"
		)
	raise ValueError(f"Failed to extract JSON from response: {text[:500]}")


def _build_json_schema_hint(schema_cls: Type[BaseModel]) -> str:
	schema = schema_cls.model_json_schema()
	defs = schema.get("$defs", schema.get("definitions", {}))

	def _resolve_example(prop: dict) -> object:
		if "$ref" in prop:
			ref_name = prop["$ref"].rsplit("/", 1)[-1]
			return _resolve_example(defs[ref_name]) if ref_name in defs else {}
		if "allOf" in prop:
			for sub in prop["allOf"]:
				if "$ref" in sub:
					return _resolve_example(sub)
			return {}
		if "enum" in prop:
			return prop["enum"][0] if prop["enum"] else "string"
		prop_type = prop.get("type", "string")
		if prop_type == "array":
			return [_resolve_example(prop.get("items", {}))]
		if prop_type == "object" and "properties" in prop:
			return {k: _resolve_example(v) for k, v in prop["properties"].items()}
		if "properties" in prop:
			return {k: _resolve_example(v) for k, v in prop["properties"].items()}
		return {"string": "string", "integer": 0, "number": 0.0, "boolean": True}.get(prop_type, "value")

	example = _resolve_example(schema)
	return (
		"\n\nIMPORTANT: Respond with ONLY a valid JSON object, NO explanations, NO markdown, NO thinking process. "
		"Output the raw JSON directly matching this exact structure:\n"
		f"{json.dumps(example, indent=2, ensure_ascii=False)}"
	)


class OpenAIProvider:
	"""OpenAI 兼容 Provider，用 httpx 直接调 v1/chat/completions。"""

	def __init__(self, api_key: str, base_url: str, model: str):
		self._api_key = api_key
		self._base_url = base_url.rstrip("/")
		self._model = model
		self._last_response: dict | None = None

	@retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
	async def generate_with_images(
		self,
		*,
		images: List[Path],
		response_schema: Type[ResponseT],
		user_prompt: str | None = None,
		description: str | None = None,
		**kwargs,
	) -> ResponseT:
		import httpx

		content_parts: list[dict] = []
		for img_path in [img for img in images if img and Path(img).exists()]:
			data_url = _image_to_data_url(Path(img_path))
			content_parts.append({"type": "image_url", "image_url": {"url": data_url, "detail": "high"}})

		text = (user_prompt or "") + _build_json_schema_hint(response_schema)
		content_parts.append({"type": "text", "text": text})

		messages: list[dict] = []
		if description:
			messages.append({"role": "system", "content": description})
		messages.append({"role": "user", "content": content_parts})

		payload = {"model": self._model, "messages": messages, "temperature": 0.0, "max_tokens": 2048}
		url = f"{self._base_url}/chat/completions"
		headers = {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}

		logger.debug(f"OpenAIProvider: calling model={self._model}")

		async with httpx.AsyncClient(timeout=120.0) as client:
			resp = await client.post(url, json=payload, headers=headers)
			resp.raise_for_status()
			data = resp.json()

		self._last_response = data
		choices = data.get("choices", [])
		if not choices:
			raise ValueError(f"No choices in response: {data}")
		assistant_content = choices[0].get("message", {}).get("content", "")
		if not assistant_content:
			raise ValueError(f"Empty assistant content in response: {data}")

		logger.debug(f"OpenAIProvider: raw response length={len(assistant_content)}")
		return _extract_json(assistant_content, response_schema)

	def cache_response(self, path: Path) -> None:
		if not self._last_response:
			return
		try:
			path.parent.mkdir(parents=True, exist_ok=True)
			path.write_text(json.dumps(self._last_response, indent=2, ensure_ascii=False), encoding="utf-8")
		except Exception as e:
			logger.warning(f"Failed to cache response: {e}")


# ============================================================
# Monkey-patches
# ============================================================

def apply_patches() -> None:
	"""运行时注入所有补丁，幂等。"""
	global _PATCHES_APPLIED
	if _PATCHES_APPLIED:
		return

	try:
		from hcaptcha_challenger.agent import challenger as ch_mod
		_patch_robotic_arm(ch_mod)
		_PATCHES_APPLIED = True
		logger.info("hcaptcha_patch: RoboticArm patched for OpenAI provider")
	except Exception as e:
		logger.warning(f"hcaptcha_patch: failed to apply patches: {e}")


def ensure_env_for_agent_config() -> None:
	"""在创建 AgentConfig 之前调用：确保环境变量满足 validator 要求。

	策略：如果配置了 OpenAI 但没有 GEMINI_API_KEY，
	设置一个 placeholder 让原始 validator 通过。
	"""
	openai_key = os.environ.get("HCAPTCHA_OPENAI_API_KEY", "")
	openai_combined = os.environ.get("HCAPTCHA_OPENAI", "")
	gemini_key = os.environ.get("GEMINI_API_KEY", "")

	if (openai_key or openai_combined) and not gemini_key:
		os.environ["GEMINI_API_KEY"] = "placeholder-using-openai-provider"


def _patch_robotic_arm(ch_mod) -> None:
	"""替换 RoboticArm.__init__，注入 OpenAIProvider。"""
	RoboticArm = ch_mod.RoboticArm
	_orig_init = RoboticArm.__init__

	def _patched_init(self, page, config):
		_orig_init(self, page, config)

		api_key = os.environ.get("HCAPTCHA_OPENAI_API_KEY", "")
		base_url = os.environ.get("HCAPTCHA_OPENAI_BASE_URL", "")
		model = os.environ.get("HCAPTCHA_OPENAI_MODEL", "")

		if api_key and base_url and model:
			provider = OpenAIProvider(api_key=api_key, base_url=base_url, model=model)
			logger.info(f"hcaptcha_patch: injecting OpenAIProvider (model={model})")
			for attr in ['_challenge_router', '_image_classifier', '_spatial_path_reasoner', '_spatial_point_reasoner']:
				tool = getattr(self, attr, None)
				if tool is not None:
					tool._provider = provider

	RoboticArm.__init__ = _patched_init
