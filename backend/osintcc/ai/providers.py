"""Provider-neutral inference interface (spec 23.1.3).

Any model string is accepted: there is no curated allowlist and no cloud moderation dependency. Model choice never
affects authorization: the policy engine, scope checks and confirmation gates live outside this package and are not
consultable or overridable by model output.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

LOOPBACK_NAMES = {"localhost"}


class ProviderError(Exception):
    pass


class ProviderUnavailable(ProviderError):
    pass


@dataclass
class Message:
    role: str  # system | user | assistant
    content: str


def is_loopback_url(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Provider:
    provider_type = "base"
    local = True

    def __init__(self, model: str):
        self.model = model

    async def health(self) -> dict:
        raise NotImplementedError

    async def list_models(self) -> list[str]:
        raise NotImplementedError

    async def chat(self, messages: list[Message], max_tokens: int = 1200, temperature: float = 0.1) -> str:
        raise NotImplementedError


class OllamaProvider(Provider):
    provider_type = "ollama"

    def __init__(self, model: str, base_url: str = "http://127.0.0.1:11434", transport: httpx.AsyncBaseTransport | None = None):
        super().__init__(model)
        if not is_loopback_url(base_url):
            raise ProviderError("local Ollama profiles must use a loopback address")
        self.base, self.transport = base_url.rstrip("/"), transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport, timeout=900, trust_env=False)  # CPU-only machines can be slow

    async def health(self) -> dict:
        try:
            async with self._client() as c:
                r = await c.get(f"{self.base}/api/tags", timeout=5)
            models = [m["name"] for m in r.json().get("models", [])]
            return {"status": "healthy", "models": models, "model_present": self.model in models}
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            return {"status": "unavailable", "detail": f"Ollama not reachable at {self.base} ({type(exc).__name__})"}

    async def list_models(self) -> list[str]:
        return (await self.health()).get("models", [])

    async def chat(self, messages, max_tokens=1200, temperature=0.1) -> str:
        body = {"model": self.model, "stream": False, "think": False, "messages": [m.__dict__ for m in messages],
                "options": {"num_predict": max_tokens, "temperature": temperature}}
        try:
            async with self._client() as c:
                r = await c.post(f"{self.base}/api/chat", json=body)
            if r.status_code != 200:
                raise ProviderUnavailable(f"Ollama HTTP {r.status_code}")
            return re.sub(r"<think>.*?</think>\s*", "", r.json()["message"]["content"], flags=re.DOTALL)
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            raise ProviderUnavailable(f"Ollama call failed ({type(exc).__name__})") from exc


class OpenAICompatProvider(Provider):
    """llama.cpp server (loopback) or any OpenAI-compatible endpoint (cloud: opt-in, per-case consent)."""
    provider_type = "openai_compat"

    def __init__(self, model: str, base_url: str, api_key: str | None = None, local: bool = True,
                 transport: httpx.AsyncBaseTransport | None = None):
        super().__init__(model)
        self.local = local
        if local and not is_loopback_url(base_url):
            raise ProviderError("a local profile must use a loopback address; mark it as cloud to use a remote endpoint")
        if not local and not base_url.startswith("https://"):
            raise ProviderError("cloud endpoints must use https")
        self.base, self.key, self.transport = base_url.rstrip("/"), api_key, transport

    @property
    def host(self) -> str:
        return urlsplit(self.base).hostname or ""

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport, timeout=120, trust_env=False)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.key}"} if self.key else {}

    async def health(self) -> dict:
        try:
            async with self._client() as c:
                r = await c.get(f"{self.base}/v1/models", headers=self._headers(), timeout=8)
            if r.status_code in (401, 403):
                return {"status": "requires_key", "detail": "the endpoint rejected the credentials"}
            return {"status": "healthy", "models": [m["id"] for m in r.json().get("data", [])]}
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            return {"status": "unavailable", "detail": f"endpoint not reachable ({type(exc).__name__})"}

    async def list_models(self) -> list[str]:
        return (await self.health()).get("models", [])

    async def chat(self, messages, max_tokens=1200, temperature=0.1) -> str:
        body = {"model": self.model, "messages": [m.__dict__ for m in messages], "max_tokens": max_tokens, "temperature": temperature}
        try:
            async with self._client() as c:
                r = await c.post(f"{self.base}/v1/chat/completions", json=body, headers=self._headers())
            if r.status_code != 200:
                raise ProviderUnavailable(f"endpoint HTTP {r.status_code}")
            return r.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, ValueError, KeyError, IndexError) as exc:
            raise ProviderUnavailable(f"call failed ({type(exc).__name__})") from exc


class FixtureProvider(Provider):
    """Deterministic stand-in for tests and demos: no model, no network."""
    provider_type = "fixture"

    def __init__(self, model: str = "fixture-1", script: Callable[[list[Message]], str] | None = None):
        super().__init__(model)
        self.script = script
        self.calls: list[list[Message]] = []

    async def health(self) -> dict:
        return {"status": "healthy", "models": [self.model], "detail": "deterministic fixture model"}

    async def list_models(self) -> list[str]:
        return [self.model]

    async def chat(self, messages, max_tokens=1200, temperature=0.1) -> str:
        self.calls.append(messages)
        if self.script:
            return self.script(messages)
        import re
        ids = re.findall(r'evidence="([0-9a-f-]{36})"', messages[-1].content)[:2]
        return json.dumps({"verified_evidence": [{"statement": "Retrieved records mention the case subject.", "evidence_ids": ids}] if ids else [],
                           "inferences": ["These records are consistent with routine registration data."],
                           "contradictions": [], "unknowns": ["Nothing here establishes who operates the asset."],
                           "next_steps": ["Review the cited evidence."], "proposed_actions": []})
