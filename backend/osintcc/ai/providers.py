"""Provider-neutral inference interface (spec 23.1.3).

Any model string is accepted: there is no curated allowlist and no cloud moderation dependency. Model choice never
affects authorization: the policy engine, scope checks and confirmation gates live outside this package and are not
consultable or overridable by model output.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import AsyncIterator, Callable
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

    async def chat_stream(self, messages: list[Message], max_tokens: int = 1200, temperature: float = 0.1) -> AsyncIterator[str]:
        """Yield the answer in pieces as the model produces them. The default yields the whole reply at once."""
        yield await self.chat(messages, max_tokens, temperature)


class OllamaProvider(Provider):
    provider_type = "ollama"

    def __init__(self, model: str, base_url: str = "http://127.0.0.1:11434", transport: httpx.AsyncBaseTransport | None = None, num_ctx: int = 8192):
        super().__init__(model)
        if not is_loopback_url(base_url):
            raise ProviderError("local Ollama profiles must use a loopback address")
        # Ollama's default context window is small and silently drops the START of a long prompt (the system rules); ask for a real one
        self.base, self.transport, self.num_ctx = base_url.rstrip("/"), transport, num_ctx

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
                "options": {"num_predict": max_tokens, "temperature": temperature, "num_ctx": self.num_ctx}}
        try:
            async with self._client() as c:
                r = await c.post(f"{self.base}/api/chat", json=body)
            if r.status_code != 200:
                raise ProviderUnavailable(f"Ollama HTTP {r.status_code}")
            return re.sub(r"<think>.*?</think>\s*", "", r.json()["message"]["content"], flags=re.DOTALL)
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            raise ProviderUnavailable(f"Ollama call failed ({type(exc).__name__})") from exc


    async def chat_stream(self, messages, max_tokens=1200, temperature=0.1):
        body = {"model": self.model, "stream": True, "think": False, "messages": [m.__dict__ for m in messages],
                "options": {"num_predict": max_tokens, "temperature": temperature, "num_ctx": self.num_ctx}}
        hide = _ThinkFilter()
        try:
            async with self._client() as c:
                async with c.stream("POST", f"{self.base}/api/chat", json=body) as r:
                    if r.status_code != 200:
                        raise ProviderUnavailable(f"Ollama HTTP {r.status_code}")
                    async for line in r.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            piece = json.loads(line).get("message", {}).get("content", "")
                        except ValueError:
                            continue
                        out = hide.feed(piece)
                        if out:
                            yield out
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            raise ProviderUnavailable(f"Ollama call failed ({type(exc).__name__})") from exc


class _ThinkFilter:
    """Drops <think>…</think> spans from a token stream (some models emit them even when asked not to)."""

    def __init__(self) -> None:
        self.buf, self.inside = "", False

    def feed(self, piece: str) -> str:
        self.buf += piece
        out = ""
        while True:
            if self.inside:
                end = self.buf.find("</think>")
                if end < 0:
                    self.buf = self.buf[-8:]  # keep a possible partial closing tag
                    return out
                self.buf, self.inside = self.buf[end + 8:].lstrip(), False
            else:
                start = self.buf.find("<think>")
                if start >= 0:
                    out += self.buf[:start]
                    self.buf, self.inside = self.buf[start + 7:], True
                    continue
                keep = max((i for i in range(1, 7) if self.buf.endswith("<think>"[:i])), default=0)
                out += self.buf[: len(self.buf) - keep]
                self.buf = self.buf[len(self.buf) - keep:]
                return out


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


    async def chat_stream(self, messages, max_tokens=1200, temperature=0.1):
        body = {"model": self.model, "messages": [m.__dict__ for m in messages], "max_tokens": max_tokens, "temperature": temperature, "stream": True}
        try:
            async with self._client() as c:
                async with c.stream("POST", f"{self.base}/v1/chat/completions", json=body, headers=self._headers()) as r:
                    if r.status_code != 200:
                        raise ProviderUnavailable(f"endpoint HTTP {r.status_code}")
                    async for line in r.aiter_lines():
                        if not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if data == "[DONE]":
                            return
                        try:
                            piece = json.loads(data)["choices"][0].get("delta", {}).get("content") or ""
                        except (ValueError, KeyError, IndexError):
                            continue
                        if piece:
                            yield piece
        except (httpx.HTTPError, ValueError) as exc:
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

    async def chat_stream(self, messages, max_tokens=1200, temperature=0.1):
        text = await self.chat(messages, max_tokens, temperature)
        for i in range(0, len(text), 16):
            yield text[i:i + 16]
