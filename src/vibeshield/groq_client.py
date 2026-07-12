from __future__ import annotations

import os
import json
import time

from .secret_redaction import redact_text


class GroqClient:
    MAX_RETRIES = 3
    BASE_BACKOFF_SECONDS = 2.0

    def __init__(self, api_key: str | None = None, *, offline: bool = False) -> None:
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        self.offline = offline or os.getenv("VIBESHIELD_OFFLINE", "0").lower() in {"1", "true", "yes"}
        self.model = os.getenv("VIBESHIELD_MODEL", "llama-3.3-70b-versatile")
        self._client = None
        self.last_error: str | None = None
        self.call_count = 0
        self.failure_count = 0
        self.retry_count = 0

    @property
    def enabled(self) -> bool:
        return bool(self.api_key) and not self.offline

    def _get_client(self):
        if self._client is None:
            from groq import Groq
            self._client = Groq(api_key=self.api_key)
        return self._client

    @staticmethod
    def _is_transient(exc: Exception) -> bool:
        try:
            from groq import RateLimitError, APITimeoutError, InternalServerError, APIConnectionError
        except ImportError:
            return False
        return isinstance(exc, (RateLimitError, APITimeoutError, InternalServerError, APIConnectionError))

    def _call_with_retry(self, make_request):
        self.call_count += 1
        last_exc: Exception | None = None
        for attempt in range(self.MAX_RETRIES + 1):
            try:
                return make_request()
            except Exception as e:
                last_exc = e
                if not self._is_transient(e) or attempt == self.MAX_RETRIES:
                    break
                self.retry_count += 1
                time.sleep(self.BASE_BACKOFF_SECONDS * (2 ** attempt))
        self.failure_count += 1
        self.last_error = f"{type(last_exc).__name__}: {last_exc}"
        return None

    def analyze(self, prompt: str) -> str | None:
        if self.offline or not self.api_key:
            return None

        redacted_prompt = redact_text(prompt)

        def _request():
            client = self._get_client()
            response = client.chat.completions.create(
                model=self.model,
                max_tokens=800,
                temperature=0,
                messages=[{"role": "user", "content": redacted_prompt}],
            )
            return response.choices[0].message.content

        return self._call_with_retry(_request)

    def analyze_json(self, system_prompt: str, user_prompt: str) -> dict | list | None:
        if self.offline or not self.api_key:
            return None

        redacted_prompt = redact_text(user_prompt)

        def _request():
            client = self._get_client()
            response = client.chat.completions.create(
                model=self.model,
                max_tokens=1200,
                temperature=0,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": redact_text(system_prompt)},
                    {"role": "user", "content": redacted_prompt},
                ],
            )
            raw = response.choices[0].message.content
            return json.loads(raw)

        return self._call_with_retry(_request)
