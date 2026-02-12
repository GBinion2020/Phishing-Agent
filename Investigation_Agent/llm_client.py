#!/usr/bin/env python3
"""Minimal OpenAI Responses API client with strict JSON response handling."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


def _clean_secret(raw: str | None) -> str | None:
    if raw is None:
        return None
    v = raw.strip()
    if len(v) >= 2 and ((v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'"))):
        v = v[1:-1].strip()
    if v.lower().startswith("bearer "):
        v = v.split(" ", 1)[1].strip()
    return v


class LLMClient:
    def __init__(self, api_key: str | None = None, model: str | None = None, timeout_seconds: int = 60) -> None:
        self.api_key = _clean_secret(api_key or os.getenv("OPENAI_API_KEY"))
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-5-mini")
        self.timeout_seconds = timeout_seconds

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def call_json(
        self,
        system_prompt: str,
        user_prompt: str,
        json_schema: dict[str, Any],
        schema_name: str,
        temperature: float | None = 0.0,
    ) -> dict[str, Any]:
        if not self.enabled:
            raise RuntimeError("OPENAI_API_KEY not configured")

        payload = {
            "model": self.model,
            "input": [
                {
                    "role": "system",
                    "content": [{"type": "input_text", "text": system_prompt}],
                },
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": user_prompt}],
                },
            ],
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": schema_name,
                    "schema": json_schema,
                    "strict": True,
                }
            },
        }
        if temperature is not None:
            payload["temperature"] = temperature

        body = self._post(payload)
        parsed = json.loads(body)
        text = _extract_response_text(parsed)
        if text is None:
            raise RuntimeError("Unable to extract JSON text from OpenAI response")

        try:
            out = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"OpenAI returned non-JSON text: {text[:200]}...") from exc
        if not isinstance(out, dict):
            raise RuntimeError("OpenAI JSON result must be an object")
        return out

    def _post(self, payload: dict[str, Any]) -> str:
        req = urllib.request.Request(
            url="https://api.openai.com/v1/responses",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            err = exc.read().decode("utf-8", errors="replace")
            # Some models do not accept temperature; retry once without it.
            if exc.code == 400 and "Unsupported parameter: 'temperature'" in err and "temperature" in payload:
                payload2 = dict(payload)
                payload2.pop("temperature", None)
                req2 = urllib.request.Request(
                    url="https://api.openai.com/v1/responses",
                    data=json.dumps(payload2).encode("utf-8"),
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req2, timeout=self.timeout_seconds) as resp2:
                    return resp2.read().decode("utf-8")
            raise RuntimeError(f"OpenAI HTTP error {exc.code}: {err}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"OpenAI connection error: {exc}") from exc



def _extract_response_text(response: dict[str, Any]) -> str | None:
    # Preferred shortcuts when present.
    output_text = response.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text

    output = response.get("output")
    if not isinstance(output, list):
        return None

    for item in output:
        if not isinstance(item, dict):
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for c in content:
            if not isinstance(c, dict):
                continue
            # Common text location.
            if isinstance(c.get("text"), str):
                return c["text"]
            # Some responses nest under output_text-like key.
            if isinstance(c.get("output_text"), str):
                return c["output_text"]
            # Fallback nested objects.
            txt = c.get("json")
            if isinstance(txt, (dict, list)):
                return json.dumps(txt)

    return None
