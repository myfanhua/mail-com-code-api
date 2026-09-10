"""Verification-code extraction with contextual matching before generic digits."""

from __future__ import annotations

import html
import re


CONTEXT_RE = re.compile(
    r"(?:verification|verify|security|login|one[- ]time|otp|code|验证码|校验码|动态码|一次性|"
    r"一時検証コード|検証コード|認証コード|ログインコード|確認コード|ワンタイムコード)[^0-9]{0,50}([0-9]{4,8})",
    re.IGNORECASE,
)
REVERSE_CONTEXT_RE = re.compile(
    r"([0-9]{4,8})[^0-9]{0,30}(?:verification|verify|security|login|one[- ]time|otp|code|验证码|校验码|动态码|一次性|"
    r"一時検証コード|検証コード|認証コード|ログインコード|確認コード|ワンタイムコード)",
    re.IGNORECASE,
)
GENERIC_RE = re.compile(r"(?<![0-9])[0-9]{4,8}(?![0-9])")


def extract_code(subject: str, body: str) -> str | None:
    text = html.unescape(f"{subject}\n{body}")
    for pattern in (CONTEXT_RE, REVERSE_CONTEXT_RE):
        match = pattern.search(text)
        if match:
            return match.group(1)
    candidates = list(dict.fromkeys(GENERIC_RE.findall(text)))
    return candidates[0] if len(candidates) == 1 else None
