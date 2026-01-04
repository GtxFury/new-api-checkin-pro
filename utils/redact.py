from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_QUERY_KEYS = {
    "code",
    "state",
    "client_id",
    "client_secret",
    "redirect_uri",
    "access_token",
    "refresh_token",
    "token",
    "id_token",
    "session",
    "oauth_token",
}


def redact_value_for_log(value: str | int | None, mask: str = "***") -> str:
    if value is None:
        return ""
    return mask


def redact_url_for_log(url: str | None, mask: str = "***") -> str:
    """用于日志输出的 URL 脱敏：仅修改字符串展示，不影响真实请求 URL。"""
    if not url:
        return ""

    try:
        parts = urlsplit(url)
        if not parts.query and not parts.fragment:
            return url

        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        redacted_query = []
        for key, value in query_pairs:
            if key in SENSITIVE_QUERY_KEYS:
                redacted_query.append((key, mask))
            else:
                redacted_query.append((key, value))

        # fragment 里也可能携带 token（如 access_token=...），同样脱敏
        fragment_pairs = parse_qsl(parts.fragment, keep_blank_values=True)
        if fragment_pairs:
            redacted_fragment = []
            for key, value in fragment_pairs:
                if key in SENSITIVE_QUERY_KEYS:
                    redacted_fragment.append((key, mask))
                else:
                    redacted_fragment.append((key, value))
            fragment = urlencode(redacted_fragment, doseq=True)
        else:
            fragment = parts.fragment

        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                urlencode(redacted_query, doseq=True),
                fragment,
            )
        )
    except Exception:
        # 兜底：解析失败则直接返回原串，避免影响主流程
        return url

