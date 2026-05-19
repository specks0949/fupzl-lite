"""HTTP fallbacks for Cloudflare-sensitive Linux.do read/auth endpoints.

The module intentionally contains only read/authenticated GET helpers. It does
not implement Discourse write endpoints such as reactions or replies.
"""

from __future__ import annotations

import html as html_lib
import json
import re
from datetime import datetime, timezone
from urllib.parse import quote

from curl_cffi import requests

from litefupzl.discourse.models import Topic, UserInfo

_IMPERSONATE = "firefox135"
_SESSION_CURRENT_JSON_URL = "https://linux.do/session/current.json"
_NOTIFICATIONS_JSON_URL = "https://linux.do/notifications.json?recent=true&limit=1"
_JSON_ACCEPT = "application/json, text/javascript, */*; q=0.01"
_HTML_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"


def _clean_user_agent(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    cleaned = str(user_agent).strip()
    return cleaned or None


def _base_headers(accept: str, *, referer: str | None = None, user_agent: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": accept,
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }
    cleaned_user_agent = _clean_user_agent(user_agent)
    if cleaned_user_agent:
        headers["User-Agent"] = cleaned_user_agent
    if referer:
        headers["Referer"] = referer
        headers["Origin"] = "https://linux.do"
    return headers


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return None


def _normalize_tags(raw_tags) -> list[str]:
    tags: list[str] = []
    for raw_tag in raw_tags or []:
        if isinstance(raw_tag, str):
            tags.append(raw_tag)
        elif isinstance(raw_tag, dict):
            tag_name = raw_tag.get("name") or raw_tag.get("slug")
            if tag_name:
                tags.append(str(tag_name))
    return tags


def _parse_topic(raw: dict, base_url: str) -> Topic:
    raw_tags = _normalize_tags(raw.get("tags", []))
    return Topic(
        id=raw["id"],
        title=raw.get("title", ""),
        slug=raw.get("slug", "") or "topic",
        url=f"{base_url}/t/{raw.get('slug', '') or 'topic'}/{raw['id']}",
        unread_posts=raw.get("unread_posts", 0) or 0,
        unseen=raw.get("unseen", True),
        closed=raw.get("closed", False),
        archived=raw.get("archived", False),
        tags=raw_tags,
        category_id=raw.get("category_id", 0) or 0,
    )


def _extract_topics(data: dict, base_url: str, *, unread_only: bool) -> list[Topic]:
    raw_topics = data.get("topic_list", {}).get("topics", [])
    topics = [_parse_topic(raw, base_url) for raw in raw_topics]
    if unread_only:
        topics = [topic for topic in topics if topic.unread_posts > 0 or topic.unseen]
    return topics


def _build_session(
    cookies: list[dict],
    *,
    accept: str,
    referer: str | None = None,
    user_agent: str | None = None,
) -> requests.Session:
    session = requests.Session()
    session.headers.update(_base_headers(accept, referer=referer, user_agent=user_agent))

    for cookie in cookies:
        name = cookie.get("name")
        value = cookie.get("value")
        if not name or value is None:
            continue
        session.cookies.set(
            name,
            value,
            domain=cookie.get("domain") or "linux.do",
            path=cookie.get("path") or "/",
        )
    return session


def fetch_json(cookies: list[dict], url: str, *, referer: str | None = None, user_agent: str | None = None) -> dict:
    """Fetch a JSON endpoint via curl_cffi using authenticated cookies."""
    session = _build_session(cookies, accept=_JSON_ACCEPT, referer=referer, user_agent=user_agent)
    response = session.get(url, impersonate=_IMPERSONATE, timeout=20)
    if response.status_code != 200:
        raise RuntimeError(f"HTTP {response.status_code} for {url}")
    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError(f"Invalid JSON from {url}") from exc


def fetch_html(cookies: list[dict], url: str, *, referer: str | None = None, user_agent: str | None = None) -> str:
    """Fetch an HTML endpoint via curl_cffi using authenticated cookies."""
    session = _build_session(cookies, accept=_HTML_ACCEPT, referer=referer, user_agent=user_agent)
    response = session.get(url, impersonate=_IMPERSONATE, timeout=20)
    if response.status_code != 200:
        raise RuntimeError(f"HTTP {response.status_code} for {url}")
    return response.text


def is_cookie_authenticated_via_http(cookies: list[dict], base_url: str, *, user_agent: str | None = None) -> bool:
    """Check whether the provided cookie authenticates successfully in this environment."""
    return probe_cookie_login_state_via_http(cookies, base_url, user_agent=user_agent) == "ok"


def _extract_current_user_from_payload(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    user = payload.get("current_user") or payload.get("currentUser") or payload.get("user")
    if isinstance(user, dict) and (user.get("username") or user.get("id")):
        return user
    return None


def _is_cf_blocked_text(text: str) -> bool:
    lowered = text[:500].lower()
    return "just a moment" in lowered or "cf-challenge" in lowered or "cf-turnstile-response" in lowered or "cloudflare" in lowered


def _is_rate_limited_text(text: str) -> bool:
    lowered = text[:500].lower()
    return "rate limit" in lowered or "too many requests" in lowered or lowered.strip() == "{}"


def _has_authenticated_shell_marker(html: str) -> bool:
    lowered = html.lower()
    return 'id="current-user"' in lowered or 'toggle-current-user' in lowered


def _is_valid_json_payload(text: str) -> bool:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return False
    return isinstance(payload, (dict, list))


def probe_cookie_login_state_via_http(cookies: list[dict], base_url: str, *, user_agent: str | None = None) -> str:
    """Classify current cookie state as ok / cf_blocked / rate_limited / cookie_invalid."""
    try:
        home_html = fetch_html(cookies, f"{base_url}/", referer=base_url, user_agent=user_agent)
        if _is_cf_blocked_text(home_html):
            return "cf_blocked"
        if _is_rate_limited_text(home_html):
            return "rate_limited"
    except Exception:
        pass

    session = _build_session(cookies, accept=_JSON_ACCEPT, referer=base_url, user_agent=user_agent)
    try:
        response = session.get(_SESSION_CURRENT_JSON_URL, impersonate=_IMPERSONATE, timeout=20)
        if response.status_code == 200:
            if _extract_current_user_from_payload(response.text) is not None:
                return "ok"
            if _is_rate_limited_text(response.text):
                return "rate_limited"
            if _is_cf_blocked_text(response.text):
                return "cf_blocked"
        if response.status_code == 429:
            return "rate_limited"
        if response.status_code == 403:
            if _is_cf_blocked_text(response.text):
                return "cf_blocked"
            if _is_rate_limited_text(response.text):
                return "rate_limited"
    except Exception:
        pass

    try:
        response = session.get(_NOTIFICATIONS_JSON_URL, impersonate=_IMPERSONATE, timeout=20)
        if response.status_code == 200:
            if _is_valid_json_payload(response.text):
                return "ok"
            if _is_rate_limited_text(response.text):
                return "rate_limited"
            if _is_cf_blocked_text(response.text):
                return "cf_blocked"
            return "cookie_invalid"
        if response.status_code == 429:
            return "rate_limited"
        if response.status_code in {403, 429}:
            if _is_cf_blocked_text(response.text):
                return "cf_blocked"
    except Exception:
        pass

    try:
        html = fetch_html(cookies, f"{base_url}/notifications", referer=base_url, user_agent=user_agent)
    except Exception:
        return "cookie_invalid"
    if _is_rate_limited_text(html):
        return "rate_limited"
    if _has_authenticated_shell_marker(html) and _extract_username_from_html(html) is not None:
        return "ok"
    if _is_cf_blocked_text(html):
        return "cf_blocked"
    return "cookie_invalid"


def _extract_username_from_html(html: str) -> str | None:
    """Extract the current username from server-rendered HTML / embedded preload data."""
    if not html:
        return None

    unescaped = html_lib.unescape(html)
    current_user_idx = unescaped.find('currentUser":"{')
    if current_user_idx >= 0:
        current_user_slice = unescaped[current_user_idx: current_user_idx + 1000]
        marker = r'\"username\":\"'
        marker_idx = current_user_slice.find(marker)
        if marker_idx >= 0:
            tail = current_user_slice[marker_idx + len(marker):]
            username = tail.split(r'\"', 1)[0]
            if username:
                return username

    patterns = (
        r'"username":"([A-Za-z0-9_\-]+)"',
        r'/u/([A-Za-z0-9_\-]+)/',
        r'/user_avatar/[^/]+/([A-Za-z0-9_\-]+)/',
    )
    for source in (unescaped, html):
        for pattern in patterns:
            match = re.search(pattern, source)
            if match:
                return match.group(1)
    return None


def extract_current_username_via_http(cookies: list[dict], base_url: str, *, user_agent: str | None = None) -> str | None:
    """Extract the current authenticated username from server-rendered HTML."""
    session = _build_session(cookies, accept=_JSON_ACCEPT, referer=base_url, user_agent=user_agent)
    try:
        response = session.get(_SESSION_CURRENT_JSON_URL, impersonate=_IMPERSONATE, timeout=20)
        if response.status_code == 200:
            user = _extract_current_user_from_payload(response.text)
            username = user.get("username") if isinstance(user, dict) else None
            if username:
                return str(username)
    except Exception:
        pass

    try:
        html = fetch_html(cookies, f"{base_url}/notifications", referer=base_url, user_agent=user_agent)
    except Exception:
        return None

    if not _has_authenticated_shell_marker(html):
        return None
    return _extract_username_from_html(html)


def get_user_info_via_http(cookies: list[dict], base_url: str, username: str, *, user_agent: str | None = None) -> UserInfo:
    """Fetch user info without relying on browser JSON navigation."""
    url = f"{base_url}/u/{quote(username, safe='')}.json"
    data = fetch_json(cookies, url, referer=base_url, user_agent=user_agent)
    user = data.get("user", {})
    return UserInfo(
        username=user.get("username", username),
        trust_level=user.get("trust_level", 0) or 0,
        suspended_till=_parse_datetime(user.get("suspended_till")),
        silenced_till=_parse_datetime(user.get("silenced_till")),
    )


def get_latest_topics_via_http(cookies: list[dict], base_url: str, *, user_agent: str | None = None) -> list[Topic]:
    """Fetch latest unread/unseen topics via curl_cffi."""
    data = fetch_json(cookies, f"{base_url}/latest.json", referer=base_url, user_agent=user_agent)
    return _extract_topics(data, base_url, unread_only=True)


def get_latest_topics_pages_via_http(
    cookies: list[dict],
    base_url: str,
    *,
    pages: int,
    user_agent: str | None = None,
) -> list[Topic]:
    """Fetch unread/unseen topics from the first N latest.json pages."""
    page_count = max(1, int(pages))
    topics: list[Topic] = []
    seen_ids: set[int] = set()

    for page in range(page_count):
        url = f"{base_url}/latest.json" if page == 0 else f"{base_url}/latest.json?page={page}"
        data = fetch_json(cookies, url, referer=base_url, user_agent=user_agent)
        for topic in _extract_topics(data, base_url, unread_only=True):
            if topic.id in seen_ids:
                continue
            seen_ids.add(topic.id)
            topics.append(topic)

    return topics
