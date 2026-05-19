from types import SimpleNamespace

import pytest


def _latest_payload(*topics: dict) -> dict:
    return {"topic_list": {"topics": list(topics)}}


def _topic(topic_id: int, *, unread_posts: int = 0, unseen: bool = False) -> dict:
    return {
        "id": topic_id,
        "title": f"redacted-{topic_id}",
        "slug": f"topic-{topic_id}",
        "unread_posts": unread_posts,
        "unseen": unseen,
        "closed": False,
        "archived": False,
        "tags": [],
        "category_id": 1,
    }


@pytest.mark.parametrize(
    ("duration_minutes", "expected_pages"),
    [
        (1, 1),
        (5, 1),
        (6, 2),
        (40, 8),
    ],
)
def test_latest_page_count_ceil_duration_by_five(duration_minutes, expected_pages):
    from litefupzl.oneshot.session import _latest_page_count_for_duration

    assert _latest_page_count_for_duration(duration_minutes) == expected_pages


def test_latest_topics_pages_fetches_first_n_pages_and_keeps_unread_filter(monkeypatch):
    from litefupzl.discourse import http_bypass

    observed_urls = []
    payloads = {
        "https://linux.do/latest.json": _latest_payload(
            _topic(100, unread_posts=1),
            _topic(101, unread_posts=0, unseen=False),
        ),
        "https://linux.do/latest.json?page=1": _latest_payload(
            _topic(102, unread_posts=0, unseen=True),
            _topic(100, unread_posts=2),
        ),
        "https://linux.do/latest.json?page=2": _latest_payload(
            _topic(103, unread_posts=3),
        ),
    }

    def fake_fetch_json(cookies, url, *, referer=None, user_agent=None):
        observed_urls.append(url)
        assert cookies == [{"name": "_t", "value": "redacted"}]
        assert referer == "https://linux.do"
        assert user_agent == "test-agent"
        return payloads[url]

    monkeypatch.setattr(http_bypass, "fetch_json", fake_fetch_json)

    topics = http_bypass.get_latest_topics_pages_via_http(
        [{"name": "_t", "value": "redacted"}],
        "https://linux.do",
        pages=3,
        user_agent="test-agent",
    )

    assert observed_urls == [
        "https://linux.do/latest.json",
        "https://linux.do/latest.json?page=1",
        "https://linux.do/latest.json?page=2",
    ]
    assert [topic.id for topic in topics] == [100, 102, 103]


@pytest.mark.asyncio
async def test_build_topic_queue_uses_duration_based_latest_page_count(monkeypatch):
    from litefupzl.oneshot import session

    captured = {}

    def fake_get_latest_topics_pages_via_http(cookies, base_url, *, pages, user_agent=None):
        captured["cookies"] = cookies
        captured["base_url"] = base_url
        captured["pages"] = pages
        captured["user_agent"] = user_agent
        return []

    monkeypatch.setattr(session, "get_latest_topics_pages_via_http", fake_get_latest_topics_pages_via_http)

    config = SimpleNamespace(duration_minutes=6)
    result = await session._build_topic_queue([{"name": "_t", "value": "redacted"}], config, user_agent="test-agent")

    assert result == []
    assert captured == {
        "cookies": [{"name": "_t", "value": "redacted"}],
        "base_url": "https://linux.do",
        "pages": 2,
        "user_agent": "test-agent",
    }
