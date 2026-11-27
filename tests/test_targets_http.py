"""Tests for the HTTP target plumbing: retries, Retry-After, response_path and env expansion.

All requests go to an in-process httpx.MockTransport, so nothing touches the network.
"""

import json
from email.utils import format_datetime
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from promptprobe.models import Message
from promptprobe.targets import TargetError, make_target
from promptprobe.targets import base as base_mod
from promptprobe.targets.base import parse_retry_after
from promptprobe.targets.http_generic import dig


@pytest.fixture
def sleeps(monkeypatch):
    """Record backoff waits instead of sleeping, and remove jitter."""
    waits: list[float] = []

    async def fake_sleep(secs):
        waits.append(secs)

    monkeypatch.setattr(base_mod.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(base_mod.random, "random", lambda: 0.0)
    return waits


def attach(target, handler):
    """Swap the target's client for one backed by a mock transport."""
    target._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return target


def http_target(**cfg):
    return make_target({"type": "http", "url": "http://app.test/chat", **cfg})


def scripted(responses, seen=None):
    """Handler that returns the given responses in order (callables are invoked)."""
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    return handler


MSGS = [Message("system", "be nice"), Message("user", "hi there")]


# --- Retry-After parsing -----------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("5", 5.0), ("1.5", 1.5), (" 2 ", 2.0), ("0", 0.0),
    (None, None), ("", None), ("-3", None), ("soon", None), ("1.2.3", None), ("nan", None),
])
def test_parse_retry_after_seconds(value, expected):
    assert parse_retry_after(value) == expected


def test_parse_retry_after_http_date():
    now = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)
    header = format_datetime(now + timedelta(seconds=7), usegmt=True)
    assert parse_retry_after(header, now=now.timestamp()) == pytest.approx(7.0)
    past = format_datetime(now - timedelta(seconds=7), usegmt=True)
    assert parse_retry_after(past, now=now.timestamp()) is None


# --- Retry behaviour ---------------------------------------------------------

async def test_retries_then_succeeds_with_exponential_backoff(sleeps):
    t = attach(http_target(), scripted([
        httpx.Response(503, text="busy"),
        httpx.Response(502, text="bad gateway"),
        httpx.Response(200, json={"reply": "ok"}),
    ]))
    assert await t.chat(MSGS) == "ok"
    assert sleeps == [1.0, 2.0]


async def test_network_errors_are_retried(sleeps):
    t = attach(http_target(), scripted([
        httpx.ConnectError("refused"),
        httpx.Response(200, json={"reply": "back"}),
    ]))
    assert await t.chat(MSGS) == "back"
    assert sleeps == [1.0]


async def test_retry_after_raises_wait_but_is_capped(sleeps):
    t = attach(http_target(), scripted([
        httpx.Response(429, headers={"Retry-After": "4"}),
        httpx.Response(429, headers={"Retry-After": "9999"}),
        httpx.Response(429, headers={"Retry-After": "garbage"}),
        httpx.Response(200, json={"reply": "ok"}),
    ]))
    assert await t.chat(MSGS) == "ok"
    # 4s hint beats the 1s base; 9999 is capped at 30; garbage falls back to backoff (4s)
    assert sleeps == [4.0, base_mod.MAX_DELAY, 4.0]


async def test_gives_up_after_max_retries(sleeps):
    calls = []
    t = attach(http_target(max_retries=2), scripted([httpx.Response(500, text="boom")] * 3, calls))
    with pytest.raises(TargetError, match=r"HTTP 500: boom \(gave up after 3 attempts\)"):
        await t.chat(MSGS)
    assert len(calls) == 3
    assert sleeps == [1.0, 2.0]  # no sleep after the final attempt


async def test_max_retries_zero_means_one_attempt(sleeps):
    t = attach(http_target(max_retries=0), scripted([httpx.ConnectError("down")]))
    with pytest.raises(TargetError, match=r"network error: down \(gave up after 1 attempt\)"):
        await t.chat(MSGS)
    assert sleeps == []


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
async def test_client_errors_fail_fast(sleeps, status):
    calls = []
    t = attach(http_target(), scripted([httpx.Response(status, text="nope")], calls))
    with pytest.raises(TargetError, match=f"HTTP {status}"):
        await t.chat(MSGS)
    assert len(calls) == 1 and sleeps == []


async def test_non_json_success_is_a_target_error(sleeps):
    t = attach(http_target(), scripted([httpx.Response(200, text="<html>login</html>")]))
    with pytest.raises(TargetError, match="not JSON"):
        await t.chat(MSGS)


async def test_backoff_base_is_configurable(sleeps):
    t = attach(http_target(backoff_base=0.25), scripted([
        httpx.Response(503), httpx.Response(503), httpx.Response(200, json={"reply": "x"}),
    ]))
    await t.chat(MSGS)
    assert sleeps == [0.25, 0.5]


# --- Generic HTTP target: body, headers, response_path ------------------------

async def test_body_placeholders_and_env_headers(sleeps, monkeypatch):
    monkeypatch.setenv("PP_TEST_TOKEN", "s3cret")
    seen = []
    t = attach(http_target(
        headers={"Authorization": "Bearer ${PP_TEST_TOKEN}", "X-Missing": "${PP_NOT_SET}"},
        body={"message": "{{last_user}}", "history": "{{messages}}", "note": "sys={{system}}"},
        response_path="data.choices.0.text",
    ), scripted([httpx.Response(200, json={"data": {"choices": [{"text": "hello"}]}})], seen))

    assert await t.chat(MSGS) == "hello"
    req = seen[0]
    assert req.headers["authorization"] == "Bearer s3cret"
    assert req.headers["x-missing"] == ""  # unset vars expand to empty, never the literal
    sent = json.loads(req.content)
    assert sent["message"] == "hi there"
    assert sent["history"] == [m.to_dict() for m in MSGS]  # list kept as a list
    assert sent["note"] == "sys=be nice"


async def test_send_system_prompt_false_strips_system(sleeps):
    seen = []
    t = attach(http_target(send_system_prompt=False),
               scripted([httpx.Response(200, json={"reply": "ok"})], seen))
    await t.chat(MSGS)
    sent = json.loads(seen[0].content)
    assert all(m["role"] != "system" for m in sent["messages"])


async def test_non_string_reply_is_stringified(sleeps):
    t = attach(http_target(response_path="n"), scripted([httpx.Response(200, json={"n": 42})]))
    assert await t.chat(MSGS) == "42"


async def test_missing_response_path_reports_payload(sleeps):
    t = attach(http_target(response_path="data.reply"),
               scripted([httpx.Response(200, json={"error": "rate limited"})]))
    with pytest.raises(TargetError, match="response_path 'data.reply' not found.*rate limited"):
        await t.chat(MSGS)


def test_dig_walks_dicts_and_lists():
    data = {"a": [{"b": "x"}, {"b": "y"}]}
    assert dig(data, "a.1.b") == "y"
    with pytest.raises(IndexError):
        dig(data, "a.5.b")
    with pytest.raises(ValueError):
        dig(data, "a.first.b")


def test_http_target_requires_url():
    with pytest.raises(TargetError, match="needs a 'url'"):
        make_target({"type": "http"})
