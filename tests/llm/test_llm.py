import dataclasses
import json

import httpx
import pytest

from cve_copilot.config import Settings
from cve_copilot.llm import complete, fake, ollama
from cve_copilot.llm.retry import LLMUnavailable, with_retry

MSGS = [{"role": "user", "content": "hello"}]
NO_SLEEP = lambda s: None


def settings(**kw):
    return dataclasses.replace(Settings.from_env(), **kw)


def mock_client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fake_provider_returns_scripted_answers():
    fake.set_responses(["one", "two"])
    s = settings(llm="fake")
    assert complete(MSGS, settings=s) == "one"
    assert complete(MSGS, json_mode=True, settings=s) == "two"
    assert fake.calls[1]["json_mode"] is True


def test_unknown_provider():
    with pytest.raises(ValueError):
        complete(MSGS, settings=settings(llm="nope"))


def test_ollama_request_shape():
    seen = {}

    def handler(req):
        seen["url"] = str(req.url)
        seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={"message": {"role": "assistant", "content": "hi"}})

    out = ollama.complete(MSGS, json_mode=True, settings=settings(),
                          client=mock_client(handler), sleep=NO_SLEEP)
    assert out == "hi"
    assert seen["url"] == "http://localhost:11434/api/chat"
    assert seen["body"]["model"] == "qwen2.5:7b"
    assert seen["body"]["options"]["temperature"] == 0
    assert seen["body"]["options"]["num_ctx"] == 8192
    assert seen["body"]["format"] == "json"
    assert seen["body"]["stream"] is False


def test_ollama_down_gives_helpful_error():
    def handler(req):
        raise httpx.ConnectError("refused")

    with pytest.raises(LLMUnavailable, match="ollama serve"):
        ollama.complete(MSGS, json_mode=False, settings=settings(),
                        client=mock_client(handler), sleep=NO_SLEEP)


def test_github_provider_is_gone():
    with pytest.raises(ValueError, match="use ollama or fake"):
        complete(MSGS, settings=settings(llm="github"))


def test_retry_then_success():
    responses = iter([httpx.Response(429), httpx.Response(503), httpx.Response(200)])
    sleeps = []
    r = with_retry(lambda: next(responses), sleep=sleeps.append)
    assert r.status_code == 200
    assert sleeps == [1, 2]


def test_retry_gives_up_after_three_attempts():
    with pytest.raises(LLMUnavailable, match="3 attempts"):
        with_retry(lambda: httpx.Response(429), sleep=NO_SLEEP)


def test_client_error_is_not_retried():
    calls = []

    def send():
        calls.append(1)
        return httpx.Response(401, request=httpx.Request("POST", "https://x"))

    with pytest.raises(httpx.HTTPStatusError):
        with_retry(send, sleep=NO_SLEEP)
    assert len(calls) == 1
