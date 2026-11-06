"""Unit tests for the real Turnstile verifier using a mocked HTTP transport (no network)."""

import os

import httpx
import pytest

from app.security.captcha import verify_turnstile


def client_returning(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_success_response_passes():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"success": True})

    assert verify_turnstile("tok", "203.0.113.5", client=client_returning(handler)) is True
    assert "response=tok" in seen["body"] and "secret=" in seen["body"] and "remoteip=203.0.113.5" in seen["body"]


def test_failure_response_is_rejected():
    handler = lambda _: httpx.Response(200, json={"success": False, "error-codes": ["invalid-input-response"]})  # noqa: E731
    assert verify_turnstile("tok", "1.2.3.4", client=client_returning(handler)) is False


@pytest.mark.parametrize(
    "handler",
    [
        lambda _: httpx.Response(500),
        lambda _: httpx.Response(200, content=b"not json"),
        lambda _: httpx.Response(200, json={"success": "true"}),
    ],
)
def test_bad_upstream_responses_fail_closed(handler):
    assert verify_turnstile("tok", "1.2.3.4", client=client_returning(handler)) is False


def test_timeout_fails_closed():
    def handler(_):
        raise httpx.ReadTimeout("timed out")

    assert verify_turnstile("tok", "1.2.3.4", client=client_returning(handler)) is False


def test_missing_token_never_calls_upstream():
    def handler(_):
        raise AssertionError("should not be called")

    assert verify_turnstile(None, "1.2.3.4", client=client_returning(handler)) is False
    assert verify_turnstile("", "1.2.3.4", client=client_returning(handler)) is False


# ---- Live check against Cloudflare (the same code path production uses) ----

live = pytest.mark.skipif(os.environ.get("RUN_LIVE_CAPTCHA") != "1", reason="set RUN_LIVE_CAPTCHA=1 to call Cloudflare")
DUMMY_TOKEN = "XXXX.DUMMY.TOKEN.XXXX"  # what Cloudflare's test site keys issue


@pytest.mark.live
@live
def test_live_always_pass_secret_accepts():
    assert verify_turnstile(DUMMY_TOKEN, "", secret="1x0000000000000000000000000000000AA") is True


@pytest.mark.live
@live
def test_live_always_fail_secret_rejects():
    assert verify_turnstile(DUMMY_TOKEN, "", secret="2x0000000000000000000000000000000AA") is False


@pytest.mark.live
@live
def test_live_invalid_secret_is_rejected_by_cloudflare():
    # Shows the production path really calls siteverify and honours its verdict.
    assert verify_turnstile(DUMMY_TOKEN, "", secret="0x-not-a-real-secret") is False
