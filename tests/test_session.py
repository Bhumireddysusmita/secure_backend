from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, update

from app.models import Session

from .conftest import signup_body


def test_me_requires_login(client):
    res = client.get("/api/auth/me")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "unauthenticated"


def test_me_returns_current_user(client):
    client.post("/api/auth/signup", json=signup_body())
    res = client.get("/api/auth/me")
    assert res.status_code == 200
    assert set(res.json()["user"]) == {"id", "name", "email", "createdAt"}


def test_logout_deletes_session_and_clears_cookie(client, db):
    client.post("/api/auth/signup", json=signup_body())
    token = client.cookies.get("sid")
    res = client.post("/api/auth/logout")
    assert res.status_code == 204
    assert 'sid=""' in res.headers["set-cookie"] or "Max-Age=0" in res.headers["set-cookie"]
    assert db.execute(select(func.count()).select_from(Session)).scalar_one() == 0
    # The old token can't be replayed.
    client.cookies.set("sid", token)
    assert client.get("/api/auth/me").status_code == 401


def test_signup_while_logged_in_ends_previous_session(client):
    client.post("/api/auth/signup", json=signup_body())
    first = client.cookies.get("sid")
    client.post("/api/auth/signup", json=signup_body(email="second.person@example.com", name="Second Person"))
    second = client.cookies.get("sid")
    assert first and second and first != second
    client.cookies.set("sid", first)
    assert client.get("/api/auth/me").status_code == 401
    client.cookies.set("sid", second)
    assert client.get("/api/auth/me").json()["user"]["email"] == "second.person@example.com"


def test_cookie_is_secure_in_production(client, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "cookie_secure", None)
    monkeypatch.setattr(get_settings(), "env", "production")
    res = client.post("/api/auth/signup", json=signup_body())
    assert res.status_code == 201
    assert "Secure" in res.headers["set-cookie"]


def test_logout_without_session_is_204(client):
    assert client.post("/api/auth/logout").status_code == 204


def test_expired_session_is_rejected(client, db):
    client.post("/api/auth/signup", json=signup_body())
    db.execute(update(Session).values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
    db.commit()
    assert client.get("/api/auth/me").status_code == 401


def test_garbage_cookie_is_rejected(client):
    client.cookies.set("sid", "x" * 500)
    assert client.get("/api/auth/me").status_code == 401


def test_api_responses_are_not_cacheable_and_have_security_headers(client):
    res = client.get("/api/auth/me")
    assert res.headers["cache-control"] == "no-store"
    assert res.headers["x-frame-options"] == "DENY"
    assert res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "frame-ancestors 'none'" in res.headers["content-security-policy"]


def test_cross_origin_post_is_blocked(client):
    res = client.post("/api/auth/signup", json=signup_body(), headers={"Origin": "https://evil.example"})
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "csrf_failed"


def test_cross_site_fetch_metadata_is_blocked(client):
    res = client.post("/api/auth/logout", headers={"Sec-Fetch-Site": "cross-site"})
    assert res.status_code == 403


def test_allowed_origin_post_passes(client):
    res = client.post("/api/auth/signup", json=signup_body(), headers={"Origin": "http://localhost:5173"})
    assert res.status_code == 201


def test_unknown_api_route_returns_json_404(client):
    res = client.get("/api/nope")
    assert res.status_code == 404
    assert res.json()["ok"] is False


def test_health_checks_database(client):
    assert client.get("/api/health").json() == {"ok": True, "db": "up"}
