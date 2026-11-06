import pytest

from .conftest import login_body, signup_body


@pytest.fixture
def registered(client):
    assert client.post("/api/auth/signup", json=signup_body()).status_code == 201
    client.cookies.clear()


def test_login_success_sets_cookie_and_returns_user(client, registered):
    res = client.post("/api/auth/login", json=login_body(email="ADA.Testwell@example.com"))
    assert res.status_code == 200
    assert res.json()["user"]["email"] == "ada.testwell@example.com"
    assert "HttpOnly" in res.headers["set-cookie"]
    assert client.get("/api/auth/me").status_code == 200


def test_wrong_password_and_unknown_email_get_identical_401(client, registered):
    wrong = client.post("/api/auth/login", json=login_body(password="WrongPass123"))
    unknown = client.post("/api/auth/login", json=login_body(email="nobody@example.com"))
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()
    assert wrong.json()["error"]["message"] == "Incorrect email or password"
    assert "set-cookie" not in wrong.headers


@pytest.mark.parametrize(
    ("overrides", "field"),
    [({"email": ""}, "email"), ({"email": "bad"}, "email"), ({"password": ""}, "password"), ({"password": "x" * 73}, "password")],
)
def test_login_invalid_input_returns_400(client, overrides, field):
    res = client.post("/api/auth/login", json=login_body(**overrides))
    assert res.status_code == 400
    assert field in res.json()["error"]["fields"]


def test_login_captcha_failure_returns_403(client, registered):
    res = client.post("/api/auth/login", json=login_body(captchaToken="nope"))
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "captcha_failed"


def test_login_missing_captcha_returns_403(client, registered):
    body = login_body()
    del body["captchaToken"]
    assert client.post("/api/auth/login", json=body).status_code == 403


def test_brute_force_lockout_after_five_failures(client, registered):
    for _ in range(5):
        assert client.post("/api/auth/login", json=login_body(password="WrongPass123")).status_code == 401
    res = client.post("/api/auth/login", json=login_body(password="WrongPass123"))
    assert res.status_code == 429
    assert int(res.headers["retry-after"]) > 0
    # Even the correct password is refused while locked out.
    assert client.post("/api/auth/login", json=login_body()).status_code == 429


def test_successful_login_resets_failure_count(client, registered):
    for _ in range(4):
        client.post("/api/auth/login", json=login_body(password="WrongPass123"))
    assert client.post("/api/auth/login", json=login_body()).status_code == 200
    for _ in range(4):
        assert client.post("/api/auth/login", json=login_body(password="WrongPass123")).status_code == 401


def test_login_rate_limited_per_ip(client):
    for i in range(20):
        assert client.post("/api/auth/login", json=login_body(email=f"u{i}@example.com")).status_code == 401
    res = client.post("/api/auth/login", json=login_body(email="u99@example.com"))
    assert res.status_code == 429


def test_successful_logins_do_not_count_toward_ip_limit(client, registered):
    # 25 people behind one office IP logging in correctly must not be blocked.
    for _ in range(25):
        assert client.post("/api/auth/login", json=login_body()).status_code == 200


def test_ip_limit_counts_captcha_failures(client):
    for i in range(20):
        assert client.post("/api/auth/login", json=login_body(email=f"c{i}@example.com", captchaToken="bad")).status_code == 403
    assert client.post("/api/auth/login", json=login_body(email="c99@example.com")).status_code == 429


def test_login_rotates_session(client, registered):
    client.post("/api/auth/login", json=login_body())
    first = client.cookies.get("sid")
    client.post("/api/auth/login", json=login_body())
    second = client.cookies.get("sid")
    assert first and second and first != second
    # Logging in again from the same browser invalidates the previous session token.
    client.cookies.set("sid", first)
    assert client.get("/api/auth/me").status_code == 401
    client.cookies.set("sid", second)
    assert client.get("/api/auth/me").status_code == 200
