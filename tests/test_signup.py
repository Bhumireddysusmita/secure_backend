import pytest
from sqlalchemy import func, select

from app.models import Session, User

from .conftest import signup_body


def test_signup_success_creates_user_and_session(client, db):
    res = client.post("/api/auth/signup", json=signup_body(email="  Ada.Testwell@Example.COM "))
    assert res.status_code == 201
    data = res.json()
    assert data["ok"] is True
    assert data["user"]["email"] == "ada.testwell@example.com"
    assert data["user"]["name"] == "Ada Testwell"
    assert "password" not in str(data).lower().replace("passwordhash", "")

    user = db.execute(select(User)).scalar_one()
    assert user.email == "ada.testwell@example.com"
    assert user.password_hash.startswith("$2b$") and "Sup3rSecret!" not in user.password_hash
    assert db.execute(select(func.count()).select_from(Session)).scalar_one() == 1


def test_signup_sets_secure_session_cookie(client):
    res = client.post("/api/auth/signup", json=signup_body())
    cookie = res.headers["set-cookie"]
    assert cookie.startswith("sid=")
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie
    assert "Path=/" in cookie
    assert "Max-Age=604800" in cookie


def test_session_token_is_stored_hashed(client, db):
    res = client.post("/api/auth/signup", json=signup_body())
    token = res.cookies.get("sid")
    stored = db.execute(select(Session.token_hash)).scalar_one()
    assert token and stored != token and len(stored) == 64


@pytest.mark.parametrize(
    ("overrides", "field", "message"),
    [
        ({"name": ""}, "name", "Full name is required"),
        ({"name": "A"}, "name", "at least 2"),
        ({"name": "A" * 81}, "name", "at most 80"),
        ({"name": "<script>alert(1)</script>"}, "name", "letters, single spaces"),
        ({"email": ""}, "email", "Email is required"),
        ({"email": "not-an-email"}, "email", "valid email"),
        ({"email": "a" * 250 + "@x.com"}, "email", "at most 254"),
        ({"password": "short1", "confirmPassword": "short1"}, "password", "at least 8"),
        ({"password": "allletters", "confirmPassword": "allletters"}, "password", "number"),
        ({"password": "12345678", "confirmPassword": "12345678"}, "password", "letter"),
        ({"password": "a1" * 37, "confirmPassword": "a1" * 37}, "password", "at most 72"),
        ({"confirmPassword": "Different123"}, "confirmPassword", "do not match"),
        ({"confirmPassword": ""}, "confirmPassword", "confirm"),
        ({"name": 123}, "name", "invalid value"),
        ({"password": "Abcdef12\x00x", "confirmPassword": "Abcdef12\x00x"}, "password", "aren't allowed"),
        ({"password": "Password1", "confirmPassword": "Password1"}, "password", "too common"),
        ({"password": "Testwell99", "confirmPassword": "Testwell99"}, "password", "name or email"),
        ({"acceptTerms": False}, "acceptTerms", "accept the terms"),
        ({"acceptTerms": "true"}, "acceptTerms", "accept the terms"),
    ],
)
def test_signup_invalid_input_returns_400_with_field_errors(client, db, overrides, field, message):
    res = client.post("/api/auth/signup", json=signup_body(**overrides))
    assert res.status_code == 400
    err = res.json()["error"]
    assert err["code"] == "validation_error"
    assert message.lower() in err["fields"][field].lower()
    assert db.execute(select(func.count()).select_from(User)).scalar_one() == 0


def test_signup_empty_body_reports_every_field(client):
    res = client.post("/api/auth/signup", json={})
    assert res.status_code == 400
    assert set(res.json()["error"]["fields"]) == {"name", "email", "password", "confirmPassword", "acceptTerms"}


@pytest.mark.parametrize("payload", ["not json", "[1,2,3]"])
def test_signup_non_object_body_returns_400(client, payload):
    res = client.post("/api/auth/signup", content=payload, headers={"Content-Type": "application/json"})
    assert res.status_code == 400
    assert res.json()["error"]["code"] == "invalid_request"


def test_signup_stores_normalised_name(client, db):
    res = client.post("/api/auth/signup", json=signup_body(name="  Ada     D’Angelo "))
    assert res.status_code == 201
    assert db.execute(select(User.name)).scalar_one() == "Ada D'Angelo"


def test_oversized_body_is_refused_before_parsing(client):
    res = client.post(
        "/api/auth/signup",
        content=b'{"name": "' + b"A" * 20_000 + b'"}',
        headers={"Content-Type": "application/json"},
    )
    assert res.status_code == 413
    assert res.json()["error"]["code"] == "payload_too_large"


def test_signup_form_encoded_body_is_rejected(client):
    res = client.post("/api/auth/signup", data=signup_body())
    assert res.status_code == 400


def test_signup_captcha_failure_returns_403(client, db):
    res = client.post("/api/auth/signup", json=signup_body(captchaToken="bad-token"))
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "captcha_failed"
    assert db.execute(select(func.count()).select_from(User)).scalar_one() == 0


def test_signup_missing_captcha_returns_403(client):
    body = signup_body()
    del body["captchaToken"]
    res = client.post("/api/auth/signup", json=body)
    assert res.status_code == 403


@pytest.mark.parametrize("dup_email", ["ada.testwell@example.com", "ADA.TESTWELL@EXAMPLE.COM", " Ada.Testwell@example.com "])
def test_signup_duplicate_email_returns_409(client, db, dup_email):
    assert client.post("/api/auth/signup", json=signup_body()).status_code == 201
    client.cookies.clear()
    res = client.post("/api/auth/signup", json=signup_body(email=dup_email, name="Other Person"))
    assert res.status_code == 409
    assert res.json()["error"]["code"] == "email_taken"
    assert db.execute(select(func.count()).select_from(User)).scalar_one() == 1


def test_signup_rate_limited_per_ip(client):
    for i in range(10):
        res = client.post("/api/auth/signup", json=signup_body(email=f"user{i}@example.com"))
        assert res.status_code == 201, res.text
    res = client.post("/api/auth/signup", json=signup_body(email="user10@example.com"))
    assert res.status_code == 429
    assert res.json()["error"]["code"] == "rate_limited"
    assert int(res.headers["retry-after"]) > 0


def test_signup_rate_limited_per_email(client):
    for _ in range(5):
        client.post("/api/auth/signup", json=signup_body(captchaToken="bad"))
    res = client.post("/api/auth/signup", json=signup_body())
    assert res.status_code == 429


def test_unique_constraint_enforced_in_database(db):
    from sqlalchemy.exc import IntegrityError

    db.add(User(name="One Person", email="dupe@example.com", password_hash="x"))
    db.commit()
    db.add(User(name="Two Person", email="dupe@example.com", password_hash="x"))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_lowercase_email_enforced_in_database(db):
    from sqlalchemy.exc import IntegrityError

    db.add(User(name="Upper Case", email="Upper@Example.com", password_hash="x"))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()
