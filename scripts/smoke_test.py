"""End-to-end smoke test: frontend dev server -> /api proxy -> FastAPI -> PostgreSQL.

Usage (with both servers running and Turnstile's always-pass TEST secret configured):
    python scripts/smoke_test.py [http://localhost:5173]

Prints one masked line per step and exits non-zero on the first failure.
"""

import sys
import time

import httpx
from sqlalchemy import func, select

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))

from app.db import SessionLocal  # noqa: E402
from app.models import User  # noqa: E402
from app.utils import mask_email  # noqa: E402

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5173").rstrip("/")
# Cloudflare's test site keys issue this dummy token; the always-pass test secret accepts it.
TOKEN = "XXXX.DUMMY.TOKEN.XXXX"

email = f"smoke.user{int(time.time())}@example.com"
password = "Smoke" + str(int(time.time()))[-6:] + "a"
results: list[tuple[str, bool, str]] = []


def step(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")
    if not ok:
        sys.exit(1)


with httpx.Client(base_url=BASE, headers={"Origin": BASE}, timeout=15) as c:
    step("frontend serves index.html", c.get("/").status_code == 200 and "<div id=\"root\">" in c.get("/").text)
    step("api health via proxy", c.get("/api/health").json().get("db") == "up")

    r = c.post("/api/auth/signup", json={"name": "Smoke Tester", "email": email, "password": password, "confirmPassword": password, "acceptTerms": True, "captchaToken": TOKEN})
    step("signup -> 201", r.status_code == 201, f"status={r.status_code} email={mask_email(email)}")
    step("session cookie HttpOnly + SameSite=Lax", "httponly" in r.headers.get("set-cookie", "").lower() and "samesite=lax" in r.headers.get("set-cookie", "").lower())

    with SessionLocal() as db:
        count = db.execute(select(func.count()).select_from(User).where(User.email == email)).scalar_one()
    step("exactly one DB row for email", count == 1, f"rows={count}")

    step("me -> 200 after signup", c.get("/api/auth/me").status_code == 200)
    step("logout -> 204", c.post("/api/auth/logout").status_code == 204)
    step("me -> 401 after logout", c.get("/api/auth/me").status_code == 401)

    r = c.post("/api/auth/login", json={"email": email.upper(), "password": "wrong-pass-1", "captchaToken": TOKEN})
    step("wrong password -> 401 generic", r.status_code == 401 and r.json()["error"]["message"] == "Incorrect email or password")

    r = c.post("/api/auth/login", json={"email": email.upper(), "password": password, "captchaToken": TOKEN})
    step("login (case-insensitive email) -> 200", r.status_code == 200, f"name={r.json().get('user', {}).get('name')}")
    step("me -> 200 after login", c.get("/api/auth/me").json()["user"]["email"] == email)

    r = c.post("/api/auth/signup", json={"name": "Smoke Dup", "email": email, "password": password, "confirmPassword": password, "acceptTerms": True, "captchaToken": TOKEN})
    step("duplicate signup -> 409", r.status_code == 409)

    r = c.post("/api/auth/login", json={"email": email, "password": password})
    step("missing CAPTCHA -> 403", r.status_code == 403)

    r = c.post("/api/auth/logout", headers={"Origin": "https://evil.example"})
    step("cross-origin POST -> 403", r.status_code == 403)

    step("logout -> 204", c.post("/api/auth/logout").status_code == 204)

print(f"\n{sum(ok for _, ok, _ in results)}/{len(results)} checks passed")
