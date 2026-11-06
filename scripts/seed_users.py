"""Development seed: create the 25 synthetic identities in the MAIN app database so a person can
log in as them by hand (e.g. for the demo recording). Not a test; the E2E suite never uses this.

  python scripts/seed_users.py           # create missing users (existing emails are skipped)
  python scripts/seed_users.py --remove  # delete exactly these 25 users again

Reads the identities from test-data/identities.json (git-ignored; run
`node scripts/generate-identities.mjs ...` first) and one shared demo password from
SEED_USER_PASSWORD in backend/.env. The password is validated with the app's own rules,
hashed with bcrypt, and never printed. Users are inserted directly through the app's models,
so no CAPTCHA is involved: this is setup data, like a database seed, not a sign-up.
Refuses to run when APP_ENV=production.
"""

import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from sqlalchemy import delete, select  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.models import User  # noqa: E402
from app.security.password import hash_password  # noqa: E402
from app.utils import mask_email  # noqa: E402
from app.validation import check_email, check_name, check_new_password  # noqa: E402

settings = get_settings()
if settings.env == "production":
    sys.exit("Refusing to seed demo users when APP_ENV=production.")

identities_file = BACKEND.parent / "test-data" / "identities.json"
if not identities_file.exists():
    sys.exit("test-data/identities.json not found: run `node scripts/generate-identities.mjs --fake-gmail` (or with approved addresses) first.")
data = json.loads(identities_file.read_text("utf-8"))
people = data["identities"]

remove = "--remove" in sys.argv
db_name = settings.database_url.rsplit("/", 1)[-1].split("?")[0]

with SessionLocal() as db:
    emails = [p["email"].strip().lower() for p in people]

    if remove:
        result = db.execute(delete(User).where(User.email.in_(emails)))
        db.commit()
        print(f"Removed {result.rowcount} seeded users from database '{db_name}'.")
        sys.exit(0)

    from dotenv import dotenv_values  # noqa: E402

    password = dotenv_values(BACKEND / ".env").get("SEED_USER_PASSWORD")
    if not password:
        sys.exit("Set SEED_USER_PASSWORD in backend/.env (git-ignored) first.")

    existing = set(db.execute(select(User.email).where(User.email.in_(emails))).scalars())
    created = skipped = 0
    for p in people:
        name, name_err = check_name(p["fullName"])
        email, email_err = check_email(p["email"])
        _, pw_err = check_new_password(password, name, email)
        if name_err or email_err or pw_err:
            sys.exit(f"{p['id']}: rejected by the app's validation rules ({name_err or email_err or pw_err}).")
        if email in existing:
            skipped += 1
            print(f"  {p['id']}  {mask_email(email):34} already exists, skipped")
            continue
        db.add(User(name=name, email=email, password_hash=hash_password(password)))  # own salt per user
        created += 1
        print(f"  {p['id']}  {mask_email(email):34} created")
    db.commit()

print(f"\nDatabase '{db_name}': {created} created, {skipped} already present.")
print(f"Email source: {data.get('emailSource', 'unknown')}")
print("Log in with any of these emails and the SEED_USER_PASSWORD value from backend/.env (not printed here).")
