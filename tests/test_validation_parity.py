"""Runs test-data/validation-cases.json against the server rules.

frontend/src/lib/validation.test.ts runs the same file against the browser rules, so the
two implementations can't drift apart.
"""

import json
from pathlib import Path

import pytest

from app.validation import ValidationFailed, validate_login, validate_signup

DATA = json.loads((Path(__file__).resolve().parents[2] / "test-data" / "validation-cases.json").read_text("utf-8"))


def expand(value):
    if isinstance(value, dict) and "$repeat" in value:
        text, times = value["$repeat"]
        return text * times + value.get("$suffix", "")
    return value


def build_body(case):
    if "body" in case:
        return {k: expand(v) for k, v in case["body"].items()}
    base = dict(DATA["signupBase"] if case["form"] == "signup" else DATA["loginBase"])
    base.update({k: expand(v) for k, v in case["set"].items()})
    return base


@pytest.mark.parametrize("case", DATA["cases"], ids=[c["id"] for c in DATA["cases"]])
def test_server_rules_match_shared_cases(case):
    validate = validate_signup if case["form"] == "signup" else validate_login
    try:
        validate(build_body(case))
        errors = {}
    except ValidationFailed as exc:
        errors = exc.fields
    assert errors == case["expect"]


def test_name_is_normalised_before_saving():
    body = build_body({"form": "signup", "set": {"name": "  Ada     D’Angelo  "}})
    assert validate_signup(body).name == "Ada D'Angelo"


def test_email_is_normalised_before_saving():
    body = build_body({"form": "signup", "set": {"email": "  ADA.Testwell@Example.COM "}})
    assert validate_signup(body).email == "ada.testwell@example.com"
