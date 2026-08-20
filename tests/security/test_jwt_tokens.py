"""Tests for app.security.jwt_tokens."""

import jwt as pyjwt

from app.security.jwt_tokens import (
    generate_citizen_token,
    generate_employee_token,
    initialize_jwt_token,
)


def _decode_unverified(token: str) -> dict:
    return pyjwt.decode(token, options={"verify_signature": False})


# If this failed, legitimate citizens could be locked out even with a valid login.
def test_generate_citizen_token_has_correct_claims():
    token = generate_citizen_token("user-1", "session-1")

    payload = _decode_unverified(token)
    assert payload["sub"] == "user-1"
    assert payload["role"] == "CITIZEN"
    assert payload["session_id"] == "session-1"
    assert "exp" in payload
    assert "iat" in payload


# If this failed, employee-only checks (e.g. department-scoped access) would
# silently break because the department couldn't be determined from the token.
def test_generate_employee_token_includes_department_id():
    token = generate_employee_token("emp-1", "AGENT", "dept-42", "session-2")

    payload = _decode_unverified(token)
    assert payload["sub"] == "emp-1"
    assert payload["role"] == "AGENT"
    assert payload["department_id"] == "dept-42"
    assert payload["session_id"] == "session-2"


# If this failed, a token could leak a user's real password or email to
# anyone who simply decodes it (JWTs are signed, not encrypted).
def test_citizen_token_contains_no_password_or_email_field():
    token = generate_citizen_token("user-1", "session-1")

    payload = _decode_unverified(token)
    assert "password" not in payload
    assert "password_hash" not in payload
    assert "email" not in payload


# If this failed, a token could leak a user's real password or email to
# anyone who simply decodes it (JWTs are signed, not encrypted).
def test_employee_token_contains_no_password_or_email_field():
    token = generate_employee_token("emp-1", "AGENT", "dept-42", "session-2")

    payload = _decode_unverified(token)
    assert "password" not in payload
    assert "password_hash" not in payload
    assert "email" not in payload


# If this failed, initialize_jwt_token could issue the wrong token shape for
# a citizen, breaking every downstream permission check that relies on it.
def test_initialize_jwt_token_dispatches_to_citizen_shape():
    token = initialize_jwt_token("user-1", "CITIZEN", "session-1")

    payload = _decode_unverified(token)
    assert payload["role"] == "CITIZEN"
    assert payload["sub"] == "user-1"
