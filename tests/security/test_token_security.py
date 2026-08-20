"""Tests for app.security.token_security."""

import jwt as pyjwt
import pytest

from app.security.jwt_tokens import generate_citizen_token, generate_employee_token
from app.security.security_errors import (
    ExpiredTokenError,
    InvalidTokenError,
    RevokedTokenError,
    WrongTokenTypeError,
)
from app.security.token_security import revoke_token, validate_token


# If this failed, a legitimate citizen with a valid, unexpired token could be
# wrongly denied access to their own account.
def test_valid_citizen_token_validates_and_returns_correct_claims():
    token = generate_citizen_token("user-1", "session-1")

    claims = validate_token(token)

    assert claims.user_id == "user-1"
    assert claims.role == "CITIZEN"
    assert claims.session_id == "session-1"
    assert claims.department_id is None


# If this failed, an expired token (e.g. stolen from an old browser tab or
# intercepted traffic) could still be used to authenticate indefinitely.
def test_expired_token_raises_expired_token_error():
    token = generate_citizen_token("user-1", "session-1", expiry_minutes=-1)

    with pytest.raises(ExpiredTokenError):
        validate_token(token)


# If this failed, anyone could forge a token by signing it with their own
# secret and have the server accept it as genuine.
def test_token_signed_with_different_secret_raises_invalid_token_error():
    forged_token = pyjwt.encode(
        {"sub": "attacker", "role": "CITIZEN", "session_id": "s1", "iat": 0, "exp": 9999999999},
        "a-completely-different-secret",
        algorithm="HS256",
    )

    with pytest.raises(InvalidTokenError):
        validate_token(forged_token)


# If this failed, an attacker could tamper with a token's payload (e.g.
# change their role to ADMIN) and have the server trust the modified claims.
def test_tampered_token_payload_raises_invalid_token_error():
    token = generate_citizen_token("user-1", "session-1")
    header, payload, signature = token.split(".")

    tampered_char = "A" if payload[-1] != "A" else "B"
    tampered_payload = payload[:-1] + tampered_char
    tampered_token = f"{header}.{tampered_payload}.{signature}"

    with pytest.raises(InvalidTokenError):
        validate_token(tampered_token)


# If this failed, logging out or force-revoking a compromised session would
# have no effect — the old token would keep working until it naturally expired.
def test_revoked_session_raises_revoked_token_error():
    token = generate_citizen_token("user-1", "session-1")
    revoke_token("session-1", "user-1")

    with pytest.raises(RevokedTokenError):
        validate_token(token)


# If this failed, a citizen's token could be used to access employee-only
# endpoints simply by being presented where an employee token was expected.
def test_citizen_token_with_expected_employee_type_raises_wrong_token_type_error():
    token = generate_citizen_token("user-1", "session-1")

    with pytest.raises(WrongTokenTypeError):
        validate_token(token, expected_user_type="EMPLOYEE")


# If this failed, an employee token could pass validation for a citizen-only
# endpoint despite carrying different permissions than a citizen role.
def test_employee_token_with_expected_citizen_type_raises_wrong_token_type_error():
    token = generate_employee_token("emp-1", "AGENT", "dept-1", "session-2")

    with pytest.raises(WrongTokenTypeError):
        validate_token(token, expected_user_type="CITIZEN")
