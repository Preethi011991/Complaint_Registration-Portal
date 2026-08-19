"""Tests for app.security.password."""

from app.security.password import (
    hash_password,
    validate_password_strength,
    verify_password,
)


# If this failed, two users with the same password would get identical
# stored hashes, making the database vulnerable to rainbow-table attacks.
def test_hash_password_produces_different_hash_each_time_for_same_input():
    hash_one = hash_password("correct-horse-battery-1")
    hash_two = hash_password("correct-horse-battery-1")

    assert hash_one != hash_two


# If this failed, legitimate users would be locked out of their own accounts.
def test_verify_password_returns_true_for_correct_password():
    password = "correct-horse-battery-1"
    password_hash = hash_password(password)

    assert verify_password(password, password_hash) is True


# If this failed, anyone could log in as anyone else without knowing their password.
def test_verify_password_returns_false_for_wrong_password():
    password_hash = hash_password("correct-horse-battery-1")

    assert verify_password("wrong-password-1", password_hash) is False


# If this failed, a single corrupted database row could crash the login endpoint.
def test_verify_password_returns_false_for_malformed_hash():
    assert verify_password("any-password-1", "not-a-real-argon2-hash") is False


# If this failed, users could set passwords too short to resist brute-forcing.
def test_validate_password_strength_rejects_too_short_password():
    is_valid, reasons = validate_password_strength("ab1")

    assert is_valid is False
    assert any("8 characters" in reason for reason in reasons)


# If this failed, users could set all-letter passwords that are easier to guess.
def test_validate_password_strength_rejects_password_with_no_digit():
    is_valid, reasons = validate_password_strength("abcdefgh")

    assert is_valid is False
    assert any("digit" in reason for reason in reasons)


# If this failed, users could set all-digit passwords that are easier to guess.
def test_validate_password_strength_rejects_password_with_no_letter():
    is_valid, reasons = validate_password_strength("12345678")

    assert is_valid is False
    assert any("letter" in reason for reason in reasons)


# If this failed, valid passwords could be wrongly rejected, blocking signups.
def test_validate_password_strength_accepts_valid_password():
    is_valid, reasons = validate_password_strength("abcdefg1")

    assert is_valid is True
    assert reasons == []


# If this failed, the UI would only show one problem at a time instead of
# letting the user fix every issue before resubmitting.
def test_validate_password_strength_returns_multiple_reasons_when_multiple_rules_fail():
    is_valid, reasons = validate_password_strength("ab")

    assert is_valid is False
    assert len(reasons) >= 2
    assert any("8 characters" in reason for reason in reasons)
    assert any("digit" in reason for reason in reasons)
