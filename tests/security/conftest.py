"""Shared pytest fixtures for app.security tests."""

import pytest

from app.security.token_security import InMemoryRevocationStore, set_revocation_store


@pytest.fixture(autouse=True)
def _jwt_secret_env(monkeypatch):
    """Ensure JWT_SECRET_KEY is always set so security_config never raises."""
    monkeypatch.setenv("JWT_SECRET_KEY", "test-only-secret-do-not-use-in-prod")


@pytest.fixture(autouse=True)
def _in_memory_revocation_store():
    """Swap the module's revocation store for an in-memory fake.

    Ensures tests never require a running Redis instance, and that
    revocation state doesn't leak between tests.
    """
    set_revocation_store(InMemoryRevocationStore())
