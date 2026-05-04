"""Shared pytest fixtures."""

from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def default_policy_path() -> Path:
    return _REPO_ROOT / "policies" / "default_policy.yaml"


@pytest.fixture
def strict_policy_path() -> Path:
    return _REPO_ROOT / "policies" / "strict_policy.yaml"


@pytest.fixture
def permissive_policy_path() -> Path:
    return _REPO_ROOT / "policies" / "permissive_policy.yaml"
