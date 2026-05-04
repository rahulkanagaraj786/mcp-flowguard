import pytest
from pathlib import Path

@pytest.fixture
def default_policy_path() -> Path:
    return Path(__file__).parent.parent / "policies" / "default_policy.yaml"

@pytest.fixture
def strict_policy_path() -> Path:
    return Path(__file__).parent.parent / "policies" / "strict_policy.yaml"

@pytest.fixture
def permissive_policy_path() -> Path:
    return Path(__file__).parent.parent / "policies" / "permissive_policy.yaml"
