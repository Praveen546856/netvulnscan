import pytest

from app.store import limiter, store


@pytest.fixture(autouse=True)
def clean_state():
    """Each test starts with empty history and no rate-limit usage."""
    store.clear()
    limiter.reset()
    yield
    store.clear()
    limiter.reset()
