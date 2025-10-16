"""Sentinels required by Starlette's test client."""

class UseClientDefault:
    """Placeholder sentinel mimicking httpx behaviour."""

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "USE_CLIENT_DEFAULT"


USE_CLIENT_DEFAULT = UseClientDefault()
