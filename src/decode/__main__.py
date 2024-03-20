"""Entrypoint with `python -m decode`."""

import sys

from .cli import entrypoint


if __name__ == "__main__":
    sys.modules["__main__"] = entrypoint  # type: ignore[assignment]  # pragma: no cover
    entrypoint()  # pragma: no cover
