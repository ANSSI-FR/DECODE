"""Main module."""

from .cli import entrypoint
from .core import analyse, prepare_orc
from .info import (
    __author__,
    __copyright__,
    __description__,
    __email__,
    __license__,
    __maintainer__,
    __project__,
    __version__,
)


__all__ = [
    "__author__",
    "__copyright__",
    "__description__",
    "__email__",
    "__license__",
    "__maintainer__",
    "__project__",
    "__version__",
    "analyse",
    "entrypoint",
    "prepare_orc",
]
