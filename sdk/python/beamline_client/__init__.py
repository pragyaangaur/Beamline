"""Beamline client and independent beacon verifier.

The verifier is importable on its own. `verify.py` promises it needs nothing but the
standard library plus `cryptography`, and that promise is the reason a sceptic is
willing to read it -- but importing it through this package used to drag in
`client.py`, and with it `httpx`. So anybody who wanted to check a draw had to install
an HTTP client first, to run code that never makes a request.

    from beamline_client import check_draw        # no httpx needed
    from beamline_client import Beamline          # httpx needed, imported now

The client is resolved lazily by `__getattr__` (PEP 562) so the two stay separable.
"""

# Defined before the submodule imports below, so `client.py` can read it without
# creating a circular import back into this package.
__version__ = "1.0.0"

from .verify import (check_chain, check_commitment, check_draw, check_pulse,
                     check_rotation, items_digest, reproduce_bytes,
                     reproduce_integers, reproduce_sample, reproduce_shuffle,
                     reproduce_unique_integers)

#: Names that live in `client.py` and therefore need httpx.
_CLIENT_NAMES = {"Beamline", "BeamlineError", "RateLimited", "QuotaExceeded", "FairDraw"}

__all__ = [
    "Beamline", "BeamlineError", "RateLimited", "QuotaExceeded", "FairDraw",
    "check_pulse", "check_chain", "check_commitment", "check_draw", "check_rotation",
    "items_digest", "reproduce_bytes", "reproduce_integers", "reproduce_sample",
    "reproduce_shuffle", "reproduce_unique_integers",
    "__version__",
]


def __getattr__(name: str):
    """Import the HTTP client only when something actually asks for it."""
    if name in _CLIENT_NAMES:
        from . import client
        return getattr(client, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(__all__)
