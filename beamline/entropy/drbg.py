"""HMAC_DRBG (SHA-512) -- NIST SP 800-90A Rev. 1, section 10.1.2.

Why a DRBG rather than shipping source bytes straight through:

  * A network entropy source is finite and slow. ANU gives ~1KB/s on a good day;
    a single customer asking for a 1MB key file would drain it for 15 minutes.
  * Bytes that arrive over someone else's TLS connection are not bytes you can
    prove are untampered. Feeding them into a pool alongside the local kernel CSPRNG
    means an adversary must compromise *every* source to predict output, instead of
    just the one you resell.
  * Backtracking resistance. Raw passthrough leaks nothing about the future but a
    DRBG state compromise is bounded by the reseed interval, and each generate call
    ratchets the key forward.

So: physical sources are the *seed material*, the DRBG is the *delivery mechanism*.
This is the same shape as /dev/urandom, Cloudflare's LavaRand, and every hardware
RNG vendor's driver stack. The randomness is real; the throughput is engineering.
"""

from __future__ import annotations

import hashlib
import hmac
import threading

HASH = hashlib.sha512
OUTLEN = 64
# SP 800-90A caps a single generate call at 2^19 bits; we chunk internally to respect it.
MAX_BYTES_PER_GENERATE = 1 << 16
# Reseed interval is capped by policy in service.py, far below the 2^48 spec limit.


class HmacDrbg:
    """Thread-safe HMAC_DRBG. One instance per process; `service.py` owns the singleton."""

    def __init__(self, entropy: bytes, nonce: bytes = b"", personalization: bytes = b""):
        if len(entropy) < 32:
            raise ValueError("HMAC_DRBG requires >= 32 bytes of seed entropy")
        self._lock = threading.Lock()
        self._k = b"\x00" * OUTLEN
        self._v = b"\x01" * OUTLEN
        self.reseed_counter = 0
        self.bytes_generated = 0
        self.reseeds = 0
        self._update(entropy + nonce + personalization)

    # --- internals --------------------------------------------------------
    def _hmac(self, key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, HASH).digest()

    def _update(self, provided: bytes = b"") -> None:
        """SP 800-90A 10.1.2.2 HMAC_DRBG_Update."""
        self._k = self._hmac(self._k, self._v + b"\x00" + provided)
        self._v = self._hmac(self._k, self._v)
        if provided:
            self._k = self._hmac(self._k, self._v + b"\x01" + provided)
            self._v = self._hmac(self._k, self._v)

    # --- public API -------------------------------------------------------
    def reseed(self, entropy: bytes, additional: bytes = b"") -> None:
        if len(entropy) < 32:
            raise ValueError("reseed requires >= 32 bytes of entropy")
        with self._lock:
            self._update(entropy + additional)
            self.reseed_counter = 0
            self.reseeds += 1

    def generate(self, n: int, additional: bytes = b"") -> bytes:
        if n <= 0:
            raise ValueError("n must be positive")
        out = bytearray()
        with self._lock:
            while len(out) < n:
                want = min(n - len(out), MAX_BYTES_PER_GENERATE)
                out += self._generate_locked(want, additional)
                additional = b""  # only mixed in on the first chunk
            self.reseed_counter += 1
            self.bytes_generated += n
        return bytes(out)

    def _generate_locked(self, n: int, additional: bytes) -> bytes:
        if additional:
            self._update(additional)
        buf = bytearray()
        while len(buf) < n:
            self._v = self._hmac(self._k, self._v)
            buf += self._v
        # Ratchet forward so the state that produced these bytes cannot be recovered
        # from the state that survives this call (backtracking resistance).
        self._update(additional)
        return bytes(buf[:n])

    def stats(self) -> dict:
        return {
            "algorithm": "HMAC_DRBG(SHA-512), NIST SP 800-90A",
            "bytes_generated": self.bytes_generated,
            "reseeds": self.reseeds,
            "requests_since_reseed": self.reseed_counter,
        }
