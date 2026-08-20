"""ANU block alphabet, packing, and conditioning.

The public ANU endpoint returns 1024-character blocks. The alphabet was measured
empirically rather than assumed:

    113,664 harvested characters -> 63 distinct symbols
    [0-9A-Za-z_], i.e. base64url MINUS the '-' character
    Shannon entropy 5.9768 bits/char (theoretical max for 63 symbols: 5.9773)

The '-' character is genuinely absent, not merely rare: under a uniform 64-symbol
model its probability of never appearing in 113,664 draws is about e^-1800. So the
alphabet really is 63 symbols and each character carries log2(63) = 5.977 bits, not
the 6.0 bits a base64url assumption would give. That 0.4% gap is small, but entropy
accounting is the one place in this codebase where optimism is not allowed, so the
measured value is what gets used.

Storage: each character is packed into 6 bits. 63 symbol indices fit in 6 bits with
one code point spare, so packing is lossless and reversible while costing 25% less
disk than storing ASCII. Raw blocks are archived rather than conditioned output, so
the archive stays auditable and can be re-conditioned if this function ever changes.
"""

from __future__ import annotations

import hashlib
import math

try:                       # optional: only the bulk paths benefit
    import numpy as _np
except ImportError:        # pragma: no cover - core service runs without numpy
    _np = None

#: Measured alphabet, in a fixed order. Index into this list is the packed 6-bit code.
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"
ALPHABET_SIZE = len(ALPHABET)          # 63
ALPHABET_SET = frozenset(ALPHABET)
INDEX = {c: i for i, c in enumerate(ALPHABET)}

#: Bits of entropy per character, assuming a uniform draw over the alphabet.
BITS_PER_CHAR = math.log2(ALPHABET_SIZE)   # 5.9773

BLOCK_CHARS = 1024


class InvalidBlock(ValueError):
    """Raised when a response does not look like an entropy block."""


def validate(text: str, min_chars: int = 512) -> str:
    """Reject anything that is not a plausible entropy block.

    This is the gate that stops an HTML error page, a redirect body, or a truncated
    response from being archived as if it were quantum data. Everything downstream --
    the pool's entropy credit, the beacon's provenance -- assumes this check ran.
    """
    text = text.strip()
    if len(text) < min_chars:
        raise InvalidBlock(f"too short: {len(text)} chars")
    bad = set(text) - ALPHABET_SET
    if bad:
        sample = "".join(sorted(bad))[:16]
        raise InvalidBlock(f"characters outside the alphabet: {sample!r}")
    # A genuine block draws nearly uniformly, so it uses most of the alphabet. A
    # cached, padded, or degenerate response will not.
    if len(set(text)) < ALPHABET_SIZE * 0.6:
        raise InvalidBlock(f"only {len(set(text))} distinct symbols; looks degenerate")
    return text


#: Byte-value -> alphabet index lookup, for the vectorised path.
def _build_lookup():
    if _np is None:
        return None
    table = _np.full(256, 255, dtype=_np.uint8)
    for i, ch in enumerate(ALPHABET):
        table[ord(ch)] = i
    return table


_LOOKUP = _build_lookup()


def pack(text: str) -> bytes:
    """Pack alphabet characters into 6 bits each. Lossless; 1024 chars -> 768 bytes.

    The pure-Python path is fine for a single 1024-character block, but the offline
    analysis tooling packs millions of characters at once, where a per-character loop
    costs minutes. NumPy, when available, does the same transform as a bit-matrix
    reshape.
    """
    if _np is not None and len(text) > 4096:
        raw = _np.frombuffer(text.encode("ascii", "strict"), dtype=_np.uint8)
        idx = _LOOKUP[raw]
        if bool((idx == 255).any()):
            bad = chr(int(raw[int(_np.argmax(idx == 255))]))
            raise InvalidBlock(f"character {bad!r} is not in the alphabet")
        # Low 6 bits of each symbol, concatenated, then re-packed into bytes.
        bits = _np.unpackbits(idx[:, None], axis=1)[:, 2:].reshape(-1)
        return _np.packbits(bits).tobytes()

    acc = bits = 0
    out = bytearray()
    for ch in text:
        i = INDEX.get(ch)
        if i is None:
            raise InvalidBlock(f"character {ch!r} is not in the alphabet")
        acc = (acc << 6) | i
        bits += 6
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits:
        out.append((acc << (8 - bits)) & 0xFF)
    return bytes(out)


def unpack(data: bytes, n_chars: int) -> str:
    """Inverse of `pack`."""
    if _np is not None and n_chars > 4096:
        bits = _np.unpackbits(_np.frombuffer(data, dtype=_np.uint8))[:n_chars * 6]
        if len(bits) < n_chars * 6:
            raise InvalidBlock("packed data is shorter than the declared character count")
        groups = bits.reshape(n_chars, 6)
        padded = _np.zeros((n_chars, 8), dtype=_np.uint8)
        padded[:, 2:] = groups
        idx = _np.packbits(padded, axis=1).reshape(-1)
        if bool((idx >= ALPHABET_SIZE).any()):
            raise InvalidBlock("packed index is outside the alphabet")
        return "".join(ALPHABET[i] for i in idx.tolist())

    out = []
    acc = bits = 0
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 6 and len(out) < n_chars:
            bits -= 6
            i = (acc >> bits) & 0x3F
            if i >= ALPHABET_SIZE:
                raise InvalidBlock(f"packed index {i} is outside the alphabet")
            out.append(ALPHABET[i])
    return "".join(out)


def entropy_bits(n_chars: int) -> float:
    """Entropy carried by `n_chars` alphabet characters, under a uniform model."""
    return n_chars * BITS_PER_CHAR


def condition(text: str) -> bytes:
    """Hash-condition a block into uniform bytes.

    Output length is derived from the MEASURED entropy of the input, floored, so
    conditioning never produces more bytes than the source could justify. Using the
    base64url assumption of 6 bits/char would inflate a 1024-char block from its true
    6120 bits to a claimed 6144 -- a small lie, but the kind that compounds.

    Construction: a sponge-style absorb/squeeze over SHA-512. The input is split into
    one slice per output block; each step folds its slice into a running state and
    squeezes 64 bytes from it under a separate domain tag, so the emitted bytes are
    never the state itself.

    Two properties this shape buys, which the obvious implementation does not:

      * **Linear time.** Re-hashing the whole input once per output block is O(n^2);
        on a multi-megabyte archive that is hundreds of gigabytes of hashing. Here
        every input byte is absorbed exactly once.
      * **Entropy that scales with input.** Hashing everything into one 512-bit digest
        and expanding from it would cap the output at 512 bits of entropy no matter
        how much went in, which would quietly invalidate the pool's credit accounting
        for any input larger than 64 bytes. Chaining keeps later output blocks
        dependent on later input.

    SHA-512 in this arrangement is not a NIST-vetted conditioning function in the
    SP 800-90B sense, so `pool.py` credits this source well below the rate computed here.
    """
    raw = text.encode()
    target = int(len(text) * BITS_PER_CHAR) // 8
    if target <= 0:
        return b""

    n_blocks = (target + 63) // 64
    slice_len = max(1, (len(raw) + n_blocks - 1) // n_blocks)

    state = hashlib.sha512(b"beamline/anu/cond/v3").digest()
    out = bytearray()
    for i in range(n_blocks):
        chunk = raw[i * slice_len:(i + 1) * slice_len]
        state = hashlib.sha512(state + len(chunk).to_bytes(4, "big") + chunk).digest()
        out += hashlib.sha512(b"squeeze" + state + i.to_bytes(4, "big")).digest()
    return bytes(out[:target])


def block_id(text: str) -> str:
    """Stable identifier for a block, used for duplicate detection."""
    return hashlib.sha256(text.encode()).hexdigest()
