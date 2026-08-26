"""Shaping raw bytes into the things people actually ask for.

Every function here takes a `rand(n) -> bytes` callable so the same code drives both
the live DRBG and deterministic beacon derivation. That symmetry is the point: a
customer can reproduce a beacon-derived draw exactly, using the published pulse, with
the same algorithm the server ran.

The recurring correctness hazard in this file is modulo bias. `rand(4) % 6` is not a
fair die -- 2^32 is not divisible by 6, so faces 0 and 1 come up marginally more often.
It is a small bias, but the entire premise of the product is that the numbers are
unbiased, and a customer running a lottery is exactly the customer who would find it.
So every bounded draw below uses rejection sampling.
"""

from __future__ import annotations

import math
from typing import Callable

Rand = Callable[[int], bytes]

MAX_COUNT = 10_000


def _bits_needed(span: int) -> int:
    return max(1, span.bit_length())


def bounded_int(rand: Rand, span: int) -> int:
    """Uniform integer in [0, span) via rejection sampling. `span` must be > 0."""
    if span <= 0:
        raise ValueError("span must be positive")
    if span == 1:
        return 0
    bits = _bits_needed(span - 1)
    nbytes = (bits + 7) // 8
    mask = (1 << bits) - 1
    # Expected iterations < 2 by construction, since mask+1 < 2*span.
    while True:
        v = int.from_bytes(rand(nbytes), "big") & mask
        if v < span:
            return v


def integers(rand: Rand, count: int, minimum: int, maximum: int, unique: bool = False) -> list[int]:
    """`count` uniform integers in the inclusive range [minimum, maximum]."""
    if count < 1 or count > MAX_COUNT:
        raise ValueError(f"count must be between 1 and {MAX_COUNT}")
    if minimum > maximum:
        raise ValueError("min must be <= max")
    span = maximum - minimum + 1
    if unique:
        if count > span:
            raise ValueError(f"cannot draw {count} unique values from a range of {span}")
        return [minimum + v for v in _sample_indices(rand, span, count)]
    return [minimum + bounded_int(rand, span) for _ in range(count)]


def _sample_indices(rand: Rand, span: int, count: int) -> list[int]:
    """`count` distinct values from [0, span) without materialising the full range.

    Two strategies, because a lottery drawing 6 of 49 and an audit sampling 10k of
    10M are different problems. Dense case: partial Fisher-Yates over a real list.
    Sparse case: draw-and-reject against a set, which is cheap while count << span.
    """
    if span <= 4 * count or span <= 4096:
        pool = list(range(span))
        for i in range(count):
            j = i + bounded_int(rand, span - i)
            pool[i], pool[j] = pool[j], pool[i]
        return pool[:count]
    seen: set[int] = set()
    out: list[int] = []
    while len(out) < count:
        v = bounded_int(rand, span)
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def floats(rand: Rand, count: int, precision: int = 17) -> list[float]:
    """Uniform floats in [0, 1).

    Built from 53 random bits divided by 2^53 -- every representable double in the
    interval with a uniform mantissa, and no chance of returning exactly 1.0 the way
    naive `int/2**64` rounding can.
    """
    if count < 1 or count > MAX_COUNT:
        raise ValueError(f"count must be between 1 and {MAX_COUNT}")
    if not 1 <= precision <= 17:
        raise ValueError("precision must be between 1 and 17")
    out = []
    for _ in range(count):
        v = (int.from_bytes(rand(7), "big") >> 3) / (1 << 53)
        out.append(round(v, precision) if precision < 17 else v)
    return out


def gaussian(rand: Rand, count: int, mean: float = 0.0, stddev: float = 1.0) -> list[float]:
    """Normal deviates via Box-Muller. Requested often enough for simulation work to belong here."""
    if count < 1 or count > MAX_COUNT:
        raise ValueError(f"count must be between 1 and {MAX_COUNT}")
    if stddev <= 0:
        raise ValueError("stddev must be positive")
    out: list[float] = []
    while len(out) < count:
        u1 = (int.from_bytes(rand(7), "big") >> 3) / (1 << 53)
        u2 = (int.from_bytes(rand(7), "big") >> 3) / (1 << 53)
        if u1 <= 0.0:
            continue  # log(0) guard; probability ~2^-53 but it would crash the request
        r = math.sqrt(-2.0 * math.log(u1))
        out.append(mean + stddev * r * math.cos(2 * math.pi * u2))
        if len(out) < count:
            out.append(mean + stddev * r * math.sin(2 * math.pi * u2))
    return out[:count]


def shuffle(rand: Rand, items: list) -> list:
    """Fisher-Yates. Unbiased over all n! permutations, given an unbiased `bounded_int`."""
    if len(items) > MAX_COUNT:
        raise ValueError(f"cannot shuffle more than {MAX_COUNT} items")
    out = list(items)
    for i in range(len(out) - 1, 0, -1):
        j = bounded_int(rand, i + 1)
        out[i], out[j] = out[j], out[i]
    return out


def sample(rand: Rand, items: list, count: int) -> list:
    """`count` items drawn without replacement."""
    if count > len(items):
        raise ValueError("count exceeds population size")
    return [items[i] for i in _sample_indices(rand, len(items), count)]


def uuid4(rand: Rand, count: int) -> list[str]:
    """RFC 4122 version 4 UUIDs: 122 random bits with the version and variant fixed."""
    if count < 1 or count > MAX_COUNT:
        raise ValueError(f"count must be between 1 and {MAX_COUNT}")
    out = []
    for _ in range(count):
        b = bytearray(rand(16))
        b[6] = (b[6] & 0x0F) | 0x40
        b[8] = (b[8] & 0x3F) | 0x80
        h = b.hex()
        out.append(f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}")
    return out


PASSWORD_SETS = {
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "digits": "0123456789",
    "symbols": "!#$%&*+-=?@^_~",
    # No ambiguous glyphs, safe to read aloud or write down.
    "unambiguous": "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789",
}


def password(rand: Rand, count: int, length: int = 20, charset: str = "unambiguous") -> list[dict]:
    if count < 1 or count > 1000:
        raise ValueError("count must be between 1 and 1000")
    if not 8 <= length <= 256:
        raise ValueError("length must be between 8 and 256")
    alphabet = PASSWORD_SETS.get(charset)
    if alphabet is None:
        raise ValueError(f"unknown charset; choose from {sorted(PASSWORD_SETS)}")
    bits = round(length * math.log2(len(alphabet)), 1)
    return [
        {
            "value": "".join(alphabet[bounded_int(rand, len(alphabet))] for _ in range(length)),
            "entropy_bits": bits,
        }
        for _ in range(count)
    ]


def dice(rand: Rand, count: int, sides: int = 6) -> list[int]:
    if not 2 <= sides <= 1000:
        raise ValueError("sides must be between 2 and 1000")
    return integers(rand, count, 1, sides)


def weighted_choice(rand: Rand, items: list, weights: list[float], count: int) -> list:
    """Weighted draw with replacement, over integer-scaled cumulative weights.

    Scaling to integers before drawing keeps the selection exactly uniform over the
    scaled space. Doing this in floating point would make the true probabilities
    depend on accumulated rounding error -- invisible, but real, and unacceptable in
    anything a customer might have to defend to a regulator.
    """
    if len(items) != len(weights):
        raise ValueError("items and weights must be the same length")
    if any(w < 0 for w in weights):
        raise ValueError("weights must be non-negative")
    scale = 1 << 32
    total_w = sum(weights)
    if total_w <= 0:
        raise ValueError("weights must sum to a positive value")
    cum: list[int] = []
    acc = 0
    for w in weights:
        acc += int(w / total_w * scale)
        cum.append(acc)

    # Absorb rounding drift into the last bucket ENTITLED to it, which is the last one
    # with a positive weight rather than simply the last one.
    #
    # `cum[-1] = scale` handed the remainder to whatever came last, weight zero
    # included. With weights [1, 1, 1, 0] the thirds truncate to 4294967295 and the
    # final assignment opened a single value of the 2^32 to the entry that had been
    # weighted out, so an excluded entrant won with probability 2^-32. Rare is not the
    # same as impossible, and "that person could not have won" is the entire claim a
    # weighted draw makes. Levelling every trailing bucket to `scale` makes each of
    # them unreachable, since selecting index i requires v < cum[i] and v >= cum[i-1].
    #
    # Granularity limit, stated rather than hidden: a weight below total_w / 2^32
    # truncates to no share at all. At that point the caller is asking for odds this
    # scale cannot represent, and rounding them up would be the same lie in reverse.
    last_funded = max((i for i, w in enumerate(weights) if w > 0), default=-1)
    for i in range(last_funded, len(cum)):
        cum[i] = scale

    out = []
    for _ in range(count):
        v = bounded_int(rand, scale)
        lo, hi = 0, len(cum) - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if v < cum[mid]:
                hi = mid
            else:
                lo = mid + 1
        out.append(items[lo])
    return out
