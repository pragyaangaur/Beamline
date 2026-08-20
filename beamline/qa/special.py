"""Special functions for the NIST test suites.

Implemented directly rather than pulled from SciPy so the randomness test suite runs
with only NumPy installed. The algorithms are the standard ones from Numerical Recipes;
igamc in particular is the workhorse behind almost every chi-square p-value in
SP 800-22, so it is worth having under local control and covered by tests.
"""

from __future__ import annotations

import math

MAXIT = 300
EPS = 3.0e-16
FPMIN = 1.0e-300


def gammln(x: float) -> float:
    return math.lgamma(x)


def _gser(a: float, x: float) -> float:
    """Lower regularized incomplete gamma P(a,x) by series expansion. Good for x < a+1."""
    if x <= 0.0:
        return 0.0
    ap = a
    total = delta = 1.0 / a
    for _ in range(MAXIT):
        ap += 1.0
        delta *= x / ap
        total += delta
        if abs(delta) < abs(total) * EPS:
            break
    return total * math.exp(-x + a * math.log(x) - gammln(a))


def _gcf(a: float, x: float) -> float:
    """Upper regularized incomplete gamma Q(a,x) by continued fraction. Good for x >= a+1."""
    b = x + 1.0 - a
    c = 1.0 / FPMIN
    d = 1.0 / b
    h = d
    for i in range(1, MAXIT + 1):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < FPMIN:
            d = FPMIN
        c = b + an / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < EPS:
            break
    return math.exp(-x + a * math.log(x) - gammln(a)) * h


def igamc(a: float, x: float) -> float:
    """Upper regularized incomplete gamma function Q(a, x) = 1 - P(a, x).

    This is the chi-square survival function used throughout SP 800-22:
    p_value = igamc(df/2, chi_square/2).
    """
    if x < 0.0 or a <= 0.0:
        raise ValueError(f"igamc domain error: a={a}, x={x}")
    if x == 0.0:
        return 1.0
    if x < a + 1.0:
        return 1.0 - _gser(a, x)
    return _gcf(a, x)


def igam(a: float, x: float) -> float:
    """Lower regularized incomplete gamma P(a, x)."""
    return 1.0 - igamc(a, x)


def erfc(x: float) -> float:
    return math.erfc(x)


def normal_cdf(z: float) -> float:
    """Standard normal CDF."""
    return 0.5 * math.erfc(-z / math.sqrt(2.0))
