"""Runner that applies both NIST suites to Beamline's actual data paths.

Three targets, answering three different questions:

    raw       Blocks as harvested from ANU, unconditioned. Asks: is the physical
              source behaving? This is the only target where a failure means the
              PHYSICS or the transport is wrong.
    pool      The conditioned output of the entropy pool. Asks: is the mixing sound?
    drbg      What the API actually serves. Asks: is the delivery path sound?

The raw target is the interesting one and the one most services never publish. A
conditioned or DRBG stream will pass SP 800-22 even if the underlying source has died,
because SHA-512 whitens anything -- which is exactly why testing only the output of a
hash is not evidence about an entropy source.
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import asdict, dataclass, field

import numpy as np

from . import sp80022, sp80090b


@dataclass
class SuiteReport:
    target: str
    description: str
    n_bits: int
    n_streams: int
    generated_at: float = field(default_factory=time.time)
    sp80022_results: list = field(default_factory=list)
    proportion_passed: float = 0.0
    proportion_interval: tuple = (0.0, 1.0)
    uniformity_p: float = float("nan")
    min_entropy: float | None = None
    entropy_estimates: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def passed(self) -> bool:
        lo, _ = self.proportion_interval
        return self.proportion_passed >= lo


def run_sp80022(data: bytes, stream_bits: int = 1_000_000,
                max_streams: int | None = None) -> tuple[list, float, tuple, float]:
    """Split `data` into bitstreams and run all 15 tests on each.

    SP 800-22 is designed around many independent bitstreams, not one long one: the
    pass proportion and the p-value uniformity check both need a population. A single
    stream gives 15 p-values, which is not enough to say anything statistically.
    """
    bits = sp80022.bytes_to_bits(data)
    n_streams = max(1, len(bits) // stream_bits)
    if max_streams:
        n_streams = min(n_streams, max_streams)
    per_test: dict[str, list[float]] = {}
    all_p: list[float] = []
    stream_pass = []

    for i in range(n_streams):
        chunk = bits[i * stream_bits:(i + 1) * stream_bits]
        results = sp80022.run_all(chunk)
        ok = True
        for r in results:
            if r.skipped:
                continue
            per_test.setdefault(r.name, []).extend(r.p_values)
            all_p.extend(r.p_values)
            ok = ok and r.passed
        stream_pass.append(ok)

    # SP 800-22 4.2.1 applies the proportion test PER TEST, over the population of
    # p-values that test produced -- not to whole streams. Marking a stream failed
    # because any one of its ~1,900 p-values dipped below alpha would fail roughly 77%
    # of streams from a perfect generator, since 1 - 0.99^1900 is essentially certain.
    summary = []
    worst_margin = 1.0
    for name, ps in per_test.items():
        fails = sum(1 for p in ps if p < sp80022.ALPHA)
        proportion = 1.0 - fails / len(ps) if ps else 0.0
        lo, hi = sp80022.proportion_confidence_interval(len(ps))
        passed = proportion >= lo
        summary.append({
            "test": name,
            "p_values": len(ps),
            "min_p": round(min(ps), 6) if ps else None,
            "median_p": round(float(np.median(ps)), 6) if ps else None,
            "below_alpha": fails,
            "expected_below_alpha": round(len(ps) * sp80022.ALPHA, 2),
            "proportion": round(proportion, 4),
            "proportion_min": round(lo, 4),
            "passed": passed,
        })
        worst_margin = min(worst_margin, proportion - lo)

    overall = sum(1 for r in summary if r["passed"]) / len(summary) if summary else 0.0
    interval = sp80022.proportion_confidence_interval(max(1, len(all_p)))
    uniformity, _ = sp80022.uniformity_of_pvalues(all_p)
    return summary, overall, interval, uniformity


def assess_bytes(data: bytes, target: str, description: str,
                 stream_bits: int = 1_000_000,
                 entropy_bits: int = 1_000_000,
                 max_streams: int | None = None,
                 skip_entropy: bool = False) -> SuiteReport:
    summary, proportion, interval, uniformity = run_sp80022(data, stream_bits, max_streams)
    rep = SuiteReport(
        target=target,
        description=description,
        n_bits=len(data) * 8,
        n_streams=min(max(1, (len(data) * 8) // stream_bits), max_streams or 10**9),
        sp80022_results=summary,
        proportion_passed=proportion,
        proportion_interval=interval,
        uniformity_p=uniformity,
    )

    if not skip_entropy:
        bits = sp80022.bytes_to_bits(data)[:entropy_bits]
        estimates, h = sp80090b.assess(bits)
        rep.min_entropy = h
        rep.entropy_estimates = [
            {"estimator": e.name, "min_entropy": round(e.min_entropy, 6),
             "detail": e.detail, "skipped": e.skipped}
            for e in estimates
        ]
        rep.notes.extend(f"SP 800-90B estimator not implemented: {n}"
                         for n in sp80090b.NOT_IMPLEMENTED)
    return rep


def render(rep: SuiteReport) -> str:
    out = []
    out.append("=" * 78)
    out.append(f"{rep.target.upper()}  --  {rep.description}")
    out.append(f"{rep.n_bits:,} bits ({rep.n_bits // 8:,} bytes), "
               f"{rep.n_streams} stream(s) of 1,000,000 bits")
    out.append("=" * 78)
    out.append("")
    out.append("NIST SP 800-22 -- Statistical Test Suite")
    out.append(f"  {'test':<30} {'p-vals':>7} {'median p':>9} {'fail':>5} "
               f"{'exp':>6} {'prop':>7} {'min':>7}  result")
    out.append("  " + "-" * 80)
    for r in rep.sp80022_results:
        mark = "PASS" if r["passed"] else "FAIL"
        out.append(f"  {r['test']:<30} {r['p_values']:>7} "
                   f"{r['median_p'] if r['median_p'] is not None else 0:>9.6f} "
                   f"{r['below_alpha']:>5} {r['expected_below_alpha']:>6} "
                   f"{r['proportion']:>7.4f} {r['proportion_min']:>7.4f}  {mark}")
    out.append("")
    failed = [r["test"] for r in rep.sp80022_results if not r["passed"]]
    out.append(f"  tests passing the proportion check : "
               f"{sum(1 for r in rep.sp80022_results if r['passed'])}"
               f"/{len(rep.sp80022_results)}")
    if failed:
        out.append(f"  failing: {', '.join(failed)}")
    unif = rep.uniformity_p
    out.append(f"  p-value uniformity     : "
               f"{'n/a (too few p-values)' if math.isnan(unif) else f'{unif:.6f}'}")

    if rep.min_entropy is not None:
        out.append("")
        out.append("NIST SP 800-90B -- min-entropy (non-IID track)")
        for e in rep.entropy_estimates:
            if e["skipped"]:
                out.append(f"  {e['estimator']:<34} skipped: {e['detail']}")
            else:
                out.append(f"  {e['estimator']:<34} {e['min_entropy']:.5f} bits/bit")
        out.append("  " + "-" * 74)
        out.append(f"  MIN-ENTROPY (worst estimator)      {rep.min_entropy:.5f} bits/bit")
    for n in rep.notes:
        out.append(f"  note: {n}")
    out.append("")
    return "\n".join(out)
