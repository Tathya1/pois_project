from __future__ import annotations

import math
import os
import secrets
import statistics
import sys
from typing import Callable, Iterable

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA8"))

from dlp_hash import DLP_Hash

MASK_64 = (1 << 64) - 1

HashCallable = Callable[[bytes], bytes]


def _truncate_to_int(raw: bytes, n_bits: int) -> int:
    if n_bits <= 0:
        raise ValueError("n_bits must be positive")

    total_bits = len(raw) * 8
    value = int.from_bytes(raw, "big")

    # Use the lower n bits for truncation. This avoids degenerate behavior when
    # high bits are structurally zero in toy-size constructions.
    if n_bits > total_bits:
        value <<= n_bits - total_bits

    return value & ((1 << n_bits) - 1)


def _int_to_nbit_bytes(value: int, n_bits: int) -> bytes:
    size = max(1, (n_bits + 7) // 8)
    return (value & ((1 << n_bits) - 1)).to_bytes(size, "big")


def collision_probability(n_bits: int, evaluations: int) -> float:
    if evaluations <= 0:
        return 0.0
    return 1.0 - math.exp(-(evaluations * (evaluations - 1)) / (2 ** (n_bits + 1)))


def _toy_hash(data: bytes) -> bytes:
    state = 0x243F6A8885A308D3

    for i, b in enumerate(data):
        state ^= (b + i + 0x9E3779B97F4A7C15) & MASK_64
        state = ((state << 13) | (state >> 51)) & MASK_64
        state = (state * 0xBF58476D1CE4E5B9 + 0x94D049BB133111EB) & MASK_64

    left = state.to_bytes(8, "big")

    state2 = state ^ 0xDEADBEEFCAFEBABE
    for i, b in enumerate(data):
        state2 ^= (b + (i * 1315423911)) & MASK_64
        state2 = ((state2 << 7) | (state2 >> 57)) & MASK_64
        state2 = (state2 * 0x94D049BB133111EB + 0x9E3779B97F4A7C15) & MASK_64

    right = state2.to_bytes(8, "big")
    return left + right


def get_hash_callable(hash_type: str) -> HashCallable:
    htype = (hash_type or "toy").strip().lower()

    if htype == "toy":
        return _toy_hash

    if htype in {"dlp", "dlp-secure"}:
        hasher = DLP_Hash(bits=17)
        return lambda data: hasher.hash(data)

    if htype == "dlp-toy":
        hasher = DLP_Hash(bits=10)
        return lambda data: hasher.hash(data)

    raise ValueError("Unsupported hashType. Use one of: toy, dlp, dlp-toy")


def _finalize_history(history: list[dict[str, float]], found_evaluations: int | None) -> None:
    if not history:
        return

    for point in history:
        k = int(point["k"])
        point["empirical"] = 1.0 if found_evaluations is not None and k >= found_evaluations else 0.0


def birthday_attack_naive(
    hash_fn: HashCallable,
    n_bits: int,
    max_evaluations: int = 200000,
    input_bytes: int = 8,
    track_history: bool = False,
    history_step: int = 1,
) -> dict:
    if history_step <= 0:
        raise ValueError("history_step must be positive")

    expected = 2 ** (n_bits / 2)
    seen: dict[int, bytes] = {}
    history: list[dict[str, float]] = []

    for evaluations in range(1, max_evaluations + 1):
        x = secrets.token_bytes(input_bytes)
        digest_int = _truncate_to_int(hash_fn(x), n_bits)

        if track_history and evaluations % history_step == 0:
            history.append(
                {
                    "k": float(evaluations),
                    "theoretical": collision_probability(n_bits, evaluations),
                }
            )

        prev = seen.get(digest_int)
        if prev is not None and prev != x:
            if track_history and (not history or int(history[-1]["k"]) != evaluations):
                history.append(
                    {
                        "k": float(evaluations),
                        "theoretical": collision_probability(n_bits, evaluations),
                    }
                )
                
            _finalize_history(history, evaluations)

            result = {
                "found": True,
                "method": "naive",
                "nBits": n_bits,
                "evaluations": evaluations,
                "expected": expected,
                "ratio": evaluations / expected,
                "x1": prev.hex(),
                "x2": x.hex(),
                "digest": _int_to_nbit_bytes(digest_int, n_bits).hex(),
            }
            if track_history:
                result["checkpoints"] = history
            return result

        seen[digest_int] = x

    _finalize_history(history, None)

    result = {
        "found": False,
        "method": "naive",
        "nBits": n_bits,
        "evaluations": max_evaluations,
        "expected": expected,
        "ratio": max_evaluations / expected,
        "message": "No collision found in limit; increase max evaluations.",
    }
    if track_history:
        result["checkpoints"] = history
    return result


def _iterate_state(start: int, steps: int, f) -> int:
    value = start
    for _ in range(steps):
        value = f(value)
    return value


def birthday_attack_floyd(
    hash_fn: HashCallable,
    n_bits: int,
    max_steps: int = 300000,
    max_restarts: int = 20,
    track_history: bool = False,
    history_step: int = 32,
) -> dict:
    if history_step <= 0:
        raise ValueError("history_step must be positive")

    expected = 2 ** (n_bits / 2)
    evaluations = 0
    history: list[dict[str, float]] = []

    def f(state: int) -> int:
        nonlocal evaluations
        evaluations += 1
        raw = hash_fn(_int_to_nbit_bytes(state, n_bits))

        if track_history and evaluations % history_step == 0:
            history.append(
                {
                    "k": float(evaluations),
                    "theoretical": collision_probability(n_bits, evaluations),
                }
            )

        return _truncate_to_int(raw, n_bits)

    for restart in range(max_restarts):
        x0 = secrets.randbits(n_bits)

        tortoise = f(x0)
        hare = f(f(x0))

        phase_steps = 0
        while tortoise != hare and phase_steps < max_steps:
            tortoise = f(tortoise)
            hare = f(f(hare))
            phase_steps += 1

        if tortoise != hare:
            continue

        mu = 0
        tortoise = x0
        while tortoise != hare and mu < max_steps:
            tortoise = f(tortoise)
            hare = f(hare)
            mu += 1

        if tortoise != hare:
            continue

        lam = 1
        hare = f(tortoise)
        while tortoise != hare and lam < max_steps:
            hare = f(hare)
            lam += 1

        if mu == 0:
            continue

        x1 = _iterate_state(x0, mu - 1, f)
        x2 = _iterate_state(x0, mu + lam - 1, f)

        d1 = f(x1)
        d2 = f(x2)

        if x1 != x2 and d1 == d2:
            if track_history and (not history or int(history[-1]["k"]) != evaluations):
                history.append(
                    {
                        "k": float(evaluations),
                        "theoretical": collision_probability(n_bits, evaluations),
                    }
                )

            _finalize_history(history, evaluations)

            result = {
                "found": True,
                "method": "floyd",
                "nBits": n_bits,
                "evaluations": evaluations,
                "expected": expected,
                "ratio": evaluations / expected,
                "restart": restart,
                "mu": mu,
                "lambda": lam,
                "x1": _int_to_nbit_bytes(x1, n_bits).hex(),
                "x2": _int_to_nbit_bytes(x2, n_bits).hex(),
                "digest": _int_to_nbit_bytes(d1, n_bits).hex(),
            }
            if track_history:
                result["checkpoints"] = history
            return result

    _finalize_history(history, None)

    result = {
        "found": False,
        "method": "floyd",
        "nBits": n_bits,
        "evaluations": evaluations,
        "expected": expected,
        "ratio": evaluations / expected if expected else 0.0,
        "message": "Could not extract a collision pair with current limits; retry or raise limits.",
    }
    if track_history:
        result["checkpoints"] = history
    return result


def run_empirical_trials(
    hash_fn: HashCallable,
    n_bits: int,
    trials: int = 100,
    method: str = "naive",
    max_evaluations: int = 200000,
    max_steps: int = 300000,
    max_restarts: int = 20,
) -> dict:
    if trials <= 0:
        raise ValueError("trials must be positive")

    method_l = (method or "naive").lower()
    evaluations: list[int] = []
    found_count = 0

    for _ in range(trials):
        if method_l == "floyd":
            result = birthday_attack_floyd(
                hash_fn,
                n_bits=n_bits,
                max_steps=max_steps,
                max_restarts=max_restarts,
            )
        else:
            result = birthday_attack_naive(
                hash_fn,
                n_bits=n_bits,
                max_evaluations=max_evaluations,
            )

        evaluations.append(int(result["evaluations"]))
        if result.get("found"):
            found_count += 1

    expected = 2 ** (n_bits / 2)
    mean_eval = statistics.fmean(evaluations)

    return {
        "trials": trials,
        "method": method_l,
        "nBits": n_bits,
        "foundCount": found_count,
        "expected": expected,
        "mean": mean_eval,
        "median": statistics.median(evaluations),
        "min": min(evaluations),
        "max": max(evaluations),
        "stddev": statistics.pstdev(evaluations) if len(evaluations) > 1 else 0.0,
        "ratioMean": mean_eval / expected,
        "evaluations": evaluations,
    }


def build_collision_curve(n_bits: int, evaluations: list[int], max_k: int | None = None) -> dict:
    expected = 2 ** (n_bits / 2)
    if max_k is None:
        baseline = max(evaluations) if evaluations else int(expected * 2)
        max_k = max(baseline, int(expected * 2.5))

    step = max(1, max_k // 120)
    points = []

    for k in range(1, max_k + 1, step):
        theoretical = collision_probability(n_bits, k)
        empirical = sum(1 for v in evaluations if v <= k) / len(evaluations) if evaluations else 0.0
        points.append({"k": k, "theoretical": theoretical, "empirical": empirical})

    if points[-1]["k"] != max_k:
        k = max_k
        theoretical = collision_probability(n_bits, k)
        empirical = sum(1 for v in evaluations if v <= k) / len(evaluations) if evaluations else 0.0
        points.append({"k": k, "theoretical": theoretical, "empirical": empirical})

    return {
        "nBits": n_bits,
        "expected": expected,
        "maxK": max_k,
        "points": points,
    }


def build_live_probability_trace(
    n_bits: int,
    found_evaluations: int,
    max_k: int | None = None,
    points: int = 120,
) -> dict:
    expected = 2 ** (n_bits / 2)

    if max_k is None:
        max_k = max(int(expected * 2.5), found_evaluations + max(8, found_evaluations // 2))

    step = max(1, max_k // max(points, 1))
    trace_points = []

    for k in range(1, max_k + 1, step):
        trace_points.append(
            {
                "k": k,
                "theoretical": collision_probability(n_bits, k),
                "empirical": 1.0 if k >= found_evaluations else 0.0,
            }
        )

    if trace_points[-1]["k"] != max_k:
        trace_points.append(
            {
                "k": max_k,
                "theoretical": collision_probability(n_bits, max_k),
                "empirical": 1.0 if max_k >= found_evaluations else 0.0,
            }
        )

    return {
        "nBits": n_bits,
        "expected": expected,
        "foundAt": found_evaluations,
        "maxK": max_k,
        "points": trace_points,
    }


def run_toy_benchmark(
    trials_per_point: int = 30,
    n_values: Iterable[int] = (8, 12, 16),
    methods: Iterable[str] = ("naive", "floyd"),
) -> dict:
    hash_fn = get_hash_callable("toy")
    rows = []
    plot = []

    for method in methods:
        for n_bits in n_values:
            stats = run_empirical_trials(
                hash_fn,
                n_bits=n_bits,
                trials=trials_per_point,
                method=method,
            )

            row = {
                "method": method,
                "nBits": n_bits,
                "meanEvaluations": stats["mean"],
                "expected": stats["expected"],
                "ratio": stats["ratioMean"],
                "stddev": stats["stddev"],
                "foundCount": stats["foundCount"],
                "trials": stats["trials"],
            }
            rows.append(row)
            plot.append(
                {
                    "method": method,
                    "nBits": n_bits,
                    "measured": stats["mean"],
                    "expected": stats["expected"],
                }
            )

    return {
        "trialsPerPoint": trials_per_point,
        "rows": rows,
        "plot": plot,
    }


def run_dlp_truncated_attack(
    n_bits: int = 16,
    method: str = "naive",
    max_evaluations: int = 500000,
    max_steps: int = 500000,
    max_restarts: int = 24,
) -> dict:
    hash_fn = get_hash_callable("dlp")
    method_l = (method or "naive").lower()

    if method_l == "floyd":
        result = birthday_attack_floyd(
            hash_fn,
            n_bits=n_bits,
            max_steps=max_steps,
            max_restarts=max_restarts,
        )
    else:
        result = birthday_attack_naive(
            hash_fn,
            n_bits=n_bits,
            max_evaluations=max_evaluations,
        )

    return {
        **result,
        "hashType": "dlp",
        "nBits": n_bits,
        "requirement": "PA8 DLP hash truncated to n bits",
    }


def run_empirical_grid(
    hash_fn: HashCallable,
    n_values: Iterable[int] = (8, 10, 12, 14, 16),
    trials: int = 100,
    method: str = "naive",
) -> dict:
    rows = []

    for n_bits in n_values:
        stats = run_empirical_trials(
            hash_fn,
            n_bits=n_bits,
            trials=trials,
            method=method,
        )
        curve = build_collision_curve(n_bits=n_bits, evaluations=stats["evaluations"])
        rows.append(
            {
                "nBits": n_bits,
                "stats": stats,
                "curve": curve,
            }
        )

    return {
        "method": method,
        "trials": trials,
        "rows": rows,
    }


def md5_sha1_context(hash_rate_per_sec: float = 1e9) -> dict:
    if hash_rate_per_sec <= 0:
        raise ValueError("hash_rate_per_sec must be positive")

    rows = []
    for name, n_bits in (("MD5", 128), ("SHA-1", 160)):
        work = 2 ** (n_bits / 2)
        seconds = work / hash_rate_per_sec
        years = seconds / (60 * 60 * 24 * 365)

        rows.append(
            {
                "hash": name,
                "nBits": n_bits,
                "work": work,
                "secondsAtGivenRate": seconds,
                "yearsAtGivenRate": years,
            }
        )

    return {
        "hashRatePerSecond": hash_rate_per_sec,
        "rows": rows,
    }
