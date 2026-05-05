from birthday_attack import (
    birthday_attack_floyd,
    birthday_attack_naive,
    build_collision_curve,
    build_live_probability_trace,
    get_hash_callable,
    md5_sha1_context,
    run_dlp_truncated_attack,
    run_empirical_grid,
    run_empirical_trials,
    run_toy_benchmark,
)


def test_naive_birthday_finds_collision_on_toy_hash():
    hash_fn = get_hash_callable("toy")
    result = birthday_attack_naive(hash_fn, n_bits=12, max_evaluations=30000)

    assert result["found"] is True
    assert result["x1"] != result["x2"]


def test_floyd_finds_collision_on_toy_hash():
    hash_fn = get_hash_callable("toy")

    result = birthday_attack_floyd(hash_fn, n_bits=10, max_steps=300000, max_restarts=20)
    if not result["found"]:
        result = birthday_attack_floyd(hash_fn, n_bits=10, max_steps=300000, max_restarts=20)

    assert result["found"] is True
    assert result["x1"] != result["x2"]


def test_empirical_trials_and_curve_generation():
    hash_fn = get_hash_callable("toy")
    stats = run_empirical_trials(hash_fn, n_bits=10, trials=20, method="naive")

    assert stats["trials"] == 20
    assert len(stats["evaluations"]) == 20
    assert stats["mean"] > 0

    curve = build_collision_curve(n_bits=10, evaluations=stats["evaluations"])
    assert curve["points"]
    assert curve["expected"] > 0


def test_toy_benchmark_covers_required_n_values():
    summary = run_toy_benchmark(trials_per_point=4)
    seen = {(row["method"], row["nBits"]) for row in summary["rows"]}

    for method in ("naive", "floyd"):
        for n_bits in (8, 12, 16):
            assert (method, n_bits) in seen


def test_dlp_truncated_attack_returns_required_fields():
    result = run_dlp_truncated_attack(n_bits=16, method="naive", max_evaluations=20000)

    assert result["hashType"] == "dlp"
    assert result["nBits"] == 16
    assert "evaluations" in result
    assert "ratio" in result


def test_empirical_grid_shape():
    hash_fn = get_hash_callable("toy")
    grid = run_empirical_grid(hash_fn, n_values=[8, 10], trials=5, method="naive")

    assert len(grid["rows"]) == 2
    assert [row["nBits"] for row in grid["rows"]] == [8, 10]
    assert all("curve" in row and "stats" in row for row in grid["rows"])


def test_live_probability_trace_contains_expected_marker():
    trace = build_live_probability_trace(n_bits=12, found_evaluations=70)
    assert trace["expected"] == 64
    assert trace["foundAt"] == 70
    assert trace["points"]


def test_md5_sha1_context_rows():
    ctx = md5_sha1_context(hash_rate_per_sec=1e9)
    names = [row["hash"] for row in ctx["rows"]]

    assert "MD5" in names
    assert "SHA-1" in names
