from flask import Blueprint, jsonify, request

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

pa9 = Blueprint("pa9", __name__)


@pa9.route("/attack", methods=["POST"])
def pa9_attack_api():
    data = request.get_json(force=True)

    n_bits = int(data.get("nBits", 12))
    method = (data.get("method", "naive") or "naive").lower()
    hash_type = data.get("hashType", "toy")
    track = bool(data.get("track", True))
    history_step = int(data.get("historyStep", 1))

    max_evaluations = int(data.get("maxEvaluations", 250000))
    max_steps = int(data.get("maxSteps", 300000))
    max_restarts = int(data.get("maxRestarts", 20))

    try:
        hash_fn = get_hash_callable(hash_type)

        if method == "floyd":
            result = birthday_attack_floyd(
                hash_fn,
                n_bits=n_bits,
                max_steps=max_steps,
                max_restarts=max_restarts,
                track_history=track,
                history_step=max(1, history_step),
            )
        else:
            result = birthday_attack_naive(
                hash_fn,
                n_bits=n_bits,
                max_evaluations=max_evaluations,
                track_history=track,
                history_step=max(1, history_step),
            )

        payload = {
            **result,
            "hashType": hash_type,
        }

        if result.get("found"):
            payload["liveTrace"] = build_live_probability_trace(
                n_bits=n_bits,
                found_evaluations=int(result["evaluations"]),
            )

        return jsonify(payload)
    except Exception as error:
        return jsonify({"error": str(error)}), 400


@pa9.route("/trials", methods=["POST"])
def pa9_trials_api():
    data = request.get_json(force=True)

    n_bits = int(data.get("nBits", 12))
    method = (data.get("method", "naive") or "naive").lower()
    hash_type = data.get("hashType", "toy")
    trials = int(data.get("trials", 100))

    try:
        hash_fn = get_hash_callable(hash_type)
        stats = run_empirical_trials(
            hash_fn,
            n_bits=n_bits,
            trials=trials,
            method=method,
        )

        curve = build_collision_curve(n_bits=n_bits, evaluations=stats["evaluations"])

        return jsonify(
            {
                "stats": stats,
                "curve": curve,
                "hashType": hash_type,
            }
        )
    except Exception as error:
        return jsonify({"error": str(error)}), 400


@pa9.route("/toy-study", methods=["POST"])
def pa9_toy_study_api():
    data = request.get_json(force=True)
    trials_per_point = int(data.get("trialsPerPoint", 30))

    try:
        return jsonify(run_toy_benchmark(trials_per_point=trials_per_point))
    except Exception as error:
        return jsonify({"error": str(error)}), 400


@pa9.route("/dlp-truncated", methods=["POST"])
def pa9_dlp_truncated_api():
    data = request.get_json(force=True)

    n_bits = int(data.get("nBits", 16))
    method = (data.get("method", "naive") or "naive").lower()

    try:
        result = run_dlp_truncated_attack(
            n_bits=n_bits,
            method=method,
            max_evaluations=int(data.get("maxEvaluations", 500000)),
            max_steps=int(data.get("maxSteps", 500000)),
            max_restarts=int(data.get("maxRestarts", 24)),
        )
        return jsonify(result)
    except Exception as error:
        return jsonify({"error": str(error)}), 400


@pa9.route("/empirical-grid", methods=["POST"])
def pa9_empirical_grid_api():
    data = request.get_json(force=True)

    hash_type = data.get("hashType", "toy")
    method = (data.get("method", "naive") or "naive").lower()
    trials = int(data.get("trials", 100))

    raw_n_values = data.get("nValues", [8, 10, 12, 14, 16])
    if not isinstance(raw_n_values, list) or not raw_n_values:
        return jsonify({"error": "nValues must be a non-empty list"}), 400

    try:
        n_values = [int(v) for v in raw_n_values]
        hash_fn = get_hash_callable(hash_type)
        result = run_empirical_grid(
            hash_fn,
            n_values=n_values,
            trials=trials,
            method=method,
        )
        return jsonify({**result, "hashType": hash_type})
    except Exception as error:
        return jsonify({"error": str(error)}), 400


@pa9.route("/context", methods=["POST"])
def pa9_context_api():
    data = request.get_json(force=True)
    hash_rate = float(data.get("hashRate", 1e9))

    try:
        return jsonify(md5_sha1_context(hash_rate_per_sec=hash_rate))
    except Exception as error:
        return jsonify({"error": str(error)}), 400
