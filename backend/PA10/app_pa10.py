from flask import Blueprint, jsonify, request

from hmac_etm import (
    DLPHMAC,
    EncryptThenHMAC,
    NaiveKeyedHash,
    compare_cca2_with_pa6,
    forge_length_extension,
    get_hash_impl,
    key_to_bytes,
    machash_summary,
    simulate_cca2,
    simulate_euf_cma,
    timing_leak_demo,
)

pa10 = Blueprint("pa10", __name__)


@pa10.route("/hmac", methods=["POST"])
def pa10_hmac_api():
    data = request.get_json(force=True)

    key = data.get("key", "1a2b3c4d")
    message = data.get("message", "")
    hash_type = data.get("hashType", "dlp")

    try:
        h = DLPHMAC(hash_impl=get_hash_impl(hash_type))
        tag = h.sign(key, message).hex()
        return jsonify({"tag": tag, "hashType": hash_type, "tagBytes": h.tag_bytes})
    except Exception as error:
        return jsonify({"error": str(error)}), 400


@pa10.route("/hmac/verify", methods=["POST"])
def pa10_hmac_verify_api():
    data = request.get_json(force=True)

    key = data.get("key", "1a2b3c4d")
    message = data.get("message", "")
    tag_hex = data.get("tag", "")
    hash_type = data.get("hashType", "dlp")

    if not tag_hex:
        return jsonify({"error": "Missing tag"}), 400

    try:
        h = DLPHMAC(hash_impl=get_hash_impl(hash_type))
        valid = h.verify(key, message, bytes.fromhex(tag_hex))
        return jsonify({"valid": valid, "hashType": hash_type})
    except Exception as error:
        return jsonify({"error": str(error)}), 400


@pa10.route("/euf-cma", methods=["POST"])
def pa10_euf_cma_api():
    data = request.get_json(force=True)

    rounds = int(data.get("rounds", 20))
    queries = int(data.get("queries", 50))
    hash_type = data.get("hashType", "dlp")

    try:
        return jsonify(simulate_euf_cma(rounds=rounds, queries=queries, hash_type=hash_type))
    except Exception as error:
        return jsonify({"error": str(error)}), 400


@pa10.route("/length-extension", methods=["POST"])
def pa10_length_extension_api():
    data = request.get_json(force=True)

    key = data.get("key", "1a2b3c4d")
    message = data.get("message", "pay=100")
    suffix = data.get("suffix", "&admin=true")
    hash_type = data.get("hashType", "dlp")

    key_b = key_to_bytes(key)
    guessed_key_len = int(data.get("guessKeyLen", len(key_b)))

    try:
        hash_impl = get_hash_impl(hash_type)
        naive = NaiveKeyedHash(hash_impl)
        hmac_impl = DLPHMAC(hash_impl)

        original_naive_tag = naive.sign(key_b, message)
        forged = forge_length_extension(
            hash_impl,
            message=message,
            original_tag=original_naive_tag,
            suffix=suffix,
            guessed_key_len=guessed_key_len,
        )

        naive_success = naive.verify(key_b, forged["forgedMessage"], forged["forgedTag"])

        original_hmac_tag = hmac_impl.sign(key_b, message)
        hmac_success = hmac_impl.verify(key_b, forged["forgedMessage"], forged["forgedTag"])

        valid_hmac_on_forged = hmac_impl.sign(key_b, forged["forgedMessage"])

        return jsonify(
            {
                "hashType": hash_type,
                "message": message,
                "suffix": suffix,
                "guessKeyLen": guessed_key_len,
                "naiveTag": original_naive_tag.hex(),
                "hmacTag": original_hmac_tag.hex(),
                "gluePaddingHex": forged["gluePadding"].hex(),
                "forgedMessageHex": forged["forgedMessage"].hex(),
                "forgedTag": forged["forgedTag"].hex(),
                "naiveForgerySucceeded": naive_success,
                "hmacForgerySucceeded": hmac_success,
                "actualHmacForForgedMessage": valid_hmac_on_forged.hex(),
            }
        )
    except Exception as error:
        return jsonify({"error": str(error)}), 400


@pa10.route("/eth/enc", methods=["POST"])
def pa10_eth_enc_api():
    data = request.get_json(force=True)

    key_e = data.get("keyE", "1a2b3c4d")
    key_m = data.get("keyM", "0f0e0d0c0b0a0908")
    message = data.get("message", "")
    hash_type = data.get("hashType", "dlp")

    try:
        scheme = EncryptThenHMAC(hash_type=hash_type)
        return jsonify({**scheme.encrypt(key_e, key_m, message), "hashType": hash_type})
    except Exception as error:
        return jsonify({"error": str(error)}), 400


@pa10.route("/eth/dec", methods=["POST"])
def pa10_eth_dec_api():
    data = request.get_json(force=True)

    key_e = data.get("keyE", "1a2b3c4d")
    key_m = data.get("keyM", "0f0e0d0c0b0a0908")
    r_hex = data.get("r")
    c_hex = data.get("c")
    tag_hex = data.get("tag")
    hash_type = data.get("hashType", "dlp")

    if not r_hex or not c_hex or not tag_hex:
        return jsonify({"error": "Missing r, c, or tag"}), 400

    try:
        scheme = EncryptThenHMAC(hash_type=hash_type)
        message = scheme.decrypt(key_e, key_m, r_hex, c_hex, tag_hex)
        return jsonify({"valid": message is not None, "message": message, "hashType": hash_type})
    except Exception as error:
        return jsonify({"error": str(error)}), 400


@pa10.route("/cca2", methods=["POST"])
def pa10_cca2_api():
    data = request.get_json(force=True)
    rounds = int(data.get("rounds", 40))
    hash_type = data.get("hashType", "dlp")

    try:
        return jsonify(simulate_cca2(rounds=rounds, hash_type=hash_type))
    except Exception as error:
        return jsonify({"error": str(error)}), 400


@pa10.route("/compare-pa6", methods=["POST"])
def pa10_compare_pa6_api():
    data = request.get_json(force=True)
    rounds = int(data.get("rounds", 40))
    hash_type = data.get("hashType", "dlp")

    try:
        return jsonify(compare_cca2_with_pa6(rounds=rounds, hash_type=hash_type))
    except Exception as error:
        return jsonify({"error": str(error)}), 400


@pa10.route("/timing", methods=["POST"])
def pa10_timing_api():
    data = request.get_json(force=True)
    iterations = int(data.get("iterations", 15000))

    try:
        return jsonify(timing_leak_demo(iterations=iterations))
    except Exception as error:
        return jsonify({"error": str(error)}), 400


@pa10.route("/machash", methods=["POST"])
def pa10_machash_api():
    data = request.get_json(force=True)

    messages = data.get("messages", ["m0", "m1", "m2", "m3", "m4"])
    hash_type = data.get("hashType", "dlp")

    try:
        return jsonify(machash_summary(list(messages), hash_type=hash_type))
    except Exception as error:
        return jsonify({"error": str(error)}), 400
