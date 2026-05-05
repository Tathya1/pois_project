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
)


def test_hmac_sign_and_verify_for_all_hash_types():
    for hash_type in ("dlp", "sha256"):
        h = DLPHMAC(hash_impl=get_hash_impl(hash_type))
        key = "1a2b3c4d"
        message = "hello hmac"

        tag = h.sign(key, message)
        assert h.verify(key, message, tag) is True

        bad = bytearray(tag)
        bad[0] ^= 0x01
        assert h.verify(key, message, bytes(bad)) is False


def test_length_extension_breaks_naive_mac_but_not_hmac():
    for hash_type in ("dlp", "sha256"):
        hash_impl = get_hash_impl(hash_type)
        naive = NaiveKeyedHash(hash_impl)
        hmac_impl = DLPHMAC(hash_impl)

        key = key_to_bytes("1a2b3c4d")
        message = "pay=100"
        suffix = "&admin=true"

        original_naive_tag = naive.sign(key, message)
        forged = forge_length_extension(
            hash_impl,
            message=message,
            original_tag=original_naive_tag,
            suffix=suffix,
            guessed_key_len=len(key),
        )

        assert naive.verify(key, forged["forgedMessage"], forged["forgedTag"]) is True
        assert hmac_impl.verify(key, forged["forgedMessage"], forged["forgedTag"]) is False


def test_encrypt_then_hmac_roundtrip_and_rejects_tampering():
    scheme = EncryptThenHMAC(hash_type="dlp")

    enc = scheme.encrypt("1a2b3c4d", "0f0e0d0c0b0a0908", "secret message")
    dec = scheme.decrypt("1a2b3c4d", "0f0e0d0c0b0a0908", enc["r"], enc["c"], enc["tag"])

    assert dec == "secret message"

    tampered_tag = ("00" if enc["tag"][:2] != "00" else "01") + enc["tag"][2:]
    dec_bad = scheme.decrypt("1a2b3c4d", "0f0e0d0c0b0a0908", enc["r"], enc["c"], tampered_tag)

    assert dec_bad is None


def test_euf_cma_and_cca2_simulations_run():
    euf = simulate_euf_cma(rounds=8, queries=20, hash_type="dlp")
    cca = simulate_cca2(rounds=16, hash_type="dlp")

    assert euf["forgeSuccessRate"] <= 0.2
    assert cca["tamperRejectRate"] >= 0.95


def test_compare_with_pa6_reports_metrics():
    summary = compare_cca2_with_pa6(rounds=8, hash_type="dlp")
    assert "hmacScheme" in summary
    assert "pa6PrfMacScheme" in summary
    assert summary["hmacScheme"]["tagBytes"] > 0
    assert summary["pa6PrfMacScheme"]["tagBytes"] > 0


def test_machash_summary_includes_reduction_argument():
    summary = machash_summary(["m0", "m1", "m2"], hash_type="dlp")
    assert "reduction" in summary
    assert len(summary["reduction"]) >= 4
