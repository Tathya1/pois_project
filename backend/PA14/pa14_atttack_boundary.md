# Håstad’s Broadcast Attack (e = 3) — Boundary Analysis

## Context

**Setup:**
A sender broadcasts the same message `m` to three different recipients. Each recipient has its own RSA modulus `N1`, `N2`, and `N3`, but all use the same small public exponent `e = 3`. The attacker sees:

c1 = m^3 mod N1
c2 = m^3 mod N2
c3 = m^3 mod N3

**Attack idea:**
If `m < Ni` for all `i`, then `m^3 < N1 · N2 · N3`. Using the Chinese Remainder Theorem, the attacker can reconstruct `m^3` exactly as an integer, and then take the integer cube root to recover `m`.

This means three ciphertexts are enough to break textbook RSA when the message is short and no padding is used.

## Question

Determine the maximum message length in bytes for which Håstad’s attack with `e = 3` succeeds, given three 1024-bit moduli. Also explain why messages with `m^3 ≥ N1 · N2 · N3` are safe from this specific attack.

## Answer

Each RSA modulus is 1024 bits, so the product `N1 · N2 · N3` is about 3072 bits.

For the attack to work, we need:

`m^3 < N1 · N2 · N3`

Taking cube roots on both sides gives:

`m < 2^1024`

So the message must be smaller than 1024 bits, which is:

`1024 / 8 = 128 bytes`

## Final result

The maximum message length is **128 bytes**.

## Why larger messages are safe from this specific attack

If `m^3 ≥ N1 · N2 · N3`, then CRT only gives `m^3 mod (N1 · N2 · N3)` instead of the true integer `m^3`. In that case, taking the cube root of the reconstructed value does not recover the original message.

So the broadcast attack fails once the message is large enough that its cube wraps around the modulus product.

Even then, textbook RSA is still insecure for other reasons, especially because it is deterministic and has no padding.
