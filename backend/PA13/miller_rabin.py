"""
PA#13 — Miller-Rabin Primality Testing

Implements (no external crypto libraries):
  - mod_exp(base, exp, mod)    : square-and-multiply (replaces library pow)
  - miller_rabin(n, k)         : probabilistic primality test
  - is_prime(n, k)             : convenience wrapper
  - gen_prime(bits, k)         : random probable prime of given bit length
  - gen_safe_prime(bits, k)    : safe prime p = 2q+1 (used by PA#11 DH groups)

Error probability of miller_rabin: <= 4^(-k).
With k=40 this is ~10^(-24), which is negligible.
"""

import secrets


# ---------------------------------------------------------------------------
# Core: square-and-multiply modular exponentiation
# ---------------------------------------------------------------------------

def mod_exp(base: int, exp: int, mod: int) -> int:
    """
    Square-and-multiply modular exponentiation.
    Computes base^exp mod mod without using Python's built-in pow().

    Algorithm:
      result = 1
      while exp > 0:
          if exp is odd: result = result * base mod mod
          exp >>= 1
          base = base^2 mod mod
    """
    if mod == 1:
        return 0
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:                        # if current bit of exp is set
            result = (result * base) % mod
        exp >>= 1                          # shift to next bit
        base = (base * base) % mod
    return result


# ---------------------------------------------------------------------------
# Miller-Rabin primality test
# ---------------------------------------------------------------------------

def miller_rabin(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin probabilistic primality test.

    Returns True  if n is *probably* prime   (error prob <= 4^(-k))
    Returns False if n is *definitely* composite.

    Algorithm:
      1. Handle small/even cases directly.
      2. Write n-1 = 2^s * d  with d odd.
      3. For k independent witness rounds:
           a. Pick random a in {2, ..., n-2}.
           b. x <- a^d mod n.
           c. If x == 1 or x == n-1: this round passes (continue).
           d. Repeat s-1 times: x <- x^2 mod n.
                If x == n-1: round passes (break).
           e. If no squaring hit n-1: n is definitely composite.
      4. If all k rounds pass: return True (probably prime).
    """
    # --- edge cases ---
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # --- write n-1 = 2^s * d ---
    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    # --- k witness rounds ---
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2      # a in [2, n-2]
        x = mod_exp(a, d, n)

        if x == 1 or x == n - 1:
            continue                           # this round passes

        for _ in range(s - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                break                          # round passes
        else:
            return False                       # definitely composite

    return True                                # probably prime


def is_prime(n: int, k: int = 40) -> bool:
    """Convenience wrapper around miller_rabin."""
    return miller_rabin(n, k)


# ---------------------------------------------------------------------------
# Prime generation
# ---------------------------------------------------------------------------

def gen_prime(bits: int, k: int = 40) -> int:
    """
    Generate a random probable prime of exactly `bits` bits.

    Strategy:
      - Sample a random odd integer with the MSB set (ensures exact bit length).
      - Test with Miller-Rabin until one passes.

    By the Prime Number Theorem, roughly 1 in ln(2^bits) = bits * ln(2)
    candidates of this size is prime, so expected ~1.4*bits candidates needed.
    """
    if bits < 2:
        raise ValueError("bits must be >= 2")

    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1))     # set MSB -> ensures exact bit length
        candidate |= 1                      # ensure odd

        if miller_rabin(candidate, k):
            return candidate


def gen_prime_with_count(bits: int, k: int = 40) -> tuple[int, int]:
    """
    Generate a random probable prime of exactly `bits` bits and return
    (prime, candidates_tested).

    This is useful for benchmarking the expected ~ln(n) candidates predicted
    by the Prime Number Theorem.
    """
    if bits < 2:
        raise ValueError("bits must be >= 2")

    candidates = 0
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1))     # set MSB -> ensures exact bit length
        candidate |= 1                      # ensure odd

        candidates += 1
        if miller_rabin(candidate, k):
            return candidate, candidates


def gen_safe_prime(bits: int, k: int = 40) -> tuple[int, int]:
    """
    Generate a safe prime p = 2q + 1 where both p and q are probable primes.

    Returns (p, q).

    Used by PA#11 (DH key exchange) to build a prime-order-q subgroup of Z*_p.
    Safe primes are stronger for DH because they prevent small-subgroup attacks.

    Note: generation takes longer than gen_prime because both p and q must pass
    Miller-Rabin. For bits <= 64 this is fast (milliseconds).
    """
    while True:
        q = gen_prime(bits - 1, k)
        p = 2 * q + 1
        if miller_rabin(p, k):
            return p, q
