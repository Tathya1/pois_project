import secrets

from cpa import CPA
from stream import BLOCK_BYTES

cpa = CPA()

def simulate_ind_cpa_dummy(rounds=1, oracle_queries=50):
    wins = 0
    total = 0

    for _ in range(rounds):
        key = secrets.randbits(BLOCK_BYTES * 8)

        for _ in range(oracle_queries):
            msg = secrets.token_hex(8)
            cpa.enc(key, msg.encode())

        m0 = "message0"
        m1 = "message1"
        
        if len(m0) != len(m1):
            raise ValueError("Messages must be equal length")

        b = secrets.randbelow(2)
        cpa.enc(key, (m0 if b == 0 else m1).encode())

        guess = secrets.randbelow(2)

        if guess == b:
            wins += 1
        total += 1

    win_rate = wins / total if total else 0
    advantage = abs(win_rate - 0.5) * 2

    return {
        "wins": wins,
        "total": total,
        "win_rate": win_rate,
        "advantage": advantage,
    }


def simulate_rounds(rounds=20, reuse_nonce=False):
    wins = 0
    total = 0

    for _ in range(rounds):
        key = secrets.randbits(BLOCK_BYTES * 8)

        fixed_r = secrets.randbits(BLOCK_BYTES * 8) if reuse_nonce else None

        m0 = "message0"
        m1 = "message1"

        if len(m0) != len(m1):
            raise ValueError("Messages must be equal length")

        b = secrets.randbelow(2)

        r, c = cpa.enc(key, (m0 if b == 0 else m1).encode(), r=fixed_r)

        if reuse_nonce:
            r0, c0 = cpa.enc(key, m0.encode(), r=fixed_r)
            r1, c1 = cpa.enc(key, m1.encode(), r=fixed_r)

            if c == c0:
                guess = 0
            elif c == c1:
                guess = 1
            else:
                guess = secrets.randbelow(2)
        else:
            guess = secrets.randbelow(2)

        if guess == b:
            wins += 1

        total += 1

    win_rate = wins / total if total else 0
    advantage = abs(win_rate - 0.5) * 2

    return {
        "wins": wins,
        "total": total,
        "win_rate": win_rate,
        "advantage": advantage,
    }
