import math
from scipy.special import gammaincc

def frequency_test(bits):
    """
    NIST Frequency (Monobit) Test.
    Checks if the proportion of zeroes and ones is approximately 0.5.
    """
    n = len(bits)
    s_n = sum(1 if b == '1' else -1 for b in bits)
    
    s_obs = abs(s_n) / math.sqrt(n)
    
    p_value = math.erfc(s_obs / math.sqrt(2))
    
    return {
        "p_value": float(p_value),
        "pass": bool(p_value >= 0.01)
    }

def runs_test(bits):
    """
    NIST Runs Test.
    Checks if the total number of runs of consecutive bits is as expected.
    """
    n = len(bits)
    n_ones = bits.count('1')
    pi = n_ones / n

    if abs(pi - 0.5) >= (2 / math.sqrt(n)):
        return {"p_value": 0.0, "pass": False}

    v_n_obs = 1
    for i in range(n - 1):
        if bits[i] != bits[i+1]:
            v_n_obs += 1

    numerator = abs(v_n_obs - 2 * n * pi * (1 - pi))
    denominator = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    
    p_value = math.erfc(numerator / denominator)

    return {
        "p_value": float(p_value),
        "pass": bool(p_value >= 0.01)
    }

def serial_test(bits):
    """
    Simplified NIST Serial Test (m=2).
    Checks the frequency of all possible overlapping patterns of length m.
    """
    n = len(bits)
    m = 2
    
    ext_bits = bits + bits[0:m-1]
    
    def get_psi_squared(block_size):
        if block_size == 0:
            return 0
        
        counts = {}
        for i in range(n):
            pattern = ext_bits[i:i+block_size]
            counts[pattern] = counts.get(pattern, 0) + 1
            
        sum_sq = sum(c**2 for c in counts.values())
        return (2**block_size / n) * sum_sq - n

    psi_m = get_psi_squared(m)
    psi_m1 = get_psi_squared(m-1)
    psi_m2 = get_psi_squared(m-2)

    del1 = psi_m - psi_m1
    del2 = psi_m - 2*psi_m1 + psi_m2

    p_value1 = gammaincc(2**(m-2), del1 / 2)
    p_value2 = gammaincc(2**(m-3) if m > 2 else 0.5, del2 / 2)

    return {
        "p_value1": float(p_value1),
        "p_value2": float(p_value2),
        "pass": bool(p_value1 >= 0.01 and p_value2 >= 0.01)
    }