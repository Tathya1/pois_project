from owf import DLP_OWF
from prg import PRG
from tests import frequency_test, runs_test, serial_test

def test_prg():
    print("\n=== Testing PRG ===")
    owf = DLP_OWF()
    prg = PRG(owf)

    seed = input("Enter seed (default 123456789): ") or "123456789"
    length = input("Enter number of bits (default 64): ")

    length = int(length) if length else 64

    prg.seed(seed)
    bits = prg.next_bits(length)

    print("\nGenerated bits:")
    print(bits)
    print(f"Length: {len(bits)}\n")

    return bits


def test_statistical_tests(bits):
    print("\n=== Statistical Tests ===")

    freq = frequency_test(bits)
    runs = runs_test(bits)
    serial = serial_test(bits)

    print(f"Frequency: p={freq['p_value']:.4f} → {'PASS' if freq['pass'] else 'FAIL'}")
    print(f"Runs:      p={runs['p_value']:.4f} → {'PASS' if runs['pass'] else 'FAIL'}")
    print(f"Serial:    p1={serial['p_value1']:.4f}, p2={serial['p_value2']:.4f} → {'PASS' if serial['pass'] else 'FAIL'}")
    print()


def test_hardness():
    print("\n=== Testing OWF Hardness ===")
    owf = DLP_OWF()

    owf.verify_hardness()
    print()


def main():

    last_bits = test_prg()
    test_statistical_tests(last_bits)
    test_hardness()



if __name__ == "__main__":
    main()