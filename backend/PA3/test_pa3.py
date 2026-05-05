from cpa import CPA
from cpa_game import simulate_ind_cpa_dummy, simulate_rounds


def encrypt():
    print("\n=== Encrypt ===")

    key = input("Enter key (hex/int, default 1a2b3c4d): ") or "1a2b3c4d"
    message = input("Enter message: ")

    reuse = input("Reuse nonce? (y/n): ").lower() == "y"

    r = None
    if reuse:
        r_input = input("Enter nonce r (hex, optional): ")
        if r_input:
            r = int(r_input, 16)

    r_out, c_out = CPA.enc_text(key, message, r=r)

    print("\nCiphertext:")
    print(f"r = {r_out}")
    print(f"c = {c_out}")
    print()


def decrypt():
    print("\n=== Decrypt ===")

    key = input("Enter key: ")
    r = input("Enter r (hex): ")
    c = input("Enter c (hex): ")

    try:
        message = CPA.dec_text(key, r, c)
        print("\nDecrypted message:")
        print(message)
    except Exception as e:
        print("Error:", e)

    print()


def simulate_dummy():
    print("\n=== Dummy Adversary ===")

    rounds = input("Rounds (default 20): ")
    queries = input("Oracle queries (default 50): ")

    rounds = int(rounds) if rounds else 20
    queries = int(queries) if queries else 50

    result = simulate_ind_cpa_dummy(rounds=rounds, oracle_queries=queries)

    print("\nResult:")
    print(result)
    print()


def simulate_attack():
    print("\n=== IND-CPA Simulation ===")

    rounds = input("Rounds (default 20): ")
    reuse = input("Reuse nonce? (y/n): ").lower() == "y"

    rounds = int(rounds) if rounds else 20

    result = simulate_rounds(rounds=rounds, reuse_nonce=reuse)

    print("\nResult:")
    print(result)
    print()


def demo():
    print("\nDemo: Secure vs Broken\n")

    print("Without nonce reuse (secure):")
    secure = simulate_rounds(rounds=20, reuse_nonce=False)
    print(secure)

    print("\nWith nonce reuse (broken):")
    broken = simulate_rounds(rounds=20, reuse_nonce=True)
    print(broken)

    print("\nNotice the advantage jump when nonce is reused!\n")
    
def test_non_block_message():
    print("\n=== Non-block-size Message Test ===")

    key = input("Enter key (default 1a2b3c4d): ") or "1a2b3c4d"
    message = input("Enter message (try uneven length): ") or "hello123"

    print(f"\nOriginal length: {len(message)} bytes")

    r, c = CPA.enc_text(key, message)

    print("\nEncrypted:")
    print(f"r = {r}")
    print(f"c = {c}")
    print(f"Cipher length (bytes): {len(bytes.fromhex(c))}")

    decrypted = CPA.dec_text(key, r, c)

    print("\nDecrypted:")
    print(decrypted)

    if decrypted == message:
        print("\nSUCCESS: Padding + keystream handled correctly")
    else:
        print("\nERROR: Something is wrong")

    print()


def main():
    while True:
        print("\n========= CPA Test Menu =========")
        print("1. Encrypt message")
        print("2. Decrypt message")
        print("3. Simulate Dummy Adversary")
        print("4. Simulate IND-CPA Attack")
        print("5. Run Demo (secure vs broken)")
        print("6. Test non-block-size message")
        print("0. Exit")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            encrypt()

        elif choice == "2":
            decrypt()

        elif choice == "3":
            simulate_dummy()

        elif choice == "4":
            simulate_attack()

        elif choice == "5":
            demo()
            
        elif choice == "6":
            test_non_block_message()

        elif choice == "0":
            print("Exiting... ")
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()