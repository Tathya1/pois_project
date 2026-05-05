import random

class DLP_OWF:
    def __init__(self):
        self.p = 2147483647 
        self.g = 5

    def evaluate(self, x):
        """The One-Way Function f(x) = g^x mod p"""
        return pow(self.g, x, self.p)
    
    def goldreich_levin_hcb(self, x, r):
        """
        The Goldreich-Levin Hard-Core Bit.
        Computes the dot product of binary x and binary r mod 2.
        """
        inner_product = x & r
        bit_sum = bin(inner_product).count('1')
        return str(bit_sum % 2)
    
    def verify_hardness(self, trials=5):
        print("Testing OWF hardness...")

        for _ in range(trials):
            x = random.randint(1, 100000)
            y = self.evaluate(x)

            found = False
            for guess in range(10000):
                if self.evaluate(guess) == y:
                    found = True
                    break

            print(f"x={x}, inversion success={found}")