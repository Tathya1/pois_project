class PRG:
    def __init__(self, owf):
        self.owf = owf
        self.x = None # The evolving part of the state
        self.r = None # The fixed random string for GL

    def seed(self, s):
        """
        Fix: Handles decimal strings (like '1234') or bitstrings.
        It derives both x and r from the provided seed.
        """
        s_str = str(s)
        
        # 1. Check if the input is a bitstring (only 0s and 1s)
        if all(c in '01' for c in s_str) and len(s_str) > 1:
            mid = len(s_str) // 2
            x_val = int(s_str[:mid], 2)
            r_val = int(s_str[mid:], 2)
        else:
            # 2. Otherwise, treat it as a standard decimal integer
            try:
                val = int(s_str)
            except ValueError:
                # Fallback for non-numeric strings
                val = hash(s_str)
            
            x_val = val
            # Create a different value for r using a bitwise XOR (0x5555 is 010101...)
            r_val = val ^ 0x55555555

        # Ensure x and r stay within the bounds of the prime p
        self.x = x_val % self.owf.p
        self.r = r_val % self.owf.p

    def next_bits(self, n, l=0):
        """
        Fix: Added l=0 as a default value so that calling 
        next_bits(length) from your test script works perfectly.
        """
        if self.x is None or self.r is None:
            raise ValueError("PRG must be seeded with (x, r).")

        output_bits = []
        total_length = n + l

        for _ in range(total_length):
            # 1. Extract the GL Hard-Core Bit using current x and fixed r
            bit = self.owf.goldreich_levin_hcb(self.x, self.r)
            output_bits.append(bit)
            
            # 2. Update only the x component: x_{i+1} = f(x_i)
            self.x = self.owf.evaluate(self.x)

        return "".join(output_bits)