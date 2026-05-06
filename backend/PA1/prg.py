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
        
        if all(c in '01' for c in s_str) and len(s_str) > 1:
            mid = len(s_str) // 2
            x_val = int(s_str[:mid], 2)
            r_val = int(s_str[mid:], 2)
        else:
            try:
                val = int(s_str)
            except ValueError:
                val = hash(s_str)
            
            x_val = val
            r_val = val ^ 0x55555555

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
            bit = self.owf.goldreich_levin_hcb(self.x, self.r)
            output_bits.append(bit)
            
            self.x = self.owf.evaluate(self.x)

        return "".join(output_bits)