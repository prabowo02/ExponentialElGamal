import random


class KeyGenerator:
    # Input: 
    #   - an integer n
    #   - an optional input `iteration`. The higher it is, the higher the probability of the correctness
    # Output: True if n is prime, otherwise False
    # Primality testing using Miller-Rabin
    @staticmethod
    def is_prime(n, iteration=20):
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # 2**r * d = n-1, d odd
        r = len(bin(n-1)) - len(bin(n-1).rstrip('0'))
        d = (n-1) // 2**r
        
        for i in range(iteration):
            a = random.randint(2, n-2)
            x = pow(a, d, n)
            
            if x == 1 or x == n-1:
                continue
            
            composite = True
            for j in range(r-1):
                x = x * x % n
                if x == n-1:
                    composite = False
                    break
                    
            if composite:
                return False
            
        return True
        
    
    # Returns a random `length`-bit prime number
    @staticmethod
    def generate_prime_number(length=1024):
        prime_lower_bound, prime_upper_bound = 2**(length-1), 2**length - 1
        while True:
            p = random.randint(prime_lower_bound, prime_upper_bound)
            
            if KeyGenerator.is_prime(p):
                return p
                
                
    # Returns a random `length`-bit prime number of the form 2*p + 1, where p is prime too
    @staticmethod
    def generate_safe_prime(length=1024):
        while True:
            p = KeyGenerator.generate_prime_number(length - 1)
            
            if p % 3 == 1:
                continue
            
            if p % 5 == 2:
                continue
                
            if p % 7 == 3:
                continue
                
            if p % 11 == 5:
                continue
            
            if KeyGenerator.is_prime(2*p + 1):
                return 2*p + 1
    
    
    # Input: a prime number p = 2*q + 1, where q prime
    # Output: a primitive root mod p
    @staticmethod
    def generate_primitive_root(p):
        lower_g, upper_g = 3, p-1
        
        p1, p2 = 2, (p-1) // 2
        
        while True:
            g = random.randint(lower_g, upper_g)
            
            if pow(g, p1, p) == 1 or pow(g, p2, p) == 1:
                continue
                
            return g
            
            