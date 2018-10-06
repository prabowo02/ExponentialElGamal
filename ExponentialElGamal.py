import random


class CipherText:
    def __init__(self, p, c1, c2):
        self.p = p
        self.c1 = c1
        self.c2 = c2
        
        
    def __add__(self, other):
        if isinstance(other, CipherText):            
            if self.p != other.p:
                raise ValueError('p not same')
            
            return CipherText(self.p, self.c1 * other.c1 % self.p, self.c2 * other.c2 % self.p)
            
        raise TypeError('Invalid operand')
        
        
    def __mul__(self, other):
        # Multiplication by constant
        if isinstance(other, int):
            if other >= 0:
                return CipherText(self.p, pow(self.c1, other, self.p), pow(self.c2, other, self.p))
            else:
                return CipherText(self.p, pow(pow(self.c1, -other, self.p), self.p - 2, self.p), pow(pow(self.c2, -other, self.p), self.p - 2, self.p))


class ExponentialElGamal:
    # Given a prime p and a secret key, generate g and public key
    def __init__(self, p, g, h):
        # Prime number
        self.p = p
        
        # Generator
        self.g = g
        
        # Public key
        self.h = h


    # Input: A message m
    # Output: Cipher text of m
    def encrypt(self, message):
        r = random.randint(0, self.p - 1)

        if message >= 0:
            return CipherText(self.p, pow(self.g, r, self.p), pow(self.g, message, self.p) * pow(self.h, r, self.p) % self.p)
        else:
            return CipherText(self.p, pow(self.g, r, self.p), pow(pow(self.g, -message, self.p), self.p - 2, self.p) * pow(self.h, r, self.p) % self.p)
        
    
    # Input: cipher text, secret key, and message space (domain)
    # Output: Decrypted message m from cipher text
    def decrypt(self, cipher_text, sk, domain=(-1, 1)):
        g_power_m = cipher_text.c2 * pow(pow(cipher_text.c1, sk, self.p), self.p - 2, self.p) % self.p
        
        for m in domain:
            if m >= 0:
                if pow(self.g, m, self.p) == g_power_m:
                    return m
            else:
                if pow(pow(self.g, -m, self.p), self.p - 2, self.p) == g_power_m:
                    return m

        raise Exception('Invalid domain')

