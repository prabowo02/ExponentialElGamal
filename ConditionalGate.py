import random

from ExponentialElGamal import ExponentialElGamal


class ConditionalGate:
    # Input: a safe prime p, generator g, and public_keys
    def __init__(self, n, p, g, h):
        self.n = n
        
        self.p = p
        
        self.g = g

        self.servers = [ExponentialElGamal(p, g, h) for i in range(n)]

        self.s = [random.choice([-1, 1]) for i in range(n)]

        
    def encrypt(self, message):
        return random.choice(self.servers).encrypt(message)


    # Input: A ciphertext `text` encrypted using ExponentialElGamal
    # Output: Another ciphertext which is reencrypted by all the servers 
    def reencrypt_with_s(self, text):
        for server, s in zip(self.servers, self.s):
            text = text * s + server.encrypt(0)

        return text


    # Input: - A ciphertext `text`
    #        - `secret_keys` to all the servers
    # Output: The decrypted message
    def decrypt(self, text, secret_keys, domain=(-1, 1)):
        g_power_m = text.c2
        for server, sk in zip(self.servers, secret_keys):
            g_power_m = g_power_m * pow(pow(text.c1, sk, server.p), server.p - 2, server.p) % server.p

        # print(self.s)
        # print(self.g, g_power_m)
        for m in domain:
            if m >= 0:
                if pow(self.g, m, self.p) == g_power_m:
                    return m
            else:
                if pow(pow(self.g, -m, self.p), self.p - 2, self.p) == g_power_m:
                    return m

        raise Exception('Invalid domain')
