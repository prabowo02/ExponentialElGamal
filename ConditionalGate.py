import random

from ExponentialElGamal import ExponentialElGamal
from KeyGenerator import KeyGenerator


class MultiElGamal:
    # p is safe prime
    def __init__(self, p, keys, g=None):
        self.servers = [ExponentialElGamal(p, key, g) for key in keys]
        
        self.s = []
        
        self.g = g or KeyGenerator.generate_primitive_root(p)


    def encrypt(self, text):
        self.s = []
        
        for server in self.servers:
            self.s.append(random.randint(0, 1))

            text = server.encrypt(text * self.s[-1]) + server.encrypt(0)

        return text
        

    def decrypt(self, text, keys, domain=(-1, 1)):
        for server, s, key in zip(self.servers, self.s, keys):
            pass
