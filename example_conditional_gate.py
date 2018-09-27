import random

from ConditionalGate import MultiElGamal
from ExponentialElGamal import ExponentialElGamal
from KeyGenerator import KeyGenerator
from Safe1024BitPrimes import get_random_1024_bit_safe_prime


p = get_random_1024_bit_safe_prime()
g = KeyGenerator.generate_primitive_root()

alice_key = random.randint(2, p-1)
alice = ExponentialElGamal(p, alice_key, g)

bob_key = random.randint(2, p-1)
bob = ExponentialElGamal(p, bob_key, g)

server_keys = [random.randint(2, p-1) for i in range(3)]
multiElGamal = MultiElGamal(p, server_keys, g)

alice.h = multiElGamal.h
bob.h = multiElGamal.h

a = -1
b = 1234

cipher_a = alice.encrypt(a)
cipher_b = bob.encrypt(b)

distributed_cipher_a = multiElGamal.encrypt(cipher_a)
distributed_cipher_b = multiElGamal.encrypt(cipher_b)


