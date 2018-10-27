import random

from ConditionalGate import ConditionalGate
from ExponentialElGamal import ExponentialElGamal
from KeyGenerator import generate_distributed_exponential_elgamal_keys


NUMBER_OF_SERVERS = 3

p, g, h, secret_keys = generate_distributed_exponential_elgamal_keys(NUMBER_OF_SERVERS)

alice = ExponentialElGamal(p, g, h)
bob = ExponentialElGamal(p, g, h)

conditional_gate = ConditionalGate(NUMBER_OF_SERVERS, p, g, h)

a = -1
b = 123

cipher_a = alice.encrypt(a)
cipher_b = bob.encrypt(b)

distributed_cipher_a = conditional_gate.reencrypt_with_s(cipher_a)
distributed_cipher_b = conditional_gate.reencrypt_with_s(cipher_b)

a_n = conditional_gate.decrypt(distributed_cipher_a, secret_keys)
print(a_n)

distributed_cipher_ab = distributed_cipher_b * a_n

ab = conditional_gate.decrypt(distributed_cipher_ab, secret_keys, domain=range(-200, 200))
print(ab)
