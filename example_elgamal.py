import random

from ExponentialElGamal import ExponentialElGamal
from KeyGenerator import generate_exponential_elgamal_key


# Prime, generator, public key, secret key
p, g, pk, sk = generate_exponential_elgamal_key()
# print(p, g, pk, sk, sep='\n================\n')

# Create elgamal instance
elgamal = ExponentialElGamal(p, g, pk)

# Encrypt message 2
x = elgamal.encrypt(2)
# Encrypt message 3
y = elgamal.encrypt(3)

# The possible value of the message, required for decryption.
message_space = [i for i in range(-10, 10)]

# Addition on encrypted data
z = x + y

# Decrypt [x + y], by giving the message domain ({-10, -9, ..., 9} in this case)
# This should output 5
print(elgamal.decrypt(z, sk=sk, domain=message_space))

# Multiplication by constant
z = x * -3

# Decrypt [-3x], and should output -6
print(elgamal.decrypt(z, sk=sk, domain=message_space))
