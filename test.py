import time

from ExponentialElGamal import ExponentialElGamal
from Safe1024BitPrimes import get_random_1024_bit_safe_prime

# This may take a while.
key = get_random_1024_bit_safe_prime()
elgamal = ExponentialElGamal(key)

# Encrypt message 2
x = elgamal.encrypt(2)
# Encrypt message 3
y = elgamal.encrypt(3)

# The possible value of the message, required for decryption.
message_domain = [i for i in range(-10, 10)]

# Addition on encrypted data
z = x + y

# Decrypt [x + y], by giving the message domain ({-10, -9, ..., 9} in this case)
# This should output 5
print(elgamal.decrypt(z, key=key, domain=message_domain))

# Multiplication by constant
z = x * -3

# Decrypt [-3x], and should output -6
print(elgamal.decrypt(z, key=key, domain=message_domain))
