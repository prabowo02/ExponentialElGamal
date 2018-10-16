from ConditionalGate import ConditionalGate
from CryptoLibrary import decrypt_binary
from CryptoLibrary import encrypt_binary
from CryptoLibrary import secure_xor
from KeyGenerator import generate_distributed_exponential_elgamal_keys


NUMBER_OF_SERVERS = 3

p, g, h, secret_keys = generate_distributed_exponential_elgamal_keys(NUMBER_OF_SERVERS)
encryption_scheme = ConditionalGate(NUMBER_OF_SERVERS, p, g, h)

# =========================== XOR ============================

# Encrypt binary 1100
x = encrypt_binary(12, encryption_scheme)

# Encrypt binary 1010
y = encrypt_binary(10, encryption_scheme)

# Result should be 6 = binary 110
x_xor_y = secure_xor(x, y, encryption_scheme, secret_keys)
print(decrypt_binary(x_xor_y, encryption_scheme, secret_keys))
