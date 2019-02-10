from ConditionalGate import ConditionalGate
from CryptoLibrary import decrypt_binary
from CryptoLibrary import encrypt_binary
from CryptoLibrary import set_encryption_scheme
from CryptoLibrary import secure_add
from CryptoLibrary import secure_comparison
from CryptoLibrary import secure_multiply
from CryptoLibrary import secure_xor
from CryptoLibrary import secure_inequality
from KeyGenerator import generate_distributed_exponential_elgamal_keys


NUMBER_OF_SERVERS = 3

p, g, h, secret_keys = generate_distributed_exponential_elgamal_keys(NUMBER_OF_SERVERS, 128)
set_encryption_scheme(ConditionalGate(NUMBER_OF_SERVERS, p, g, h))

# =========================== XOR ============================

# Encrypt binary 1100
x = encrypt_binary(12)

# Encrypt binary 1010
y = encrypt_binary(10)

# Result should be 6 = binary 110
x_xor_y = secure_xor(x, y, secret_keys)
print(decrypt_binary(x_xor_y, secret_keys))

# =========================== ADD =============================

# Encrypt binary 00011100
x = encrypt_binary(28, binary_length=8)

# Encrypt binary 00011010
y = encrypt_binary(26, binary_length=8)

# Result should be 54
x_plus_y = secure_add(x, y, secret_keys)
print(decrypt_binary(x_plus_y, secret_keys))

# ========================= COMPARISON ========================

# Encrypt binary 1100
x = encrypt_binary(12)

# Encrypt binary 1010
y = encrypt_binary(10)

# Result should be 0
x_lt_y = [secure_comparison(x, y, secret_keys)]
print(decrypt_binary(x_lt_y, secret_keys))

# Result should be 1
y_lt_x = [secure_comparison(y, x, secret_keys)]
print(decrypt_binary(y_lt_x, secret_keys))

# ======================== EQUALITY ===========================

x = encrypt_binary(6)
y = encrypt_binary(3)

# Result should be 1
x_eq_y = [secure_inequality(x, y, secret_keys)]
print(decrypt_binary(x_eq_y, secret_keys))

x = encrypt_binary(6)
y = encrypt_binary(6)

# Result should be 0
x_eq_y = [secure_inequality(x, y, secret_keys)]
print(decrypt_binary(x_eq_y, secret_keys))

# ========================= MULTIPLY ============================

x = encrypt_binary(3, binary_length=32)
y = encrypt_binary(4, binary_length=32)

# Result should be 12
x_mul_y = secure_multiply(x, y, secret_keys)
print(decrypt_binary(x_mul_y, secret_keys))
