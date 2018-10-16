# Input: E(x) where x is either -1 or 1, and y
# Output: E(x * y)
def conditional_gate(x, y, encryption_scheme, secret_keys):
    x = encryption_scheme.reencrypt_with_s(x)
    y = encryption_scheme.reencrypt_with_s(y)
    
    x_n = encryption_scheme.decrypt(x, secret_keys)

    return y * x_n


# Input: An integer `n`, and the `encryption_scheme`
# Output: A ciphertext of `n` using `encryption_scheme`
def encrypt_binary(n, encryption_scheme, binary_length=0):
    return [encryption_scheme.encrypt(int(bit)) for bit in '{:0{}b}'.format(n, binary_length)]


# Input: x = [E(x_{m-1}), ..., E(x_0)]
# Output: Integer representation of x_{m-1}...x_0
def decrypt_binary(cipher, encryption_scheme, secret_key):
    return int(''.join([str(encryption_scheme.decrypt(bit, secret_key, domain=(0, 1))) for bit in cipher]), 2)


# Input: x, y with values either E(0) or E(1)
# Output: x xor y
def secure_bit_xor(x, y, encryption_scheme, secret_key):
    negative_one = encryption_scheme.encrypt(-1)
    return x + conditional_gate(x*2 + negative_one, y, encryption_scheme, secret_key) * -1


# Input: x = [E(x_{m-1}), ..., E(x_0)] and
#        y = [E(y_{m-1}), ..., E(y_0)]
# Output: [E(x_{m-1} ^ y_{m-1}), ..., E(x_0 ^ y_0)] where ^ is xor operation
def secure_xor(X, Y, encryption_scheme, secret_key):
    result = []

    for x, y in zip(X, Y):
        result.append(secure_bit_xor(x, y, encryption_scheme, secret_key))

    return result
