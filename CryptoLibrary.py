encryption_scheme = None


def set_encryption_scheme(scheme):
    global encryption_scheme
    encryption_scheme = scheme


# Input: E(x) where x is either -1 or 1, and y
# Output: E(x * y)
def conditional_gate(x, y, secret_keys):
    x = encryption_scheme.reencrypt_with_s(x)
    y = encryption_scheme.reencrypt_with_s(y)

    x_n = encryption_scheme.decrypt(x, secret_keys)

    return y * x_n


# Input: E(x) where x is either 0 or 1, and y
# Output: E(x * y)
def conditional_gate_binary(x, y, secret_keys):
    negative_one = encryption_scheme.encrypt(-1)

    x = x*2 + negative_one
    result = conditional_gate(x, y, secret_keys) + y

    q = (encryption_scheme.p - 1) // 2
    inv_2 = pow(2, q-2, q)

    return result * inv_2


# Input: An integer `n`
# Output: A ciphertext of `n` using `encryption_scheme`
def encrypt_binary(n, binary_length=1):
    if n < 0:
        return [encryption_scheme.encrypt(1)] + [encryption_scheme.encrypt(int(bit)) for bit in '{:0{}b}'.format(n + (1 << binary_length-1), binary_length-1)]
    return [encryption_scheme.encrypt(int(bit)) for bit in '{:0{}b}'.format(n, binary_length)]


# Input: x = [E(x_{m-1}), ..., E(x_0)]
# Output: Integer representation of x_{m-1}...x_0
def decrypt_binary(cipher, secret_key):
    return int(''.join([str(encryption_scheme.decrypt(bit, secret_key, domain=(0, 1))) for bit in cipher]), 2)


# Input: x, y with values either E(0) or E(1)
# Output: x xor y
def secure_bit_xor(x, y, secret_key):
    negative_one = encryption_scheme.encrypt(-1)
    return x + conditional_gate(x*2 + negative_one, y, secret_key) * -1


# Input: X = [E(x_{m-1}), ..., E(x_0)] and
#        Y = [E(y_{m-1}), ..., E(y_0)]
# Output: [E(x_{m-1} ^ y_{m-1}), ..., E(x_0 ^ y_0)] where ^ is xor operation
def secure_xor(X, Y, secret_key):
    result = []

    for x, y in zip(X, Y):
        result.append(secure_bit_xor(x, y, secret_key))

    return result


# Input: X = E(x) = [E(x_{m-1}), ..., E(x_0)] and
#        Y = E(y) = [E(y_{m-1}), ..., E(y_0)]
# Output: Z = E(z) = E(x + y) = [E(z_{m-1}), ..., E(z_0)]
def secure_add(X, Y, secret_key):
    c = encryption_scheme.encrypt(0)
    Z = []

    for x, y in zip(X[::-1], Y[::-1]):
        xy = conditional_gate_binary(x, y, secret_key)
        xyc = conditional_gate_binary(c, x + y + xy*-2, secret_key)

        # x*y + x*c + y*c - 2*x*y*c
        nc = xy + xyc
        z = x + y + c + nc * -2

        Z.append(z)
        c = nc

    return Z[::-1]


# Input: X = E(x) = [E(x_{m-1}), ..., E(x_0)] and
#        Y = E(y) = [E(y_{m-1}), ..., E(y_0)]
# Output: E(1) if x < y else E(0)
def secure_comparison(X, Y, secret_key):
    one = encryption_scheme.encrypt(1)
    t = encryption_scheme.encrypt(0)
    
    X[0], Y[0] = Y[0], X[0]

    for x, y in zip(X[::-1], Y[::-1]):
        xy = conditional_gate_binary(x, y, secret_key)

        # t(1 - x - y + 2xy) + (1 - x)y

        # if x = y then 1 else 0
        x_eq_y = one + x*-1 + y*-1 + xy*2

        # if x < y then 1 else 0
        x_lt_y = y + xy*-1

        t = conditional_gate_binary(t, x_eq_y, secret_key) + x_lt_y

    X[0], Y[0] = Y[0], X[0]
        
    return t


# Input: X = [E(x_{m-1}), ..., E(x_0)] and
#        Y = [E(y_{m-1}), ..., E(y_0)]
# Output: E(1) if x != y else E(0)
def secure_inequality(X, Y, secret_key):
    one = encryption_scheme.encrypt(1)
    u = encryption_scheme.encrypt(0)

    for x, y in zip(X[::-1], Y[::-1]):
        xy = conditional_gate_binary(x, y, secret_key)

        # if x != y then 1 else 0
        x_ne_y = x + y + xy*-2

        # if x = y then 1 else 0
        x_eq_y = one + x_ne_y*-1

        u = conditional_gate_binary(u, x_eq_y, secret_key) + x_ne_y

    return u


# Input: X = [E(x_{m-1}), ..., E(x_0)],
#        Y = [E(y_{m-1}), ..., E(y_0)] and
#        bit = E(0) or bit =  E(1)
# Output: If bit = E(0) output X, otherwise output Y
def secure_multiplexer(X, Y, bit, secret_key):
    bit_complement = secure_bit_xor(bit, encryption_scheme.encrypt(1), secret_key)
    return secure_add(
        [conditional_gate_binary(x, bit_complement, secret_key) for x in X],
        [conditional_gate_binary(y, bit, secret_key) for y in Y],
        secret_key,
    )

    
# Input: X = [E(x_{m-1}), ..., E(x_0)] and
#        Y = [E(y_{m-1}), ..., E(y_0)]
# Output: Z = E(z) = E(x * y) = [E(z_{m-1}), ..., E(z_0)]
def secure_multiply(X, Y, secret_key):
    result = encrypt_binary(0, binary_length=len(X))
    adder = X
    
    for y in Y[::-1]:
        y_times_adder = [conditional_gate_binary(y, bit, secret_key) for bit in adder]
        result = secure_add(result, y_times_adder, secret_key)
        adder = secure_add(adder, adder, secret_key)
        
    return result
