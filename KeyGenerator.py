import random

from Safe1024BitPrimes import get_random_1024_bit_safe_prime


# Input: 
#   - an integer n
#   - an optional input `iteration`. The higher it is, the higher the probability of the correctness
# Output: True if n is prime, otherwise False
# Primality testing using Miller-Rabin
def is_prime(n, iteration=20):
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # 2**r * d = n-1, d odd
    r = len(bin(n-1)) - len(bin(n-1).rstrip('0'))
    d = (n-1) // 2**r
    
    for i in range(iteration):
        a = random.randint(2, n-2)
        x = pow(a, d, n)
        
        if x == 1 or x == n-1:
            continue
        
        composite = True
        for j in range(r-1):
            x = x * x % n
            if x == n-1:
                composite = False
                break
                
        if composite:
            return False
        
    return True
    

# Returns a random `length`-bit prime number
def generate_prime_number(length=1024):
    prime_lower_bound, prime_upper_bound = 2**(length-1), 2**length - 1
    while True:
        p = random.randint(prime_lower_bound, prime_upper_bound)
        
        if KeyGenerator.is_prime(p):
            return p
            
            
# Returns a random `length`-bit prime number of the form 2*p + 1, where p is prime too
def generate_safe_prime(length=1024):
    while True:
        p = KeyGenerator.generate_prime_number(length - 1)
        
        if KeyGenerator.is_prime(2*p + 1):
            return 2*p + 1


# Input: a prime number p = 2*q + 1, where q prime
# Output: a primitive root mod p
def generate_primitive_root(p):
    lower_g, upper_g = 3, p-1
    
    p1, p2 = 2, (p-1) // 2
    
    while True:
        g = random.randint(lower_g, upper_g)
        
        if pow(g, p1, p) == 1 or pow(g, p2, p) == 1:
            continue
            
        return g
        
        
# Input: the length of the key
# Output: A `length`-bit safe prime, a generator, a secret key, and a public key for elgamal
def generate_exponential_elgamal_key(length=1024):
    if length == 1024:
        p = get_random_1024_bit_safe_prime()
    else:
        p = generate_safe_prime(length)
    
    # Generator
    g = generate_primitive_root(p)
    g = g*g % p
    
    # Secret key
    sk = random.randint(2, (p-1)//2)
    
    # Public key
    pk = pow(g, sk, p)
    
    # print(p, g, pk, sk, sep='\n=====\n')
    
    return p, g, pk, sk

    
# Input: number of servers and length of the key
# Output: A `length`-bit safe prime number, a generator, n secret keys, and n public keys for elgamal
def generate_distributed_exponential_elgamal_keys(n, length=1024):
    if length == 1024:
        p = get_random_1024_bit_safe_prime()
    else:
        p = generate_safe_prime(length)
        
    # Generator
    g = generate_primitive_root(p)
    g = g*g % p
    
    # Secret keys: [x_1, x_2, ..., x_n]
    secret_keys = [random.randint(2, (p-1)//2) for i in range(n)]
    
    # Public keys: [h_1, h_2, ..., h_n]
    public_keys = [pow(g, sk, p) for sk in secret_keys]
    
    # Common public key h = h_1 * h_2 * ... * h_n
    h = 1
    for pk in public_keys:
        h = h * pk % p
    
    # print(p, g, secret_keys, h, public_keys, sep='\n=====\n')
    
    return p, g, h, secret_keys
