import time

from django.http import HttpResponse

from .models import PublicKeys
from .models import Coefficients
from ConditionalGate import ConditionalGate
from CryptoLibrary import encrypt_binary
from CryptoLibrary import secure_add
from CryptoLibrary import secure_multiply
from CryptoLibrary import set_encryption_scheme
from ExponentialElGamal import CipherText

PRECISION = 64


def setup_encryption_scheme():
    public_keys_object = PublicKeys.objects.get()
    p = int(public_keys_object.prime)
    g = int(public_keys_object.generator)
    h = int(public_keys_object.public_key)

    set_encryption_scheme(
        ConditionalGate(3, p, g, h)
    )


def get_attrs(query_dict):
    age = int(query_dict['age'])
    gender = 0 if query_dict['gender'] == 'Male' else 1
    pressure = int(query_dict['pressure'])
    cholestoral = int(query_dict['cholestoral'])
    heart_rate = int(query_dict['heart_rate'])
    
    return age, gender, pressure, cholestoral, heart_rate


def get_encrypted_attrs(query_dict):
    return [encrypt_binary(attr, PRECISION) for attr in get_attrs(query_dict)]
    
    
def get_encrypted_coeffs():
    p = int(PublicKeys.objects.get().prime)
    coefficients_object = Coefficients.objects.get()
    
    def str_to_ciphers(s):
        s = s.split(';')
        return [[CipherText(p, int(s[j]), int(s[j+1])) for j in range(i, i+PRECISION*2, 2)] for i in range(0, len(s), PRECISION*2)]
    
    return (
        str_to_ciphers(coefficients_object.c1),
        str_to_ciphers(coefficients_object.c2),
        str_to_ciphers(coefficients_object.c3),
        str_to_ciphers(coefficients_object.c4),
        str_to_ciphers(coefficients_object.c5),
    )


def get_secret_key():
    secret_keys = PublicKeys.objects.get().secret_keys
    return [int(sk) for sk in secret_keys.split(';')]
    
    
def get_distances(attrs, coeffs, secret_key):
    distances = []

    for row in coeffs:
        distance = encrypt_binary(0, PRECISION)
        print('computing distance')
        for attr, coeff in zip(attrs, row):
            print('add one term')
            secure_add(distance, secure_multiply(attr, coeff, secret_key), secret_key)
        
        distance = secure_add(distance, row[-1], secret_key)
        
        distances.append(distance)
        
    return distances

    
def get_max_index(distances):
    encrypted_index = encrypt_binary(0, PRECISION)
    encrypted_max_distance = distances[0]
    
    for i in range(1, len(distances)):
        less_than = secure_comparison(encrypted_max_distance, distances[i], secret_key)
        
        encrypted_index = secure_multiplexer(
            encrypted_index,
            encrypt_binary(i, PRECISION),
            less_than,
            secret_key,
        )
        encrypted_max_distance = secure_multiplexer(
            encrypted_max_distance,
            distances[i],
            less_than,
            secret_key,
        )
    
    return decrypt_binary(encrypted_index, secret_key)


def predict(request):
    setup_encryption_scheme()
    
    attrs = get_encrypted_attrs(request.POST)
    coeffs = get_encrypted_coeffs()
    
    secret_key = get_secret_key()
    
    distances = get_distances(attrs, coeffs, secret_key)
    idx = get_max_index(distances, secret_key)

    prediction = None
    if idx == 0:
        prediction = 'No'
    elif idx == 1:
        prediction = 'Mild'
    elif idx == 2:
        prediction = 'Moderate'
    elif idx == 3:
        prediction = 'Severe'
    elif idx == 4:
        prediction = 'Fatal'
    
    return HttpResponse(prediction)
