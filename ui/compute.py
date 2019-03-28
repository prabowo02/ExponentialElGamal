import os
import subprocess
import time

from django.http import HttpResponse

from .models import PublicKeys
from ConditionalGate import ConditionalGate
from CryptoLibrary import encrypt_binary
from CryptoLibrary import secure_add
from CryptoLibrary import secure_xor
from CryptoLibrary import secure_comparison
from CryptoLibrary import secure_inequality
from CryptoLibrary import secure_multiply
from CryptoLibrary import set_encryption_scheme
from ExponentialElGamal import CipherText


COMPUTATION_DIR = os.path.join('ui', 'compute')


def setup_encryption_scheme():
    public_keys_object = PublicKeys.objects.get()
    p = int(public_keys_object.prime)
    g = int(public_keys_object.generator)
    h = int(public_keys_object.public_key)
    
    set_encryption_scheme(
        ConditionalGate(3, p, g, h)
    )

    return p, g, h


def str_to_cipher(p, s):
    s = s.split(';')
    return [CipherText(p, int(s[i]), int(s[i+1])) for i in range(0, len(s), 2)]
    
    
def cipher_to_str(c):
    return ';'.join([str(cipher.c1) + ';' + str(cipher.c2) for cipher in c])


def get_secret_key():
    secret_keys = PublicKeys.objects.get().secret_keys
    return [int(sk) for sk in secret_keys.split(';')]

# 12191544068129812483;2837090849165181589;7646666471503822361;14139586618188822328;11947664888451507162;10065335398846561640
# 4588414401898764265;13651019617639839506;8639088365596071039;778386991029696328;848990670881613806;9992031814703530376
def clean_data(fn):
    def clean_data_wrapped(request):
        p, _, _ = setup_encryption_scheme()
        sk = get_secret_key()
        
        x = request.GET['c1']
        y = request.GET['c2']
        
        return HttpResponse(fn(x, y, sk))
        
    return clean_data_wrapped


@clean_data
def add(x, y, sk):
    process = subprocess.Popen([os.path.join(COMPUTATION_DIR, 'add.exe'), x, y], stdout=subprocess.PIPE)
    output, error = process.communicate()
    return output

    # return secure_add(x, y, sk)
    

@clean_data
def xor(x, y, sk):
    return secure_xor(x, y, sk)

    
@clean_data
def comparison(x, y, sk):
    return secure_comparison(x, y, sk)

    
@clean_data
def inequality(x, y, sk):
    return secure_inequality(x, y, sk)


@clean_data
def multiply(x, y, sk):
    return secure_multiply(x, y, sk)
