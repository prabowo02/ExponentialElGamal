from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponse
from django.shortcuts import render

from .models import PublicKeys
from .models import Coefficients
from .predict import PRECISION
from ConditionalGate import ConditionalGate
from CryptoLibrary import set_encryption_scheme
from CryptoLibrary import encrypt_binary
from KeyGenerator import generate_distributed_exponential_elgamal_keys

PRIME_LENGTH = 42


def index(request):
    return render(request, 'ui\\predict.html')
    
    
def get_coefficients():
    return (
        [-436978, -679683, -744310, -995461, 2047171, 121125],
        [41110, 299842, 140080, 318122, -334943, -811526],
        [329596, 111966, -177, 517609, -741119, -755609],
        [-226711, 173959, 351773, 138003, -1012674, -309475],
        [189192, 65683, 221353, -35101, -121302, -1053553],
    )

    
def generate_keys(request):
    if request.method == 'POST':
        PublicKeys.objects.all().delete()
        
        p, g, h, sk = generate_distributed_exponential_elgamal_keys(3, PRIME_LENGTH)
        public_key = PublicKeys(
            public_key=str(h),
            prime=str(p),
            generator=str(g),
            secret_keys=';'.join([str(k) for k in sk]),
        )
        
        public_key.save()
        
        Coefficients.objects.all().delete()
        set_encryption_scheme(ConditionalGate(3, p, g, h))
        
        coefficient_attrs = dict()
        for attr_name, coeffs in zip(['c1', 'c2', 'c3', 'c4', 'c5'], get_coefficients()):
            ciphers = []
            for c in coeffs:
                print(c)
                for cipher in encrypt_binary(c, PRECISION):
                    ciphers.append(str(cipher.c1))
                    ciphers.append(str(cipher.c2))
                
            coefficient_attrs[attr_name] = ';'.join(ciphers)
        
        Coefficients(**coefficient_attrs).save()
    
        return render(request, 'ui\\generate_keys.html', {
            'public_key': public_key,
            'private_key': ';'.join([str(k) for k in sk]),
        })
        
    try:
        public_key = PublicKeys.objects.get()
    except ObjectDoesNotExist:
        public_key = None
        
    return render(request, 'ui\\generate_keys.html', {
        'public_key': public_key,
    })

    
def compute(request):
    return render(request, 'ui\\compute.html')