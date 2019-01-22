from django.db import models

class PublicKeys(models.Model):
    public_key = models.TextField()
    prime = models.TextField()
    generator = models.TextField()
    secret_keys = models.TextField()
    

# Every c_i is of the form enc_1;enc_2;...;enc_6
# Every enc_i if of the form b1;b2;...;b_p where p is precision
# Every b_i is of the form c1;c2
class Coefficients(models.Model):
    c1 = models.TextField()
    c2 = models.TextField()
    c3 = models.TextField()
    c4 = models.TextField()
    c5 = models.TextField()
