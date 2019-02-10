from django.urls import path

from . import compute
from . import views
from . import predict

app_name = 'ui'
urlpatterns = [
    path('', views.index, name='index'),
    path('generate/', views.generate_keys, name='generate_keys'),
    path('compute/', views.compute, name='compute'),
    path('predict/', predict.predict),
    
    path('compute/add/', compute.add),
    path('compute/xor/', compute.xor),
    path('compute/comparison/', compute.comparison),
    path('compute/inequality/', compute.inequality),
    path('compute/multiply/', compute.multiply),
]
