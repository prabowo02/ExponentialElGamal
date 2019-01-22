from django.urls import path

from . import views
from . import predict

app_name = 'ui'
urlpatterns = [
    path('', views.index, name='index'),
    path('generate/', views.generate_keys, name='generate_keys'),
    path('predict/', predict.predict)
]
