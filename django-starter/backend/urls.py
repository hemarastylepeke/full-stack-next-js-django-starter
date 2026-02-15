from django.urls import path, include
from django.contrib import admin
from .api import api

urlpatterns = [
    path("api/", api.urls),
    path('admin/', admin.site.urls),
    path('api/auth/', include('djoser.urls')),
]
