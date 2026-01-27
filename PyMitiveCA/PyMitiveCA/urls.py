"""
URL configuration for PyMitiveCA project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),

    path('issue_cert/', views.issue_cert, name='issue_cert'),
    path('generate_cert/', views.generate_cert, name='generate_cert'),
    path('generate_csr/', views.generate_csr, name='generate_csr'),

    path('get_cert/', views.get_cert, name='get_cert'),
    path('get_csr/', views.get_csr, name='get_csr'),
    path('get_crl/', views.get_crl, name='get_crl'),

    path('revoke/', views.revoke_cert, name='revoke'),
]
