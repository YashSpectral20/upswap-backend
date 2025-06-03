from django.urls import path

from .views import (
    ProviderAPIView,
    GetProvidersView
)

urlpatterns = [
    path('get-providers/', ProviderAPIView.as_view(), name='get-providers'),
    path('create-provider/', ProviderAPIView.as_view(), name='create-provider'),
    path('get-all-providers/', GetProvidersView.as_view(), name='get-all-providers'),
]