from django.urls import path

from .views import (
    ProviderAPIView,
    GetProvidersView,
    RetrieveProviderView,
    ServiceCategoryAPIView,
    ServiceAPIVIew,
    RetrieveServiceAPIView,
    GetServicesView,
    TimeSlotAPIView,
    AppointmentsAPIView,
)

urlpatterns = [
    # Provider URLs
    path('get-providers/', ProviderAPIView.as_view(), name='get-providers'),
    path('create-provider/', ProviderAPIView.as_view(), name='create-provider'),
    path('get-provider/<int:pk>/', RetrieveProviderView.as_view(), name='get-provider'),
    path('get-all-providers/', GetProvidersView.as_view(), name='get-all-providers'),
    path('delete-provider/<int:pk>/', ProviderAPIView.as_view(), name='delete-provider'),
    path('update-provider/<int:pk>/', ProviderAPIView.as_view(), name='update-provider'),

    # Service Category URLs
    path('get-service-categories/', ServiceCategoryAPIView.as_view(), name='get-service-categories'),
    path('create-service-category/', ServiceCategoryAPIView.as_view(), name='create-service-category'),

    # Service URLs
    path('create-service/', ServiceAPIVIew.as_view(), name='create-service'),
    path('get-services/', ServiceAPIVIew.as_view(), name='get-services'),
    path('update-service/<int:pk>/', ServiceAPIVIew.as_view(), name='update-service'),
    path('delete-service/<int:pk>/', ServiceAPIVIew.as_view(), name='delete-service'),
    path('get-service/<int:pk>/', RetrieveServiceAPIView.as_view(), name='get-service-by-id'),
    path('get-all-services/', GetServicesView.as_view(), name='get-all-services'),

    # Time slot URLs
    path('create-time-slot/<int:service_id>/', TimeSlotAPIView.as_view(), name='create-time-slot'),
    path('get-time-slots/', TimeSlotAPIView.as_view(), name='get-time-slots'),

    # Appointments URLs
    path('book-appointment/', AppointmentsAPIView.as_view(), name='book-appointment'),
]