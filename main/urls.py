from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import RegisterView, LoginView, VerifyOTPView, ActivityListCreateView, ActivityRetrieveUpdateDestroyView, ActivityImageUploadView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('activities/', ActivityListCreateView.as_view(), name='activity-list-create'),
    path('activities/<uuid:pk>/', ActivityRetrieveUpdateDestroyView.as_view(), name='activity-detail'),
    path('activities/upload-image/', ActivityImageUploadView.as_view(), name='activity-image-upload'),

]
