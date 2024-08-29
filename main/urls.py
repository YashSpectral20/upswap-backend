from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import (
    CustomUserCreateView, RegisterView, OTPVerifyView, LoginView,
    ActivityListCreateView, ActivityRetrieveUpdateDestroyView,
    ActivityImageUploadView, ChatRoomCreateView, ChatRoomRetrieveView,
    ChatMessageCreateView, ChatMessageListView, ChatRequestCreateView,
    ChatRequestRetrieveView, ChatRequestUpdateView, AcceptChatRequestView,
    VendorKYCCreateView, VendorKYCListView, VendorKYCDetailView, VendorKYCUpdateView, VendorKYCDeleteView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-otp/', OTPVerifyView.as_view(), name='verify-otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('custom-user/create/', CustomUserCreateView.as_view(), name='custom-user-create'),
    path('activities/', ActivityListCreateView.as_view(), name='activity-list-create'),
    path('activities/<uuid:pk>/', ActivityRetrieveUpdateDestroyView.as_view(), name='activity-detail'),
    path('activities/images/', ActivityImageUploadView.as_view(), name='activity-image-upload'),
    path('chat-rooms/', ChatRoomCreateView.as_view(), name='chat-room-create'),
    path('chat-rooms/<uuid:pk>/', ChatRoomRetrieveView.as_view(), name='chat-room-detail'),
    path('chat-messages/', ChatMessageCreateView.as_view(), name='chat-message-create'),
    path('chat-messages/<uuid:chat_room_id>/', ChatMessageListView.as_view(), name='chat-message-list'),
    path('chat-requests/', ChatRequestCreateView.as_view(), name='chat-request-create'),
    path('chat-requests/<uuid:pk>/', ChatRequestRetrieveView.as_view(), name='chat-request-detail'),
    path('chat-requests/<uuid:pk>/update/', ChatRequestUpdateView.as_view(), name='chat-request-update'),
    path('accept-chat-request/', AcceptChatRequestView.as_view(), name='accept-chat-request'),
    path('vendor-kyc/', VendorKYCListView.as_view(), name='vendor-kyc-list'),
    path('vendor-kyc/create/', VendorKYCCreateView.as_view(), name='vendor-kyc-create'),
    path('vendor-kyc/<uuid:pk>/', VendorKYCDetailView.as_view(), name='vendor-kyc-detail'),
    path('vendor-kyc/<uuid:pk>/update/', VendorKYCUpdateView.as_view(), name='vendor-kyc-update'),
    path('vendor-kyc/<uuid:pk>/delete/', VendorKYCDeleteView.as_view(), name='vendor-kyc-delete'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh')
]
