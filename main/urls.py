from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import (
    RegisterView, SendOTPView, VerifyOTPView, LoginView, CustomUserCreateView,
    ActivityCreateView, ActivityListView,
    ActivityImageListCreateView, ChatRoomCreateView, ChatRoomRetrieveView,
    ChatMessageCreateView, ChatMessageListView, ChatRequestCreateView,
    ChatRequestRetrieveView, AcceptChatRequestView,
    VendorKYCListCreateView, VendorKYCDetailView, 
    BusinessDocumentListCreateView, BusinessPhotoListCreateView, CreateDealView, DealImageUploadView, CreateDealListView,
    VendorDetailListView, VendorListView, ActivityListView, LogoutView
)

urlpatterns = [
    # User Registration (No Authentication Required)
    path('register/', RegisterView.as_view(), name='register'),
    
    # OTP Verification (No Authentication Required)
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),

    # Login (No Authentication Required)
    path('login/', LoginView.as_view(), name='login'),
    
    # Custom User Creation (Requires Authentication)
    path('custom-user/create/', CustomUserCreateView.as_view(), name='custom-user-create'),

    # Activities (Requires Authentication)
    path('activities/create/', ActivityCreateView.as_view(), name='activity-create'),
    path('activities/<uuid:pk>/', ActivityListView.as_view(), name='activity-details'),
    # path('activities/<uuid:pk>/', ActivityRetrieveUpdateDestroyView.as_view(), name='activity-detail'),

    # Activity Images (Requires Authentication)
    path('activity-images/', ActivityImageListCreateView.as_view(), name='activity-image-create'),

    # Chat Rooms (Requires Authentication)
    path('chat-rooms/', ChatRoomCreateView.as_view(), name='chat-room-create'),
    path('chat-rooms/<uuid:pk>/', ChatRoomRetrieveView.as_view(), name='chat-room-detail'),

    # Chat Messages (Requires Authentication)
    path('chat-messages/', ChatMessageCreateView.as_view(), name='chat-message-create'),
    path('chat-messages/<uuid:chat_room_id>/', ChatMessageListView.as_view(), name='chat-message-list'),

    # Chat Requests (Requires Authentication)
    path('chat-requests/', ChatRequestCreateView.as_view(), name='chat-request-create'),
    path('chat-requests/<uuid:pk>/', ChatRequestRetrieveView.as_view(), name='chat-request-detail'),
    path('chat-requests/<uuid:pk>/accept/', AcceptChatRequestView.as_view(), name='accept-chat-request'),

    # Vendor KYC (Requires Authentication)
    path('vendor-kyc/create/', VendorKYCListCreateView.as_view(), name='vendor-kyc-list-create'),
    #path('vendor-kyc/<uuid:pk>/', VendorKYCDetailView.as_view(), name='vendor-kyc-detail'),

    # Business Document endpoints (Requires Authentication)
    path('vendor-kyc/documents/', BusinessDocumentListCreateView.as_view(), name='business-document-list-create'),

    # Business Photo endpoints (Requires Authentication)
    path('vendor-kyc/photos/', BusinessPhotoListCreateView.as_view(), name='business-photo-list-create'),
    
    # Deals (Requires Authentication)
    path('deals/create/', CreateDealView.as_view(), name='create-deal'),
    path('deals/', CreateDealListView.as_view(), name='list-deals'),
    path('deals/<int:deal_id>/upload-images/', DealImageUploadView.as_view(), name='upload-deal-images'),
    
    path('vendors/details/<uuid:pk>/', VendorDetailListView.as_view(), name='vendor-details'),
    
    path('vendors/list/', VendorListView.as_view(), name='vendor-list'),
    
    path('activities/list/', ActivityListView.as_view(), name='activity-list'),
    
    path('logout/', LogoutView.as_view(), name='logout'),
    
    # Forgot Password
    path('send-otp/', SendOTPView.as_view(), name='send-otp'),
    # path('validate-otp/', ValidateOTPView.as_view(), name='validate-otp'),
    # path('reset-password-otp/', OTPResetPasswordView.as_view(), name='reset-password-otp'),
    
    # JWT Authentication
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
