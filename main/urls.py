from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import (
    RegisterView, VerifyOTPView, LoginView, CustomUserCreateView,
    ActivityCreateView, ActivityListView,
    ActivityImageListCreateView, ChatRoomCreateView, ChatRoomRetrieveView,
    ChatMessageCreateView, ChatMessageListView, ChatRequestCreateView,
    ChatRequestRetrieveView, AcceptChatRequestView,
    VendorKYCCreateView, VendorKYCDetailView, 
    BusinessDocumentListCreateView, BusinessPhotoListCreateView, CreateDealView, DealImageUploadView, CreateDealDetailView, CreateDeallistView, 
    VendorKYCListView, ActivityListView, LogoutAPI, ForgotPasswordView, ResetPasswordView
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
    path('vendor-kyc/create/', VendorKYCCreateView.as_view(), name='vendor-kyc-list-create'),
    
    path('vendor-kyc/lists/', VendorKYCListView.as_view(), name='vendor-kyc-list-view'),
    
    path('vendorKYC/details/<uuid:uuid>/', VendorKYCDetailView.as_view(), name='vendorKYC-details'),
    
    #path('vendor-kyc/<uuid:pk>/', VendorKYCDetailView.as_view(), name='vendor-kyc-detail'),

    # Business Document endpoints (Requires Authentication)
    path('vendor-kyc/documents/', BusinessDocumentListCreateView.as_view(), name='business-document-list-create'),

    # Business Photo endpoints (Requires Authentication)
    path('vendor-kyc/photos/', BusinessPhotoListCreateView.as_view(), name='business-photo-list-create'),
    
    # Deals (Requires Authentication)
    path('deals/create/', CreateDealView.as_view(), name='create-deal'),
    path('deals/details/<uuid:deal_uuid>/', CreateDealDetailView.as_view(), name='details-deals'),
    path('deals/lists/', CreateDeallistView.as_view(), name='list-deals'),
    path('deals/upload-deal-image/<uuid:deal_uuid>/', DealImageUploadView.as_view(), name='upload-deal-image'),
    
    path('activities/list/', ActivityListView.as_view(), name='activity-list'),
    
    path('logout/', LogoutAPI.as_view(), name='logout'),
    
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('password-reset-confirm/<uidb64>/<token>/', ResetPasswordView.as_view(), name='password-reset-confirm'),
    
    # JWT Authentication
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)