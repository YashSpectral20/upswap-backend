# from django.conf import settings
# from django.conf.urls.static import static
# from django.urls import path
# from rest_framework_simplejwt.views import (
#     TokenObtainPairView,
#     TokenRefreshView,
# )
# from .views import (
#     RegisterView, VerifyOTPView, LoginView, CustomUserCreateView,
#     ActivityCreateView,
#     ActivityImageListCreateView, ChatRoomCreateView, ChatRoomRetrieveView,
#     ChatMessageCreateView, ChatMessageListView, ChatRequestCreateView,
#     ChatRequestRetrieveView, AcceptChatRequestView,
#     VendorKYCCreateView, VendorKYCDetailView, 
#     BusinessDocumentListCreateView, BusinessPhotoListCreateView, CreateDealView, DealImageUploadView, CreateDealDetailView, CreateDeallistView, 
#     VendorKYCListView, ActivityListsView, LogoutAPI, ForgotPasswordView, ResetPasswordView, PlaceOrderView, PlaceOrderDetailsView, CategoriesView,
#     CustomUserDetailView, PlaceOrderListsView, ActivityImagesListView, download_s3_file
# )

# urlpatterns = [
#     # User Registration (No Authentication Required)
#     path('register/', RegisterView.as_view(), name='register'),
    
#     # OTP Verification (No Authentication Required)
#     path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),

#     # Login (No Authentication Required)
#     path('login/', LoginView.as_view(), name='login'),
    
#     # Custom User Creation (Requires Authentication)
#     path('custom-user/create/', CustomUserCreateView.as_view(), name='custom-user-create'),

#     # Activities (Requires Authentication)
#     path('activities/create/', ActivityCreateView.as_view(), name='activity-create'),
#     #path('activities/<uuid:pk>/', ActivityListView.as_view(), name='activity-details'),
#     # path('activities/<uuid:pk>/', ActivityRetrieveUpdateDestroyView.as_view(), name='activity-detail'),

#     # Activity Images (Requires Authentication)
#     path('activities/<uuid:activity_id>/images/', ActivityImageListCreateView.as_view(), name='activity-image-list-create'),
    
#     path('activities/lists/<uuid:activity_id>/images/', ActivityImagesListView.as_view(), name='activity-images-list'),

#     # Chat Rooms (Requires Authentication)
#     path('chat-rooms/', ChatRoomCreateView.as_view(), name='chat-room-create'),
#     path('chat-rooms/<uuid:pk>/', ChatRoomRetrieveView.as_view(), name='chat-room-detail'),

#     # Chat Messages (Requires Authentication)
#     path('chat-messages/', ChatMessageCreateView.as_view(), name='chat-message-create'),
#     path('chat-messages/<uuid:chat_room_id>/', ChatMessageListView.as_view(), name='chat-message-list'),

#     # Chat Requests (Requires Authentication)
#     path('chat-requests/', ChatRequestCreateView.as_view(), name='chat-request-create'),
#     path('chat-requests/<uuid:pk>/', ChatRequestRetrieveView.as_view(), name='chat-request-detail'),
#     path('chat-requests/<uuid:pk>/accept/', AcceptChatRequestView.as_view(), name='accept-chat-request'),

#     # Vendor KYC (Requires Authentication)
#     path('vendor-kyc/create/', VendorKYCCreateView.as_view(), name='vendor-kyc-list-create'),
    
#     path('vendor/lists/', VendorKYCListView.as_view(), name='vendor-kyc-list'),
    
#     path('vendorKYC/details/<uuid:vendor_id>/', VendorKYCDetailView.as_view(), name='vendorKYC-details'),
    
#     #path('vendor-kyc/<uuid:pk>/', VendorKYCDetailView.as_view(), name='vendor-kyc-detail'),

#     # Business Document endpoints (Requires Authentication)
#     path('vendor-kyc/documents/', BusinessDocumentListCreateView.as_view(), name='business-document-list-create'),

#     # Business Photo endpoints (Requires Authentication)
#     path('vendor-kyc/photos/', BusinessPhotoListCreateView.as_view(), name='business-photo-list-create'),
    
#     # Deals (Requires Authentication)
#     path('deals/create/', CreateDealView.as_view(), name='create-deal'),
#     path('deals/details/<uuid:deal_uuid>/', CreateDealDetailView.as_view(), name='details-deals'),
#     path('deals/lists/', CreateDeallistView.as_view(), name='list-deals'),
#     path('deals/images/upload/', DealImageUploadView.as_view(), name='deal-image-upload'),
#     path('download/<str:file_key>/', download_s3_file, name='download_s3_file'),
    
#     path('activities/list/', ActivityListsView.as_view(), name='activity-list'),
    
#     path('logout/', LogoutAPI.as_view(), name='logout'),
    
#     path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
#     path('password-reset-confirm/<uidb64>/<token>/', ResetPasswordView.as_view(), name='password-reset-confirm'),
    
#     #PlaceOrder
#     path('place-order/', PlaceOrderView.as_view(), name='place-order'),
#     path('place-order/details/<uuid:order_id>/', PlaceOrderDetailsView.as_view(), name='place-order-details'),
#     path('place-order/lists/', PlaceOrderListsView.as_view(), name='place-order-lists'),
    
#     path('categories/', CategoriesView.as_view(), name='categories'),
    
#     path('customuser/details/<uuid:id>/', CustomUserDetailView.as_view(), name='customuser-details'),
    
#     # JWT Authentication
#     path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
#     path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
# ]

# if settings.DEBUG:
#     urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


###############################################################################################################################

from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions
from .views import (    
    OTPResetPasswordView, 
    RegisterView, SendOTPView, ValidateOTPView, VerifyOTPView, LoginView, CustomUserCreateView,
    ActivityCreateView,
    VendorKYCCreateView, VendorKYCDetailView, 
    CreateDealView, CreateDealDetailView, CreateDeallistView, 
    VendorKYCListView, ActivityListsView, ActivityDetailsView, LogoutAPI, ForgotPasswordView, ResetPasswordView, PlaceOrderView, PlaceOrderDetailsView, CategoriesView,
    CustomUserDetailView, PlaceOrderListsView, UploadImagesAPI, UploadDocumentsAPI, UploadProfileImageAPI, VendorKYCStatusView, CustomUserEditView, SocialLogin, MyDealView,
    SuperadminLoginView, FavoriteVendorView, FavoriteVendorsListView, MyActivityView, SubmitRatingView, RaiseAnIssueMyOrdersView, RaiseAnIssueVendorsCreateView,
    RaiseAnIssueCustomUserView, DeactivateDealView, RepostDealView, DeactivateActivitiesView, ActivityRepostView, MySalesAPIView, ViewTotalSales,
    ResendOTPView, NotificationListView, MarkNotificationAsReadView, RegisterDeviceView, VendorAddressListView, SendVendorWhatsAppMessage, CreateDealHackathonView, CheckVendorStatusView, SendPhoneVerificationOTP, 
    GetAllVendors, GetVendorServiceAndProviders,
    VerifyOTPNewPhoneNumberView, ServicesCreateView, test_push_notification,
    SendVerificationOTP, VerifyOTPViewV2, UpdatePasswordAPI, DealDeleteView, ActivityDeleteView,
    SendOTPToEmail, VerifyOTPForPassword, SetPasswordAPI,ConfirmRejectActivityPartcipation, VerifyOTPAPIViewV2, RegisterAPIViewV2,
    RegisterResendOTP, RegisterAPIViewV3, VerifyOTPAPIViewV3, CreateUserInDB, LoginWithOTP, LoginAPIViewV2, LoginResendOTP, RemoveActivityParticipantView, LogoutAPIV2, FavoriteUnfavoriteUserAPI
)

# Swagger Schema View
schema_view = get_schema_view(
    openapi.Info(
        title="UpSwap API",
        default_version="v1",
        description="API documentation for your project",
        terms_of_service="https://upswap.app/privacy-policy/",
        contact=openapi.Contact(email="contact@upswap.app"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    # Swagger Documentation
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),

    # User Registration (No Authentication Required)
    path('register/', RegisterView.as_view(), name='register'),
    
    # OTP Verification (No Authentication Required)
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),

    # Login (No Authentication Required)
    path('login/', LoginView.as_view(), name='login'),
    
    #SocialLogin API()
    path('social-login/', SocialLogin.as_view(), name='social_login'),
    
    # Custom User Creation (Requires Authentication)
    path('custom-user/create/', CustomUserCreateView.as_view(), name='custom-user-create'),

    # Activities (Requires Authentication)
    path('activities/create/', ActivityCreateView.as_view(), name='activity-create'),

    # Chat Rooms (Requires Authentication)
    # path('chat-rooms/', ChatRoomCreateView.as_view(), name='chat-room-create'),
    # path('chat-rooms/<uuid:pk>/', ChatRoomRetrieveView.as_view(), name='chat-room-detail'),

    # # Chat Messages (Requires Authentication)
    # path('chat-messages/', ChatMessageCreateView.as_view(), name='chat-message-create'),
    # path('chat-messages/<uuid:chat_room_id>/', ChatMessageListView.as_view(), name='chat-message-list'),

    # # Chat Requests (Requires Authentication)
    # path('chat-requests/', ChatRequestCreateView.as_view(), name='chat-request-create'),
    # path('chat-requests/<uuid:pk>/', ChatRequestRetrieveView.as_view(), name='chat-request-detail'),
    # path('chat-requests/<uuid:pk>/accept/', AcceptChatRequestView.as_view(), name='accept-chat-request'),

    # Vendor KYC (Requires Authentication)
    path('vendor-kyc/create/', VendorKYCCreateView.as_view(), name='vendor-kyc-list-create'),
    path('vendor/lists/', VendorKYCListView.as_view(), name='vendor-kyc-list'),
    path('vendor/details/<uuid:vendor_id>/', VendorKYCDetailView.as_view(), name='vendorKYC-details'),
    path('vendor/status/<str:vendor_id>/', VendorKYCStatusView.as_view(), name='vendor-status'),
    path('get-all-vendors/', GetAllVendors.as_view(), name='get-all-vendors'),
    path('get-vendor-service-and-providers/<uuid:vendor_id>/', GetVendorServiceAndProviders.as_view(), name='get-vendor-service-and-providers'),
    
    # Deals (Requires Authentication)
    path('deals/create/', CreateDealView.as_view(), name='create-deal'),
    path('deals/details/<uuid:deal_uuid>/', CreateDealDetailView.as_view(), name='details-deals'),
    path('deals/lists/', CreateDeallistView.as_view(), name='list-deals'),
    
    path('activities/lists/', ActivityListsView.as_view(), name='activity-list'),
    
    path('activities/details/<uuid:activity_id>/', ActivityDetailsView.as_view(), name='details-activities'),
    
    path('logout/', LogoutAPI.as_view(), name='logout'),
    
    path('send-otp/', SendOTPView.as_view(), name='send-otp'),
    path('validate-otp/', ValidateOTPView.as_view(), name='validate-otp'),
    path('reset-password-otp/', OTPResetPasswordView.as_view(), name='reset-password-otp'), #
    
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('password-reset-confirm/<uidb64>/<token>/', ResetPasswordView.as_view(), name='password-reset-confirm'),
    
    # PlaceOrder
    path('place-order/', PlaceOrderView.as_view(), name='place-order'),
    path('place-order/details/<str:placeorder_id>/', PlaceOrderDetailsView.as_view(), name='place-order-details'),
    path('place-order/lists/', PlaceOrderListsView.as_view(), name='place-order-lists'),
    
    path('categories/', CategoriesView.as_view(), name='categories'),
    
    path('customuser/details/<uuid:id>/', CustomUserDetailView.as_view(), name='customuser-details'),
    path('custom-user/edit-profile/', CustomUserEditView.as_view(), name='edit-profile'),
    
    # path('notification/', NotificationView.as_view(), name='notifications'),
    
    path('UploadImagesAPI/', UploadImagesAPI.as_view(), name='upload-images'),
    
    path('UploadDocumentsAPI/', UploadDocumentsAPI.as_view(), name='upload-documents'),
    
    path('UploadProfileImageAPI/', UploadProfileImageAPI.as_view(), name='upload-profileimages'),
    
    path('my-deals/<uuid:vendor_id>/', MyDealView.as_view(), name='my_deals'),
    
    path('superadmin/login/', SuperadminLoginView.as_view(), name='superadmin-login'),
    
    path('vendors/<uuid:vendor_id>/favorite/', FavoriteVendorView.as_view(), name='favorite_vendor'),
    
    path('favorite-vendors/lists/', FavoriteVendorsListView.as_view(), name='favorite-vendors-list'),
    
    path('my-activities/', MyActivityView.as_view(), name='my_activities'),
    
    path('submit-rating/<str:placeorder_id>/', SubmitRatingView.as_view(), name='submit-rating'),
    
    path("place-order/<str:place_order_id>/raise-issue/", RaiseAnIssueMyOrdersView.as_view(), name="raise-issue"),
    
    path('raise-issue/vendors/<uuid:vendor_id>/', RaiseAnIssueVendorsCreateView.as_view(), name='raise-issue-vendors'),
    
    path("raise-issue/<uuid:against_user_id>/<uuid:activity_id>/", RaiseAnIssueCustomUserView.as_view(), name="raise-issue-custom-user"),
    
    path("deals/deactivate/<uuid:deal_uuid>/", DeactivateDealView.as_view(), name='deactivate-deal'),
    
    path('deals/repost/<uuid:deal_uuid>/', RepostDealView.as_view(), name='repost-deal'),
    
    path('activities/deactivate/<uuid:activity_id>/', DeactivateActivitiesView.as_view(), name='deactivate-activity'),
    
    path('activity/repost/<uuid:activity_id>/', ActivityRepostView.as_view(), name='activity-repost'),
    
    path('mysales/', MySalesAPIView.as_view(), name='my-sales'),
    
    path('view-total-sales/', ViewTotalSales.as_view(), name='view-total-sales'),
    
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    
    path('notifications/', NotificationListView.as_view(), name='notifications-list'),
    path('notifications/mark-as-read/<uuid:pk>/', MarkNotificationAsReadView.as_view(), name='mark-as-read'),
    path('register-device/', RegisterDeviceView.as_view(), name='register-device'),
    
    path('vendor/addresses/', VendorAddressListView.as_view(), name='vendor-address-list'),
    
    path('send-whatsapp/', SendVendorWhatsAppMessage.as_view(), name='send-whatsapp'),
    
    path('create-deal/hackathon/', CreateDealHackathonView.as_view(), name='create-deal-hackathon'),
    
    path('check-vendor/<uuid:user_id>/', CheckVendorStatusView.as_view(), name='check-vendor'),
    
    path('send-phone-verification-otp/', SendPhoneVerificationOTP.as_view(), name='send-phone-verification-otp'),
    
    path('verify-otp/update-phone-number/', VerifyOTPNewPhoneNumberView.as_view(), name='verify-otp'),
    
    path('vendor/<uuid:vendor_id>/services/create/', ServicesCreateView.as_view(), name='create-multiple-services'),
    
    #For Testing PUSH Notification
    path('test-notification/', test_push_notification),
    
    # JWT Authentication
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('send-verification-otp/', SendVerificationOTP.as_view(), name='send-verification-otp'),
    path('verify-otp/v2/', VerifyOTPViewV2.as_view(), name='verify-otp-v2'),
    path('update-password/v2/', UpdatePasswordAPI.as_view(), name='update-password-v2'),
    path('delete-activity/<uuid:activity_id>/', ActivityDeleteView.as_view(), name='delete-activity'),
    path('delete-deal/<uuid:deal_uuid>/', DealDeleteView.as_view(), name='delete-deal'),

    path('send/email/forgot-password/', SendOTPToEmail.as_view(), name='send-email-forgot-password'),
    path('verify/otp/forgot-password/', VerifyOTPForPassword.as_view(), name='verify-otp-forgot-password'),
    path('reset-password/v2/', SetPasswordAPI.as_view(), name='reset-password-v2'),
    # activity participation 
    path('activity/confirm-reject/participation/<uuid:activity_id>/', ConfirmRejectActivityPartcipation.as_view(), name='confirm-reject-activity-participation'),
    path('activity/remove/participant/<uuid:activity_id>/', RemoveActivityParticipantView.as_view(), name='remove-participant'), 
    path('register/v2/', RegisterAPIViewV2.as_view(), name='register-v2'),
    path('verify/create/v2/', VerifyOTPAPIViewV2.as_view(), name='verify-v2'),
    path('resend/register/otp/', RegisterResendOTP.as_view(), name='resend-register-otp'),

    path('register/v3/', RegisterAPIViewV3.as_view(), name='register-v3'),
    path('verify/register/otp/v3/', VerifyOTPAPIViewV3.as_view(), name='verify-register-otp-v3'),
    path('create-user/', CreateUserInDB.as_view(), name='create-user'),
    path('login/v2/', LoginAPIViewV2.as_view(), name='login-v2'),
    path('login-otp/', LoginWithOTP.as_view(), name='login-otp'),
    path('resend/login/otp/', LoginResendOTP.as_view(), name='resend-login-otp'),
    path('logout/v2/', LogoutAPIV2.as_view(), name='logout-v2'),

    # Favorite APIs (Same APIs can be used for Unfavoriting.)
    path('favorite/user/<uuid:fav_user_id>/', FavoriteUnfavoriteUserAPI.as_view(), name='favorite-user'), # can unfavorite also
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
