from django.db import models
from main.models import CustomUser

class ActivityLog(models.Model):
    SIGN_UP = 'sign_up'
    LOGIN = 'login'
    LOGOUT = 'logout'
    EDIT_PROFILE = 'edit_profile'
    PLACE_ORDER = 'place_order'
    RESET_PASSWORD = 'reset_password'
    VERIFY_OTP = 'verify_otp'
    FAVORITE_VENDOR = 'favorite_vendor'
    UNFAVORITE_VENDOR = 'unfavorite_vendor'
    RATE_VENDOR = 'rate_vendor'
    RAISE_ISSUE = 'raise_issue'
    CREATE_ACTIVITY = 'create_activity'
    DEACTIVATE_ACTIVITY = 'deactivate_activity'
    REPOST_ACTIVITY = 'repost_activity'
    SHOW_INTEREST_IN_ACTIVITY = 'show_interest_in_activity'
    CHAT_REQUEST = 'chat_request'
    ACCEPT_CHAT_REQ = 'accept_chat_req'
    REJET_CHAT_REQ = 'rejet_chat_req'
    APPLY_KYC = 'apply_kyc'
    UPLOAD_DEAL = 'upload_deal'
    END_DEAL = 'end_deal'
    CREATE_DEAL = 'create_deal'
    EDIT_DEAL = 'edit_deal'
    DEACTIVATE_DEAL = 'deactivate_deal'
    REPOST_DEAL = 'repost_deal'
    KYC_APPROVED = 'kyc_approved'
    NOTIFICATION_FIRED_FOR_EVENT = 'notification_fired_for_event'

    event_choices = [
        # users
        (SIGN_UP, 'sign_up'),
        (LOGIN, 'login'),
        (LOGOUT, 'logout'),
        (EDIT_PROFILE, 'edit_profile'),
        (PLACE_ORDER, 'place_order'),
        (RESET_PASSWORD, 'reset_password'),
        (VERIFY_OTP, 'verify_otp'),
        (FAVORITE_VENDOR, 'favorite_vendor'),
        (UNFAVORITE_VENDOR, 'unfavorite_vendor'),
        (RATE_VENDOR, 'rate_vendor'),
        (RAISE_ISSUE, 'raise_issue'),
        # activity
        (CREATE_ACTIVITY, 'create_activity'),
        (DEACTIVATE_ACTIVITY, 'deactivate_activity'),
        (REPOST_ACTIVITY, 'repost_activity'),
        (SHOW_INTEREST_IN_ACTIVITY, 'show_interest_in_activity'),
        # chat
        (CHAT_REQUEST, 'chat_request'),
        (ACCEPT_CHAT_REQ, 'accept_chat_req'),
        (REJET_CHAT_REQ, 'rejet_chat_req'),
        # vendor
        (APPLY_KYC, 'apply_kyc'),
        (UPLOAD_DEAL, 'upload_deal'),
        (END_DEAL, 'end_deal'),
        (CREATE_DEAL, 'create_deal'),
        (EDIT_DEAL, 'edit_deal'),
        (REPOST_DEAL, 'repost_deal'),
        (DEACTIVATE_DEAL, 'deactivate_deal'),
        (KYC_APPROVED, 'kyc_approved'),
        (NOTIFICATION_FIRED_FOR_EVENT, 'notification_fired_for_event')
    ]
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='activity_logs')
    event = models.CharField(max_length=255, choices=event_choices)
    metadata = models.JSONField(default=dict, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)