from .models import BlacklistedAccessToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed

class AccessTokenBlacklistMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        auth = JWTAuthentication()
        try:
            token = auth.get_validated_token(auth.get_raw_token(request))
            if BlacklistedAccessToken.objects.filter(token=str(token)).exists():
                raise AuthenticationFailed("Access token has been blacklisted")
        except AuthenticationFailed:
            pass  # Token might be invalid or expired, handled by other middleware
        
        response = self.get_response(request)
        return response
