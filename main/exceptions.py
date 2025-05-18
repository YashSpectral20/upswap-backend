from rest_framework.exceptions import APIException

class PhoneNumberNotVerified(APIException):
    status_code = 418
    default_detail = "This phone number is not verified via OTP."
    default_code = "phone_number_not_verified"
    
    def __init__(self, detail=None, code=None):
        self.detail = {"message": detail or self.default_detail}
