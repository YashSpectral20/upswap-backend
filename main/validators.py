import re
from django.core.exceptions import ValidationError

PASSWORD_REGEX = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$'

def validate_password_strength(value):
    if not re.match(PASSWORD_REGEX, value):
        raise ValidationError("Password must contain at least 8 characters, one uppercase, one lowercase, one digit, and one special character.")
