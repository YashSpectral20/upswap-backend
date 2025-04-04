from firebase_admin import messaging
from .models import Device

def send_notification_to_user(user, title, body, data=None):
    device_tokens = Device.objects.filter(user=user).values_list('device_token', flat=True)

    if not device_tokens:
        print(f"No devices registered for user {user.email}")
        return

    message = messaging.MulticastMessage(
        notification=messaging.Notification(
            title=title,
            body=body,
        ),
        data={key: str(value) for key, value in (data or {}).items()},
        tokens=list(device_tokens),
    )

    response = messaging.send_multicast(message)
    print(f"Successfully sent {response.success_count} messages. Failed: {response.failure_count}")