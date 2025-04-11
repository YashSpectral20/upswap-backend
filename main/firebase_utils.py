from firebase_admin import messaging
from .models import Device


def send_single_fcm_message(registration_token, title, body, data=None):
    message = messaging.Message(
        notification=messaging.Notification(
            title=title,
            body=body,
        ),
        data={key: str(value) for key, value in (data or {}).items()},
        token=registration_token,
    )

    try:
        response = messaging.send(message)
        print(f"✅ Successfully sent message to single device: {response}")
        return response
    except Exception as e:
        print(f"❌ Error sending message to single device: {e}")
        return None


def send_multicast_fcm_message(registration_tokens, title, body, data=None):
    success_count = 0
    failure_count = 0

    for idx, token in enumerate(registration_tokens):
        message = messaging.Message(
            notification=messaging.Notification(
                title=title,
                body=body,
            ),
            data={key: str(value) for key, value in (data or {}).items()},
            token=token,
        )

        try:
            response = messaging.send(message)
            print(f"✅ [{idx}] Sent to {token}: {response}")
            success_count += 1
        except Exception as e:
            print(f"❌ [{idx}] Failed to send to {token}: {e}")
            failure_count += 1

    print(f"✅ {success_count} messages were sent successfully.")
    print(f"❌ {failure_count} messages failed.")
    return {"success": success_count, "failure": failure_count}


def send_notification_to_user(user, title, body, data=None):
    device_tokens = Device.objects.filter(user=user).values_list('device_token', flat=True)

    if not device_tokens:
        print(f"⚠️ No devices registered for user {user.email}")
        return

    if len(device_tokens) == 1:
        return send_single_fcm_message(device_tokens[0], title, body, data)
    else:
        return send_multicast_fcm_message(list(device_tokens), title, body, data)
