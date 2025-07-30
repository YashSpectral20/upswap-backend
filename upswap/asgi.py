# import os
# from django.core.asgi import get_asgi_application
# from channels.routing import ProtocolTypeRouter, URLRouter
# from channels.security.websocket import AllowedHostsOriginValidator
# from channels.auth import AuthMiddlewareStack
# from upswap_chat import routing

# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'upswap.settings')

# application = ProtocolTypeRouter({
#     "http": get_asgi_application(),
#     "websocket": AllowedHostsOriginValidator(AuthMiddlewareStack(
#         URLRouter(
#             routing.websocket_urlpatterns
#         )
#     )),
# })


# upswap/asgi.py

import os
from django.core.asgi import get_asgi_application

# Set the environment variable for settings FIRST.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'upswap.settings')

# Initialize the Django ASGI application EARLY.
# This call is CRUCIAL as it runs django.setup() and loads the app registry.
django_asgi_app = get_asgi_application()

# Now that Django is initialized, it's safe to import other components.
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from channels.auth import AuthMiddlewareStack
from upswap_chat import routing

application = ProtocolTypeRouter({
    "http": django_asgi_app, # Use the application object we created earlier
    "websocket": AllowedHostsOriginValidator(
        AuthMiddlewareStack(
            URLRouter(
                routing.websocket_urlpatterns
            )
        )
    ),
})

# Add this in your Django startup file (like wsgi.py or asgi.py or a middleware)
from django.http.response import StreamingHttpResponse
import traceback

_original_init = StreamingHttpResponse.__init__

def debug_streaming_init(self, *args, **kwargs):
    print("\n=== StreamingHttpResponse Created ===")
    traceback.print_stack(limit=10)
    print("====================================\n")
    return _original_init(self, *args, **kwargs)

StreamingHttpResponse.__init__ = debug_streaming_init
