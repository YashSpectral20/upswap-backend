# """
# URL configuration for upswap project.

# The `urlpatterns` list routes URLs to views. For more information please see:
#     https://docs.djangoproject.com/en/5.0/topics/http/urls/
# Examples:
# Function views
#     1. Add an import:  from my_app import views
#     2. Add a URL to urlpatterns:  path('', views.home, name='home')
# Class-based views
#     1. Add an import:  from other_app.views import Home
#     2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
# Including another URLconf
#     1. Import the include() function: from django.urls import include, path
#     2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
# """
# from django.contrib import admin
# from django.urls import path, include
# from django.conf import settings
# from django.conf.urls.static import static

# urlpatterns = [
#     path('api/', include('main.urls')),
#     path('admin/', admin.site.urls),
# ] 

# if settings.DEBUG:
#     urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


#######################################################################################################################

"""
URL configuration for main project.

The `urlpatterns` list routes URLs to views. For more information, see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views:
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views:
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf:
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions
from django.http import JsonResponse

# Fallback view for undefined routes
def not_found(request, *args, **kwargs):
    return JsonResponse({'error': 'Endpoint not found'}, status=404)

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
    # Admin Site
    path('admin/', admin.site.urls),

    # Include app URLs
    path('api/', include('main.urls')),
    path('api/chat/', include('upswap_chat.urls')),
    path('api/appointments/', include('appointments.urls')),

    # Swagger Endpoints
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('swagger.json', schema_view.without_ui(cache_timeout=0), name='schema-json'),
]

# Serve Media Files in Debug Mode
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Custom 404 Handler
handler404 = 'upswap.urls.not_found'
