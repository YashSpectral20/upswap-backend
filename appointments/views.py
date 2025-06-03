import json
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated, AllowAny

from main.utils import upload_to_s3
from .serializers import ProviderSerializer
from .models import Provider

from main.models import VendorKYC

class ProviderAPIView(APIView):
    """
    Get() ---> Retreive all Providers for the vendor.
    Post() ---> Create a new Provider.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        try:
            user = request.user
            vendor = VendorKYC.objects.filter(user=user).first()
            if not vendor:
                return Response({
                    'message': 'You must be a vendor to view providers.',
                    'data': {}
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            providers = vendor.providers.all()
            if providers:
                serializer = ProviderSerializer(providers, many=True)
                return Response({
                    'message': 'Providers found for the vendor.',
                    'data': serializer.data
                }, status=status.HTTP_200_OK)
            
            return Response({
                    'message': 'Providers not found.',
                    'data': {}
                }, status=status.HTTP_204_NO_CONTENT)
        
        except Exception as e:
            return Response({
                'message': 'An error occurred while retrieving providers.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request, format=None):
        user = request.user
        vendor = VendorKYC.objects.filter(user=user).first()

        if not vendor:
            return Response({
                'message': 'You must be a vendor to add a provider.',
                'data': {}
            }, status=status.HTTP_401_UNAUTHORIZED)

        profile_photo = request.FILES.get('profilePhoto')
        data = request.data.copy()

        # Parse and remove 'services' from data
        try:
            services = json.loads(data.get('services', '[]'))
        except json.JSONDecodeError:
            return Response({
                'message': 'Invalid format for services.',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)
        data.pop('services', None)

        serializer = ProviderSerializer(data=data)
        if not serializer.is_valid():
            return Response({
                'message': 'Failed to add provider.',
                'error': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        # Upload profile photo if provided
        profile_photo_url = None
        if profile_photo:
            profile_photo_url = upload_to_s3(
                profile_photo,
                f'profile-pictures/{vendor.vendor_id}',
                profile_photo.name
            )

        provider_instance = serializer.save(
            vendor=vendor,
            profile_photo=[profile_photo_url] if profile_photo_url else []
        )

        # Add services if provided
        if services:
            provider_instance.services.set(services)

        return Response({
            'message': 'Provider added successfully.',
            'data': ProviderSerializer(provider_instance).data
        }, status=status.HTTP_201_CREATED)


class GetProvidersView(generics.ListAPIView):
    queryset = Provider.objects.all()
    serializer_class = ProviderSerializer
    permission_classes = [AllowAny]