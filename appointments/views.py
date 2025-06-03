from rest_framework import APIView
from rest_framework.response import Response
from rest_framework import status

from main.utils import upload_to_s3
from .serializers import ProviderSerializer

class ProviderAPIView(APIView):
    """
    Get() ---> Retreive all Providers for the vendor.
    Post() ---> Create a new Provider.
    """

    def get(self, request, format=None):
        try:
            user = request.user
            if not user.vendor_kyc:
                return Response({
                    'message': 'You must be a vendor to view providers.',
                    'data': {}
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            providers = user.venor_kyc.providers.all()
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
        try:
            user = request.user
            profile_picture = request.FILES.get('profilePhoto')
            if not user.vendor_kyc:
                return Response({
                    'message': 'You must be a vendor to add a provider.',
                    'data': {}
                }, status=status.HTTP_401_UNAUTHORIZED)
            serializer = ProviderSerializer(data=request.data)
            if serializer.is_valid():
                if profile_picture:
                    # upload profile picture to s3
                    profile_picture_url = upload_to_s3(profile_picture, f'profile-pictures/{user.vendor_kyc.id}/', profile_picture.name)
                    serializer.save(vendor=user.vendor_kyc, profile_picture=[profile_picture_url])
                else:
                    serializer.save(vendor=user.vendor_kyc)
                return Response({
                    'message': 'Provider added successfully.',
                    'data': serializer.data
                }, status=status.HTTP_201_CREATED)
            
            return Response({
                'message': 'Failed to add provider.',
                'error': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            return Response({
                'message': 'An error occurred while adding the provider.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)