import json

from datetime import datetime, timedelta
from django.db import IntegrityError

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated, AllowAny

from main.utils import upload_to_s3

from .utils.generate_slots import generate_timeslots
from .serializers import (
    ProviderSerializer,
    ServiceSerializer,
    ServiceCategorySerializer,
    TimeSlotSerializer,
    AppointmentSerializer
)
from .models import (
    Provider,
    Service,
    ServiceCategory,
    TimeSlot
)

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
            
            providers = vendor.vendor_providers.all()
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
        data['vendor'] = vendor.vendor_id

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
        message = 'Provider added successfully.'
        generated, err = generate_timeslots(provider_instance)
        if generated:
            message += ' Time slots generated successfully.'
        elif err:
            message += f" Failed to generate time slots: {err}"
        return Response({
            'message': message,
            'data': ProviderSerializer(provider_instance).data
        }, status=status.HTTP_201_CREATED)

    def put(self, request, pk, format=None):
        try:
            provider = Provider.objects.get(pk=pk)
            data = request.data.copy()
            profile_photo = request.FILES.get('profilePhoto')

            services = json.loads(data.get('services', '[]'))
            data.pop('services', None)
            if profile_photo:
                profile_photo_url = upload_to_s3(
                    profile_photo,
                    f'profile-pictures/{provider.vendor.vendor_id}',
                    profile_photo.name
                )
                profile_photo = [profile_photo_url]

            serializer = ProviderSerializer(provider, data=data, partial=True, context={'profile_photo': profile_photo})
            if serializer.is_valid():
                
                provider_instance = serializer.save()
                if services:
                    provider_instance.services.set(services)
                return Response({
                    'message': 'Provider updated successfully.',
                    'data': ProviderSerializer(provider_instance).data
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'message': 'Failed to update provider.',
                    'error': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
        except Provider.DoesNotExist:
            return Response({
                'message': 'Provider not found.',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'message': 'An error occurred while updating the provider.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, pk, format=None):
        try:
            provider = Provider.objects.get(pk=pk)
            provider.delete()
            return Response({
                'message': 'Provider deleted successfully.',
                'data': {}
            }, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({
                'message': 'Failed to delete provider.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetProvidersView(generics.ListAPIView):
    """
    Get All providers for Customer view
    """
    queryset = Provider.objects.all()
    serializer_class = ProviderSerializer
    permission_classes = [AllowAny]

class RetrieveProviderView(generics.RetrieveAPIView):
    """
    Get Particular Provider with ID (pk)
    """
    queryset = Provider.objects.all()
    serializer_class = ProviderSerializer
    permission_classes = [AllowAny]

class ServiceCategoryAPIView(APIView):
    """
    Get() ---> Retrieve all Service Categories for the vendor.
    Post() ---> Create a new Service Category.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        user = request.user
        vendor = VendorKYC.objects.filter(user=user).first()
        if not vendor:
            return Response({
                'message': 'You must be a vendor to view service categories.',
                'data': {}
            }, status=status.HTTP_401_UNAUTHORIZED)

        try:
            service_categories = vendor.ven_service_categories.all()
            serializer = ServiceCategorySerializer(service_categories, many=True)
            return Response({
                'message': 'Service Categories found for the vendor.',
                'data': serializer.data
            }, status=status.HTTP_200_OK if service_categories else status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({
                'message': 'Error while fetching Service Categories.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request, format=None):
        user = request.user
        vendor = VendorKYC.objects.filter(user=user).first()
        if not vendor:
            return Response({
                'message': 'You must be a vendor to add a service category.',
                'data': {}
            }, status=status.HTTP_401_UNAUTHORIZED)

        data = request.data.copy()
        try:
            service_category = data.get('service_category')
            if not service_category:
                return Response({
                    'message': 'Service category is required.',
                    'data': {}
                }, status=status.HTTP_400_BAD_REQUEST)
            serializer = ServiceCategorySerializer(data={'service_category': service_category, 'vendor': vendor.vendor_id})
            if serializer.is_valid():
                serializer.save()
            else:
                return Response({
                    'message': 'Failed to add Service Category.',
                    'error': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            return Response({
                'message': 'Service Category added successfully.',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({
                'message': 'Failed to add Service Category.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ServiceAPIVIew(APIView):
    """
    Get() ---> Retrieve all Servces for the vendor.
    Post() ---> Create a new Service.
    """

    def get(self, request, format=None):
        user = request.user
        vendor = VendorKYC.objects.filter(user=user).first()
        if not vendor:
            return Response({
                'message': 'You must be a vendor to add a service.',
                'data': {}
            }, status=status.HTTP_401_UNAUTHORIZED)
        try:
            services = vendor.ven_services.all()
            if services:
                serializer = ServiceSerializer(services, many=True)
                return Response({
                    'message': 'Services found for the vendor.',
                    'data': serializer.data
                }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'message': 'Error while fetching services.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def post(self, request, format=None):
        user = request.user
        vendor = VendorKYC.objects.filter(user=user).first()
        if not vendor:
            return Response({
                'message': 'You must be a vendor to add a service.',
                'data': {}
            }, status=status.HTTP_401_UNAUTHORIZED)

        data = request.data.copy()
        images = request.FILES.getlist('images')
        providers = data.pop('providers', [])
        data['vendor'] = vendor.vendor_id
        
        serializer = ServiceSerializer(data=data)
        if not serializer.is_valid():
            return Response({
                'message': 'Failed to add provider.',
                'error': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        if images:
            image_urls = []
            for image in images:
                image_url = upload_to_s3(
                    image,
                    f'service-images/{vendor.vendor_id}',
                    image.name
                )
                image_urls.append(image_url)
                serializer.validated_data['image'] = image_urls
        service_intance = serializer.save()
        provider_names = []
        if providers:
            for provider_id in providers:
                try:
                    provider = Provider.objects.get(id=provider_id)
                    service_intance.providers.add(provider)
                    provider_names.append(provider.name)
                except Provider.DoesNotExist:
                    return Response({
                        'message': f'Provider with ID {provider_id} does not exists.',
                        'data': {}
                    }, status=status.HTTP_404_NOT_FOUND)
        resp_data = serializer.data
        resp_data['providers'] = provider_names
        return Response({
            'message': 'Service added successfully.',
            'data': resp_data
        }, status=status.HTTP_201_CREATED)

    def put(self, request, pk, format=None):
        try:
            service = Service.objects.get(pk=pk)
            data = request.data.copy()
            images = request.FILES.getlist('images')
            providers = data.pop('providers', [])
            existing_images = request.data.getlist('existing_images', [])
            data['vendor'] = service.vendor.vendor_id
            image_urls = []
            if images:
                for image in images:
                    image_url = upload_to_s3(
                        image,
                        f'service-images/{service.vendor.vendor_id}',
                        image.name
                    )
                    image_urls.append(image_url)
            if existing_images:
                image_urls.extend(existing_images)

            serializer = ServiceSerializer(service, data=data, partial=True, context={'images': image_urls})
            if serializer.is_valid():
                service_instance = serializer.update(service, serializer.validated_data)
                if providers:
                    service_instance.providers.clear()
                    for provider_id in providers:
                        try:
                            provider = Provider.objects.get(id=provider_id)
                            service_instance.providers.add(provider)
                        except Provider.DoesNotExist:
                            return Response({
                                'message': f'Provider with ID {provider_id} does not exists.',
                                'data': {}
                            }, status=status.HTTP_404_NOT_FOUND)
                return Response({
                    'message': 'Service updated successfully.',
                    'data': serializer.data
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'message': 'Failed to update service.',
                    'error': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
        except Service.DoesNotExist:
            return Response({
                'message': 'Service not found.',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'message': 'An error occurred while updating the service.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, pk, format=None):
        try:
            service = Service.objects.get(pk=pk)
            service.delete()
            return Response({
                'message': 'Service deleted successfully.',
                'data': {}
            }, status=status.HTTP_204_NO_CONTENT)
        except Service.DoesNotExist:
            return Response({
                'message': 'Service not found.',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'message': 'Failed to delete service.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RetrieveServiceAPIView(generics.RetrieveAPIView):
    """
    Get particular Service with ID (pk)
    """
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [AllowAny]

class GetServicesView(generics.ListAPIView):
    """
    Get All services for Customer view
    """
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [AllowAny]

class TimeSlotAPIView(APIView):
    """
    Get() ---> Get time slots for a provider & service.
    Post() ---> Create time slots for the provider.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        try:
            provider_id = request.query_params.get('provider_id')
            for_date = request.query_params.get('for_date')
            if not provider_id or not for_date:
                return Response({
                    'message': 'Provider ID and date are required.',
                    'data': {}
                }, status=status.HTTP_400_BAD_REQUEST)
            # for_date =datetime.strptime(for_date, '%Y-%m-%d').date()
            timeslots = TimeSlot.objects.filter(provider_id=provider_id, date=for_date)
            if timeslots:
                serializer = TimeSlotSerializer(timeslots, many=True)
                return Response({
                    'message': 'Time slots found for the provider.',
                    'data': serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                    'message': 'Time slots not found for the provider.',
                    'data': []
                }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                    'message': 'Error occurred while fetching time slots.',
                    'error': str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request, service_id, format=None):
        try:
            data = request.data.copy()
            start_date = data.get('start_date')
            if not start_date:
                return Response({
                    'message': 'Start date and is required.',
                    'date': {}
                }, status=status.HTTP_400_BAD_REQUEST)
            generated, err = generate_timeslots(service_id, start_date)
            if generated:
                return Response({
                    'message': 'Time slots created successfully.',
                    'data': {}
                }, status=status.HTTP_201_CREATED)
            return Response({
                'message': 'Failed to create time slots.',
                'error': err
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'message': 'An error occurred while creating time slots.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AppointmentsAPIView(APIView):
    # provider, service, timeslot, notes, vendor, customer, created_at, updated_at, status
    """
    Post() ---> Book an Appointment 
    """
    
    def post(self, request, format=None):
        from django.db import connection
        connection.queries_log.clear()
        data = request.data.copy()
        data['customer'] = request.user.id
        
        try:
            provider = Provider.objects.get(id=data['provider'])
            timeslot = TimeSlot.objects.get(id=data['time_slot'])
            if not timeslot.is_available:
                return Response({
                    'message': 'This timeslot is not available, try a different time slot.',
                    'data': {}
                }, status=status.HTTP_200_OK)
            data['vendor'] = provider.vendor.vendor_id
        except Exception as e:
            return Response({
                'message': 'provider not found.',
                'error': str(e)
            }, status=status.HTTP_404_NOT_FOUND)
        serializer = AppointmentSerializer(data=data)
        if serializer.is_valid():
            timeslot.is_available = False
            serializer.save()
            timeslot.save()
            num_queries = len(connection.queries)
            print(num_queries)
            return Response({
                'message': 'Appointment has been booked successfully.',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            'message': 'Appointment cannot be booked.',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)