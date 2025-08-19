import json
import math
from datetime import date, datetime, timedelta
from django.utils.timezone import make_aware
from django.db import IntegrityError, transaction
from django.utils.timezone import is_aware

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated, AllowAny

from main.utils import (
    upload_to_s3, 
    generate_asset_uuid, 
    process_image, 
    get_error_messages
)

from .utils.generate_slots import generate_timeslots, create_slots_for_provider_in_range
from .serializers import (
    ProviderSerializer,
    ServiceSerializer,
    ServiceCategorySerializer,
    TimeSlotSerializer,
    AppointmentSerializer,
    GetAppointmentSerializer
)
from .models import (
    Appointment,
    Provider,
    Service,
    ServiceCategory,
    TimeSlot
)

from main.models import VendorKYC

INITIAL_SLOT_GENERATION_DAYS = 30
SLOT_DURATION = 15

class GenerateProviderSlotsAPIView(APIView):
    """
    An API view to generate future timeslots for a specific provider.
    """
    def post(self, request, provider_id, format=None):
        try:
            provider = Provider.objects.get(pk=provider_id)
        except Provider.DoesNotExist:
            return Response({
                'error': 'Provider not found.'
            }, status=status.HTTP_404_NOT_FOUND)

        try:
            days_to_generate = int(request.data.get('days'))
            if days_to_generate <= 0:
                raise ValueError()
        except (ValueError, TypeError):
            return Response({
                'error': "Invalid input. Please provide a positive integer for 'days'."
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            latest_timeslot = TimeSlot.objects.filter(provider=provider).latest('date')
            # Check if slots already exist for more than 6 months from now.
            # We use 180 days as an approximation for 6 months.
            six_months_future_date = datetime.now().date() + timedelta(days=180)
            if latest_timeslot.date >= six_months_future_date:
                return Response({
                    'error': 'You already have 6 months worth of slots.'
                }, status=status.HTTP_400_BAD_REQUEST)
            start_date = latest_timeslot.date + timedelta(days=1)
        except TimeSlot.DoesNotExist:
            # If no timeslots exist, start from today
            start_date = datetime.now().date()

        end_date = start_date + timedelta(days=days_to_generate - 1)

        try:
            created_count, error_message = create_slots_for_provider_in_range(provider, start_date, end_date)
            if error_message:
                return Response({'error': error_message}, status=status.HTTP_400_BAD_REQUEST)
            
            if created_count > 0:
                return Response({
                    'message': f'{created_count} timeslots created successfully.',
                    'data': {
                        'provider_id': provider.id,
                        'start_date': start_date.strftime('%Y-%m-%d'),
                        'end_date': end_date.strftime('%Y-%m-%d')
                    }
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'message': 'No new timeslots were created. This may be because the days fall on non-working days.',
                    'data': []
                }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'message': 'An unexpected error occurred while creating time slots.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
        services = data.get('services')

        # Parse and remove 'services' from data
        try:
            if not isinstance(services, list):
                services = json.loads(data.get('services', '[]'))
        except json.JSONDecodeError:
            return Response({
                'error': 'Invalid format for services.',
            }, status=status.HTTP_400_BAD_REQUEST)
        data.pop('services', None)
        data['vendor'] = vendor.vendor_id
        try:
            with transaction.atomic():
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

                if services:
                    provider_instance.services.set(services)
                message = 'Provider added successfully.'
                start_date = datetime.now().date()
                end_date = start_date + timedelta(days=INITIAL_SLOT_GENERATION_DAYS - 1)
                
                created_count, err = create_slots_for_provider_in_range(provider_instance, start_date, end_date)
                
                if created_count > 0:
                    message += f' {created_count} time slots generated successfully for the next {INITIAL_SLOT_GENERATION_DAYS} days.'
                elif err:
                    message += f" Failed to generate time slots: {err}"
                else:
                     message += " No initial time slots were generated (check work hours)."

                return Response({
                    'message': message,
                    'data': ProviderSerializer(provider_instance).data
                }, status=status.HTTP_201_CREATED)
        except Exception as e:
            print(str(e))
            return Response({
                'info': str(e),
                'message': 'Something went wrong while adding provider.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk, format=None):
        try:
            provider = Provider.objects.get(pk=pk)
            data = request.data.copy()
            profile_photo = request.FILES.get('profilePhoto')
            services = data.get('services')

            try:
                if not isinstance(services, list):
                    services = json.loads(data.get('services', '[]'))
            except json.JSONDecodeError:
                return Response({
                    'error': 'Invalid format for services.',
                }, status=status.HTTP_400_BAD_REQUEST)
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
                    'error': get_error_messages(serializer.errors)
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
                'data': []
            }, status=status.HTTP_200_OK)
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
                    'error': 'Service category is required.',
                    'data': []
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
    Get() ---> Retrieve all Services for the vendor.
    Post() ---> Create a new Service.
    """

    def get(self, request, format=None):
        
        user = request.user
        vendor = VendorKYC.objects.filter(user=user.id).first()
        if not vendor:
            return Response({
                'message': 'You must be a vendor to add a service.',
                'data': []
            }, status=status.HTTP_401_UNAUTHORIZED)
        try:
            services = vendor.ven_services.all()
            if services:
                serializer = ServiceSerializer(services, many=True)
                return Response({
                    'message': 'Services found for the vendor.',
                    'data': serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                'message': 'No services found for this vendor.',
                'data': []
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
        uploaded_image_urls = request.data.get('uploaded_image_urls', [])
        providers = data.pop('providers', [])
        data['vendor'] = vendor.vendor_id
        
        serializer = ServiceSerializer(data=data)
        if not serializer.is_valid():
            errors = serializer.errors
            error_list = [f"{field} {str(msg)}" for field, messages in errors.items() for msg in messages]
            return Response({
                'message': error_list[0],
                'error': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        if images:
            # image_urls = []
            uploaded_images = []
            for image in images:
            #     image_url = upload_to_s3(
            #         image,
            #         f'service-images/{vendor.vendor_id}',
            #         image.name
            #     )
            #     image_urls.append(image_url)
            #     serializer.validated_data['image'] = image_urls
                asset_uuid = generate_asset_uuid()
                base_file_name = f"asset_{asset_uuid}.webp"

                # Process and upload thumbnail
                thumbnail = process_image(image, (160, 130))
                thumbnail_url = upload_to_s3(thumbnail, 'service-images', f"thumbnail_{base_file_name}")

                # Process and upload compressed image
                compressed = process_image(image, (600, 250))
                compressed_url = upload_to_s3(compressed, 'service-images', base_file_name)

                original_image = process_image(image, None)   # Only changing format to WEBP
                original_url = upload_to_s3(original_image, 'service-images', f"original_{base_file_name}")

                uploaded_images.append({
                    "thumbnail": thumbnail_url,
                    "compressed": compressed_url,
                    "original": original_url
                })
            serializer.validated_data['image'] = uploaded_images
        elif uploaded_image_urls:
            serializer.validated_data['image'] = uploaded_image_urls
        service_instance = serializer.save()
        provider_names = []
        if providers:
            for provider_id in providers:
                try:
                    provider = Provider.objects.get(id=provider_id)
                    service_instance.providers.add(provider)
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
            existing_images = None
            if 'existing_images' in request.data.keys():
                existing_images = request.data.getlist('existing_images', []) 
            uploaded_image_urls = request.data.get('uploaded_image_urls', [])
            data['vendor'] = service.vendor.vendor_id
            image_urls = []
            if images:
                # uploaded_images = []
                for image in images:
                    asset_uuid = generate_asset_uuid()
                    base_file_name = f"asset_{asset_uuid}.webp"

                    # Process and upload thumbnail
                    thumbnail = process_image(image, (160, 130))
                    thumbnail_url = upload_to_s3(thumbnail, 'service-images', f"thumbnail_{base_file_name}")

                    # Process and upload compressed image
                    compressed = process_image(image, (600, 250))
                    compressed_url = upload_to_s3(compressed, 'service-images', base_file_name)

                    original_image = process_image(image, None)   # Only changing format to WEBP
                    original_url = upload_to_s3(original_image, 'service-images', f"original_{base_file_name}")

                    image_urls.append({
                        "thumbnail": thumbnail_url,
                        "compressed": compressed_url,
                        "original": original_url
                    })
            if existing_images:
                for img in existing_images:
                    if isinstance(img, str):
                        try:
                            img_dict = json.loads(img)
                            image_urls.append(img_dict)
                        except json.JSONDecodeError:
                            print("Failed to decode image JSON:", img)
                    elif isinstance(img, dict):
                        image_urls.append(img)
                    else:
                        print("Unknown image format:", img)
            if uploaded_image_urls:
                image_urls.extend(uploaded_image_urls)

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
            print(str(e))
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
            }, status=status.HTTP_200_OK)
        except Service.DoesNotExist:
            return Response({
                'message': 'Service not found.',
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

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['request'] = self.request
        return context

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
            curr_time = request.query_params.get('time')
            for_date_str = request.query_params.get('for_date')
            service_id = request.query_params.get('service_id')

            if not provider_id or not for_date_str or not service_id:
                return Response({
                    'error': 'Provider ID, service ID, and date are required.',
                    'data': []
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                for_date = datetime.strptime(for_date_str, "%Y-%m-%d").date()
            except ValueError:
                return Response({
                    'error': 'Invalid date format. Use YYYY-MM-DD.',
                    'data': []
                }, status=status.HTTP_400_BAD_REQUEST)

            provider = Provider.objects.get(id=provider_id)
            service = Service.objects.get(id=service_id)
            # required_slots = service.duration // 15
            required_slots = int(math.ceil(service.duration / 15))

            timeslot_filter = {
                'provider': provider,
                'date': for_date,
                # 'is_available': True
            }

            # Apply time filter only if for_date is today and curr_time is provided
            if curr_time and for_date == date.today():
                try:
                    curr_time_obj = datetime.strptime(curr_time, "%H:%M").time()
                    timeslot_filter['start_time__gt'] = curr_time_obj
                except ValueError:
                    return Response({
                        'error': 'Invalid time format. Use HH:MM.',
                        'data': []
                    }, status=status.HTTP_400_BAD_REQUEST)

            # Query time slots
            all_timeslots = TimeSlot.objects.filter(**timeslot_filter).order_by('start_time')

            if not all_timeslots.exists():
                return Response({
                    'error': 'No available time slots for the given service on this date. Please try different date or provider.',
                    'data': []
                }, status=status.HTTP_400_BAD_REQUEST)

            available_blocks = []
            slots = list(all_timeslots)
            i = 0

            while i + required_slots <= len(slots):
                block = slots[i:i + required_slots]

                # Ensure slots are continuous
                is_continuous = True
                for j in range(1, required_slots):
                    expected_next_time = (
                        datetime.combine(datetime.today(), block[j - 1].start_time) + timedelta(minutes=15)
                    ).time()
                    if block[j].start_time != expected_next_time:
                        is_continuous = False
                        break

                if is_continuous:
                    available_blocks.append({
                        'start_time': block[0].start_time,
                        'end_time': block[-1].end_time,
                        'is_available': True,
                        'timeslots': [
                            ts.id for ts in block 
                        ]
                    })
                    i += required_slots  # ⬅️ move to the next non-overlapping block
                else:
                    i += 1  # try next starting point

            return Response({
                'message': 'Available timeslot blocks retrieved.',
                'data': {
                    'service_id': service.id,
                    'service_name': service.name,
                    'duration': service.duration,
                    'available_blocks': available_blocks
                }
            }, status=status.HTTP_200_OK)

        except Provider.DoesNotExist:
            return Response({
                'message': 'Provider not found.',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)

        except Service.DoesNotExist:
            return Response({
                'message': 'Service not found.',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                'message': 'An error occurred while fetching time slots.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def post(self, request, service_id, format=None):
        try:
            data = request.data.copy()
            start_date = data.get('start_date')
            if not start_date:
                return Response({
                    'error': 'Start date and is required.',
                    'date': []
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
    """
    Get() ---> Get all appointments of the vendor
    Post() ---> Book an Appointment 
    """
    permission_classes = [IsAuthenticated]

    # def get(self, request, vendor_id):
    #     now = make_aware(datetime.now())

    #     appointments = Appointment.objects.filter(vendor=vendor_id).prefetch_related('time_slot')
    #     if not appointments.exists():
    #         return Response({
    #             'message': 'No appointments found.',
    #             'data': []
    #         }, status=status.HTTP_200_OK)

    #     upcoming_appointments = []
    #     past_appointments_to_expire = []
    #     past_appointments_data = []

    #     for appointment in appointments:
    #         slot_datetime = make_aware(datetime.combine(
    #             appointment.time_slot.date,
    #             appointment.time_slot.start_time
    #         ))

    #         if slot_datetime >= now:
    #             upcoming_appointments.append(appointment)
    #         else:
    #             if appointment.status != 'expired':
    #                 appointment.status = 'expired'
    #                 past_appointments_to_expire.append(appointment)
    #             past_appointments_data.append(appointment)

    #     # Bulk update the expired appointments
    #     if past_appointments_to_expire:
    #         Appointment.objects.bulk_update(past_appointments_to_expire, ['status'])

    #     # Serialize data
    #     upcoming_serializer = GetAppointmentSerializer(upcoming_appointments, many=True)
    #     past_serializer = GetAppointmentSerializer(past_appointments_data, many=True)

    #     return Response({
    #         'message': 'Appointments found.',
    #         'data': {
    #             'upcoming': upcoming_serializer.data,
    #             'past': past_serializer.data
    #         }
    #     }, status=status.HTTP_200_OK)

    def get(self, request, vendor_id):
        now = make_aware(datetime.now())

        appointments = Appointment.objects.filter(vendor=vendor_id).prefetch_related('time_slot')
        if not appointments.exists():
            return Response({
                'message': 'No appointments found.',
                'data': []
            }, status=status.HTTP_200_OK)

        upcoming_appointments = []
        past_appointments_to_expire = []
        past_appointments_data = []

        for appointment in appointments:
            timeslots = appointment.time_slot.all().order_by('date', 'start_time')

            if not timeslots.exists():
                continue  # or optionally treat it as past

            earliest_slot = timeslots.first()
            slot_datetime = datetime.combine(earliest_slot.date, earliest_slot.start_time)
            if not is_aware(slot_datetime):
                slot_datetime = make_aware(slot_datetime)

            if slot_datetime >= now:
                upcoming_appointments.append(appointment)
            else:
                if appointment.status != 'expired':
                    appointment.status = 'expired'
                    past_appointments_to_expire.append(appointment)
                past_appointments_data.append(appointment)

        # Bulk update expired appointments
        if past_appointments_to_expire:
            Appointment.objects.bulk_update(past_appointments_to_expire, ['status'])

        # Serialize data
        upcoming_serializer = GetAppointmentSerializer(upcoming_appointments, many=True)
        past_serializer = GetAppointmentSerializer(past_appointments_data, many=True)

        return Response({
            'message': 'Appointments found.',
            'data': {
                'upcoming': upcoming_serializer.data,
                'past': past_serializer.data
            }
        }, status=status.HTTP_200_OK)


    def post(self, request, format=None):
        data = request.data.copy()
        data['customer'] = request.user.id

        # Parse the slots
        slots = request.data.get('time_slot')
        if not isinstance(slots, list):
            try:
                slots = json.loads(slots)
            except json.JSONDecodeError:
                return Response({
                    'message': 'Invalid time_slot format. It must be a list or a valid JSON list.',
                    'data': {}
                }, status=status.HTTP_400_BAD_REQUEST)

        try:
            provider = Provider.objects.get(id=data['provider'])

            # Validate all slots
            timeslot_objs = []
            for slot_id in slots:
                timeslot = TimeSlot.objects.get(id=slot_id)
                if not timeslot.is_available:
                    return Response({
                        'message': f"Timeslot {slot_id} is not available. Try different time slots.",
                        'data': {}
                    }, status=status.HTTP_200_OK)
                timeslot_objs.append(timeslot)

            data['vendor'] = provider.vendor.vendor_id

        except Provider.DoesNotExist:
            return Response({
                'message': 'Provider not found.'
            }, status=status.HTTP_404_NOT_FOUND)
        except TimeSlot.DoesNotExist:
            return Response({
                'message': f"One or more provided time slot IDs are invalid."
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = AppointmentSerializer(data=data)
        if serializer.is_valid():
            appointment = serializer.save()

            # Set M2M field and mark slots as unavailable
            appointment.time_slot.set(timeslot_objs)
            for ts in timeslot_objs:
                ts.is_available = False
                ts.save()

            return Response({
                'message': 'Appointment has been booked successfully.',
                'data': AppointmentSerializer(appointment).data
            }, status=status.HTTP_201_CREATED)

        return Response({
            'message': 'Appointment cannot be booked.',
            'error': get_error_messages(serializer.errors)
        }, status=status.HTTP_400_BAD_REQUEST)


    def patch(self, request, pk):
        print("Incoming data:", request.data)

        try:
            appointment = Appointment.objects.get(pk=pk)
        except Appointment.DoesNotExist:
            return Response({
                'error': 'Appointment does not exists.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # appointment_status = request.data.get('status')
        data = request.data.copy()
        data.pop('time_slot', None)
        print("before serializer")
        serializer = AppointmentSerializer(appointment, data=data, partial=True)
        print("after serializer")
        if serializer.is_valid():
            print("serializer is valid")
            print("validated data ", serializer.validated_data)
            serializer.save(update_fields=['status'])
            return Response({
                'message': 'Status updated successfully.',
                'data': serializer.data
            }, status=status.HTTP_200_OK)

        return Response({
            'message': 'Status could not be updated.',
            'error': get_error_messages(serializer.errors)
        }, status=status.HTTP_400_BAD_REQUEST)

class RetrieveAppointmentAPIView(generics.RetrieveAPIView):
    """
    Get particular Service with ID (pk)
    """
    queryset = Appointment.objects.all()
    serializer_class = GetAppointmentSerializer
    permission_classes = [IsAuthenticated]

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['request'] = self.request
        return context

class GetUserAppointmentsAPIView(APIView):
    """
    Get() ---> Get the user's all appointments
    """
    permission_classes = [IsAuthenticated]
    # def get(self, request):
    #     user = request.user
    #     now = make_aware(datetime.now())  # current timezone-aware datetime

    #     upcoming_appointments = []
    #     past_appointments = []

    #     appointments = Appointment.objects.filter(customer=user).prefetch_related('time_slot')
    #     # for appointment in appointments:
    #     #     slot_datetime = make_aware(datetime.combine(appointment.time_slot.date, appointment.time_slot.start_time))

    #     #     if slot_datetime >= now:
    #     #         upcoming_appointments.append(appointment)
    #     #     else:
    #     #         appointment.status = 'expired'
    #     #         appointment.save()
    #     #         past_appointments.append(appointment)
    #     # ==================================
    #     for appointment in appointments:
    #         timeslots = appointment.time_slot.all().order_by('date', 'start_time')
    #         if not timeslots.exists():
    #             continue  # Or handle empty case

    #         earliest_slot = timeslots.first()
    #         slot_datetime = make_aware(datetime.combine(earliest_slot.date, earliest_slot.start_time))

    #         if slot_datetime >= now:
    #             upcoming_appointments.append(appointment)
    #         else:
    #             appointment.status = 'expired'
    #             past_appointments.append(appointment)
    #     # ==================================
    #     if past_appointments:
    #         print("Past appointments: ", past_appointments)
    #         Appointment.objects.bulk_update(past_appointments, ['status'])

    #     upcoming_serializer = GetAppointmentSerializer(upcoming_appointments, many=True)
    #     past_serializer = GetAppointmentSerializer(past_appointments, many=True)

    #     return Response({
    #         'message': 'Appointments categorized.',
    #         'data': {
    #             'upcoming': upcoming_serializer.data,
    #             'past': past_serializer.data
    #         }
    #     }, status=status.HTTP_200_OK)

    def get(self, request):
        user = request.user
        now = make_aware(datetime.now())

        upcoming_appointments = []
        past_appointments = []

        appointments = Appointment.objects.filter(customer=user).prefetch_related('time_slot')
        print(f"Total appointments for user {user}: {appointments.count()}")

        for appointment in appointments:
            timeslots = appointment.time_slot.all().order_by('date', 'start_time')
            if not timeslots.exists():
                print(f"⚠️ Appointment {appointment.id} has no linked time slots.")
                continue

            earliest_slot = timeslots.first()
            slot_datetime = datetime.combine(earliest_slot.date, earliest_slot.start_time)
            if not is_aware(slot_datetime):
                slot_datetime = make_aware(slot_datetime)

            if slot_datetime >= now:
                upcoming_appointments.append(appointment)
            else:
                if appointment.status != 'expired':
                    appointment.status = 'expired'
                    past_appointments.append(appointment)

        if past_appointments:
            Appointment.objects.bulk_update(past_appointments, ['status'])

        upcoming_serializer = GetAppointmentSerializer(upcoming_appointments, many=True)
        past_serializer = GetAppointmentSerializer(past_appointments, many=True)

        return Response({
            'message': 'Appointments categorized.',
            'data': {
                'upcoming': upcoming_serializer.data,
                'past': past_serializer.data
            }
        }, status=status.HTTP_200_OK)
