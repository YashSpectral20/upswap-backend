from datetime import datetime, timedelta
from django.shortcuts import get_object_or_404
from django.db import IntegrityError

from ..models import Service, TimeSlot

# def generate_timeslots(service_id, start_date):
#     service = get_object_or_404(Service, pk=service_id)
#     providers = service.providers.all()
#     start_date_str = start_date
#     start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()

#     end_date = start_date + timedelta(days=30)

#     slot_duration = service.duration   # + service.buffer_time
#     new_timeslots = []
    
#     for provider in providers:

#         current_date = start_date
#         while current_date <= end_date:
#             day_name = current_date.strftime("%A")
#             today = provider.work_hours.get(day_name.lower())
#             work_hours = provider.work_hours
#             if work_hours and not today['closed']:
#                 start_time = datetime.strptime(today['start'], '%H:%M').time()
#                 end_time = datetime.strptime(today['end'], '%H:%M').time()
    
#                 current_time = datetime.combine(current_date, start_time)
#                 work_end_time = datetime.combine(current_date, end_time)

#                 while current_time + timedelta(minutes=service.duration) <= work_end_time:
#                     slot_end_time = (current_time + timedelta(minutes=service.duration)).time()
                    
#                     # Create a new TimeSlot instance
#                     timeslot = TimeSlot(
#                         provider=provider,
#                         date=current_date,
#                         start_time=current_time.time(),
#                         end_time=slot_end_time
#                     )
#                     new_timeslots.append(timeslot)

#                     # Move to the next slot
#                     current_time += timedelta(minutes=slot_duration)
#             current_date += timedelta(days=1)
#     try:
#         print("Timeslot to be created---> ", len(new_timeslots))
#         TimeSlot.objects.bulk_create(new_timeslots, ignore_conflicts=True) # ignore_conflicts uses the unique_together constraint
#         return True, None
#     except IntegrityError:
#     # Handle cases where a unique constraint is violated if not using ignore_conflicts
#         return False, "Time slots already exist for the given provider and date range."
#     return False, "No providers found for the given service."

SLOT_DURATION = 15

def generate_timeslots(provider):
    start_date = datetime.now().date()
    end_date = start_date + timedelta(days=30)

    new_timeslots = []
    current_date = start_date
    while current_date <= end_date:
        day_name = current_date.strftime("%A")
        today = provider.work_hours.get(day_name.lower())
        work_hours = provider.work_hours
        if work_hours and not today['closed']:
            start_time = datetime.strptime(today['start'], '%H:%M').time()
            end_time = datetime.strptime(today['end'], '%H:%M').time()

            current_time = datetime.combine(current_date, start_time)
            work_end_time = datetime.combine(current_date, end_time)

            while current_time + timedelta(minutes=SLOT_DURATION) <= work_end_time:
                slot_end_time = (current_time + timedelta(minutes=SLOT_DURATION)).time()
                
                # Create a new TimeSlot instance
                timeslot = TimeSlot(
                    provider=provider,
                    date=current_date,
                    start_time=current_time.time(),
                    end_time=slot_end_time
                )
                new_timeslots.append(timeslot)

                # Move to the next slot
                current_time += timedelta(minutes=SLOT_DURATION)
        current_date += timedelta(days=1)
    try:
        print("Timeslot to be created---> ", len(new_timeslots))
        TimeSlot.objects.bulk_create(new_timeslots, ignore_conflicts=True) # ignore_conflicts uses the unique_together constraint
        return True, None
    except IntegrityError:
    # Handle cases where a unique constraint is violated if not using ignore_conflicts
        return False, "Time slots already exist for the given provider and date range."
    return False, "No providers found for the given service."