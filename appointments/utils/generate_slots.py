from datetime import datetime, timedelta
from django.shortcuts import get_object_or_404
from django.db import IntegrityError

from ..models import Service, TimeSlot

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

# your_app/utils.py or wherever you store helper functions

def create_slots_for_provider_in_range(provider, start_date, end_date):
    """
    Generates TimeSlot objects for a given provider within a specific date range.
    
    Args:
        provider (Provider): The provider instance.
        start_date (date): The first day to generate slots for.
        end_date (date): The last day to generate slots for.
        
    Returns:
        A tuple of (number_of_slots_created, error_message).
    """
    new_timeslots = []
    current_date = start_date
    work_hours = provider.work_hours

    if not work_hours:
        return 0, "Provider has no work hours defined."

    while current_date <= end_date:
        day_name = current_date.strftime("%A").lower()
        day_info = work_hours.get(day_name)
        
        # Check if the provider works on this day
        if day_info and not day_info.get('closed', True):
            try:
                start_time = datetime.strptime(day_info['start'], '%H:%M').time()
                end_time = datetime.strptime(day_info['end'], '%H:%M').time()

                current_time = datetime.combine(current_date, start_time)
                work_end_time = datetime.combine(current_date, end_time)

                while current_time + timedelta(minutes=SLOT_DURATION) <= work_end_time:
                    slot_end_time = (current_time + timedelta(minutes=SLOT_DURATION)).time()
                    
                    timeslot = TimeSlot(
                        provider=provider,
                        date=current_date,
                        start_time=current_time.time(),
                        end_time=slot_end_time
                    )
                    new_timeslots.append(timeslot)
                    
                    current_time += timedelta(minutes=SLOT_DURATION)
            except (ValueError, KeyError):
                # Handle malformed work_hours data for a specific day
                pass

        current_date += timedelta(days=1)

    if not new_timeslots:
        return 0, None # No error, just no slots to create

    try:
        # Use bulk_create with ignore_conflicts for efficiency and to prevent duplicates
        TimeSlot.objects.bulk_create(new_timeslots, ignore_conflicts=True)
        return len(new_timeslots), None
    except IntegrityError:
        return 0, "An integrity error occurred. Some slots might already exist."