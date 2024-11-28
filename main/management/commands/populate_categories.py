from django.core.management.base import BaseCommand
from main.models import ActivityCategory, ServiceCategory

class Command(BaseCommand):
    help = 'Populate ActivityCategory and ServiceCategory with predefined values'

    def handle(self, *args, **kwargs):
        # Activity categories ko list me define kiya
        activity_categories = [
            "Tech and Gaming", "Volunteer Opportunities", "Cultural Exchanges",
            "Intellectual Pursuits", "Sports and Recreation", "Arts and Crafts",
            "Social Gatherings", "Educational Workshops", "Music and Entertainment", "Others"
        ]
        # Loop chalake categories ko add karo
        for category in activity_categories:
            ActivityCategory.objects.get_or_create(actv_category=category)

        # Service categories ko list me define kiya
        service_categories = [
            "Restaurants", "Consultants", "Estate Agents", "Rent & Hire",
            "Dentist", "Personal Care", "Food", "Bakery", "Groceries", "Others"
        ]
        # Loop chalake service categories ko add karo, ab serv_category field use karo
        for category in service_categories:
            ServiceCategory.objects.get_or_create(serv_category=category)

        self.stdout.write(self.style.SUCCESS('Successfully populated categories'))
