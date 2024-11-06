from django.core.management.base import BaseCommand
from main.models import ActivityCategory, ServiceCategory

class Command(BaseCommand):
    help = 'Populate ActivityCategory and ServiceCategory with predefined values'

    def handle(self, *args, **kwargs):
        activity_categories = [
            "Tech and Gaming", "Volunteer Opportunities", "Cultural Exchanges",
            "Intellectual Pursuits", "Sports and Recreation", "Arts and Crafts",
            "Social Gatherings", "Educational Workshops", "Music and Entertainment", "Others"
        ]
        for category in activity_categories:
            ActivityCategory.objects.get_or_create(name=category)

        service_categories = [
            "Restaurants", "Consultants", "Estate Agents", "Rent & Hire",
            "Dentist", "Personal Care", "Food", "Bakery", "Groceries", "Others"
        ]
        for category in service_categories:
            ServiceCategory.objects.get_or_create(name=category)

        self.stdout.write(self.style.SUCCESS('Successfully populated categories'))