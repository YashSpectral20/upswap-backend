from django.db import models
from main.models import (
    VendorKYC,
    CustomUser
)

class ServiceCategory(models.Model):
    vendor = models.ForeignKey(VendorKYC, on_delete=models.CASCADE, related_name='ven_service_categories')
    service_category = models.CharField(max_length=100)

    def __str__(self):
        return self.service_category

class Service(models.Model):
    SERVICE_CATEGORY_CHOICES = [
        ("Automotive Services & Products", "Automotive Services & Products"),
        ("Art, Crafts & Collectibles", "Art, Crafts & Collectibles"),
        ("Baby Care", "Baby Care"),
        ("Bakery", "Bakery"),
        ("Books, Stationery & Toys", "Books, Stationery & Toys"),
        ("Clothing", "Clothing"),
        ("Clothing", "Clothing"),
        ("Dentist", "Dentist"),
        ("Electronics", "Electronics"),
        ("Estate Agents", "Estate Agents"),
        ("Fashion, Apparel & Accessories", "Fashion, Apparel & Accessories"),
        ("Food", "Food"),
        ("Furniture", "Furniture"),
        ("Groceries", "Groceries"),
        ("Health, Wellness & Fitness", "Health, Wellness & Fitness"),
        ("Home, Living & Kitchen", "Home, Living & Kitchen"),
        ("Others", "Others"),
        ("Personal Care", "Personal Care"),
        ("Pet Care Services & Supplies", "Pet Care Services & Supplies"),
        ("Professional & Business Services", "Professional & Business Services"),
        ("Rent & Hire", "Rent & Hire"),
        ("Restaurants", "Restaurants"),
        ("Sports & Outdoors", "Sports & Outdoors"),
        ("Other Services & Consultations", "Other Services & Consultations"),
    ]
    name = models.CharField(max_length=255)
    vendor = models.ForeignKey(VendorKYC, on_delete=models.CASCADE, related_name='ven_services')
    description = models.TextField(blank=True, null=True)
    category = models.CharField(max_length=100, choices=SERVICE_CATEGORY_CHOICES)
    duration = models.PositiveIntegerField(help_text="Duration in minutes.")
    buffer_time = models.PositiveIntegerField(default=0, help_text="Buffer time in minutes.")
    price = models.DecimalField(max_digits=10, decimal_places=2)
    color_code = models.CharField(max_length=20, blank=True, null=True)
    image = models.JSONField(default=list, blank=True, null=True)


class Provider(models.Model):
    vendor = models.ForeignKey(VendorKYC, on_delete=models.CASCADE, related_name='vendor_providers')
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15, blank=True, null=True)
    profile_photo = models.JSONField(blank=True, default=list)
    title = models.CharField(max_length=100)
    services = models.ManyToManyField(Service, related_name='providers', blank=True)
    work_hours = models.JSONField(default=dict)

class TimeSlot(models.Model):
    provider = models.ForeignKey(Provider, on_delete=models.CASCADE, related_name='time_slots')
    date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    is_available = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['date', 'start_time']
        unique_together = ['provider', 'date', 'start_time', 'end_time']

    def __str__(self):
        return f"{self.date} {self.start_time}-{self.end_time}"

class Appointment(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]

    customer = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='customer_appointments')
    vendor = models.ForeignKey(VendorKYC, on_delete=models.CASCADE, related_name='vendor_appointments')
    provider = models.ForeignKey(Provider, on_delete=models.CASCADE, null=True, blank=True)
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='appointments')
    time_slot = models.ForeignKey(TimeSlot, on_delete=models.CASCADE, related_name='appointments')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Appointment {self.id} - {self.customer.username} with {self.vendor.business_name} for {self.service.name}"

    @property
    def date_time(self):
        return f"{self.time_slot.date} {self.time_slot.start_time}"

    def save(self, *args, **kwargs):
        if self.pk:  # If this is an update
            old_instance = Appointment.objects.get(pk=self.pk)
            old_status = old_instance.status
            new_status = self.status

            # Handle status changes
            if old_status != new_status:
                if new_status == 'approved':
                    self.time_slot.is_available = False
                    self.time_slot.save()
                elif new_status == 'cancelled' and old_status == 'approved':
                    self.time_slot.is_available = True
                    self.time_slot.save()
                elif new_status == 'rejected' and old_status == 'pending':
                    self.time_slot.is_available = True
                    self.time_slot.save()

        super().save(*args, **kwargs) 

