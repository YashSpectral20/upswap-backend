from django.db import models
from main.models import (
    Service,
    VendorKYC
)

class Provider(models.Model):
    vendor = models.ForeignKey(VendorKYC, on_delete=models.CASCADE, related_name='providers')
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15, blank=True, null=True)
    profile_photo = models.JSONField(blank=True, default=list)
    title = models.CharField(max_length=100)
    services = models.ManyToManyField(Service, related_name='providers', blank=True)
    work_hours = models.JSONField(default=dict)