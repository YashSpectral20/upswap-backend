import uuid
from django.db import models
from django.utils import timezone
 
from main.models import VendorKYC as Vendor
from main.models import CreateDeal as Deal
from main.models import Address as Adrs
 
# class Vendor(models.Model):
#     vendor_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     vendor_name = models.CharField(max_length=255)
#     contact_email = models.EmailField(unique=True)
#     contact_phone = models.CharField(max_length=50, blank=True, null=True)
#     address = models.TextField(blank=True, null=True)
#     is_active = models.BooleanField(default=True)
#     created_at = models.DateTimeField(default=timezone.now)
#     updated_at = models.DateTimeField(auto_now=True)
 
class Category(models.Model):
    category_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    category_name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    parent_category = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
 
class Supplier(models.Model):
    supplier_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    supplier_name = models.CharField(max_length=255)
    contact_info = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
 
class InventoryItem(models.Model):
    ITEM_TYPES = [
        ('PHYSICAL_GOOD', 'Physical Good'),
        ('PERISHABLE_GOOD', 'Perishable Good'),
        ('DIGITAL_PRODUCT', 'Digital Product'),
        ('SERVICE', 'Service'),
    ]
 
    item_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vendor = models.ForeignKey(Vendor, on_delete=models.CASCADE)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    item_type = models.CharField(max_length=50, choices=ITEM_TYPES, default='PHYSICAL_GOOD')
    sku = models.CharField(max_length=100)
    item_name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    measurement_unit = models.CharField(max_length=50, blank=True, null=True)
    standard_selling_price = models.DecimalField(max_digits=12, decimal_places=2)
    image_url = models.URLField(max_length=512, blank=True, null=True)
    attributes = models.JSONField(blank=True, null=True)
    tracks_batches = models.BooleanField(default=False)
    quantity_on_hand = models.IntegerField(blank=True, null=True)
    cost_price = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    manufacturing_date = models.DateField(blank=True, null=True)
    expiry_date = models.DateField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    last_suggestion_check_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
 
    class Meta:
        unique_together = ('vendor', 'sku')
 
class ItemBatch(models.Model):
    STATUS_CHOICES = [
        ('AVAILABLE', 'Available'),
        ('RESERVED', 'Reserved'),
        ('QUARANTINED', 'Quarantined'),
        ('SOLD_OUT', 'Sold Out'),
        ('EXPIRED', 'Expired'),
    ]
 
    batch_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    item = models.ForeignKey(InventoryItem, on_delete=models.CASCADE)
    batch_number = models.CharField(max_length=100, blank=True, null=True)
    quantity_in_batch = models.IntegerField(default=0)
    original_quantity = models.IntegerField(default=0)
    cost_price_per_unit = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    manufacturing_date = models.DateField(blank=True, null=True)
    expiry_date = models.DateField(blank=True, null=True)
    received_date = models.DateField(default=timezone.now, blank=True, null=True)
    supplier = models.ForeignKey(Supplier, on_delete=models.SET_NULL, null=True, blank=True)
    location_in_warehouse = models.CharField(max_length=100, blank=True, null=True)
    batch_attributes = models.JSONField(blank=True, null=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='AVAILABLE')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
 
    class Meta:
        unique_together = ('item', 'batch_number')
 
class DealSuggestion(models.Model):
    SUGGESTION_TYPES = [
        ('PERCENTAGE_DISCOUNT', 'Percentage Discount'),
        ('FIXED_DISCOUNT', 'Fixed Discount'),
        ('BUNDLE', 'Bundle'),
    ]
 
    STATUS_CHOICES = [
        ('PENDING_REVIEW', 'Pending Review'),
        ('ACCEPTED', 'Accepted'),
        ('REJECTED', 'Rejected'),
        ('IMPLEMENTED', 'Implemented'),
    ]
 
    suggestion_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    item = models.ForeignKey(InventoryItem, on_delete=models.CASCADE)
    batch = models.ForeignKey(ItemBatch, on_delete=models.SET_NULL, null=True, blank=True)
    suggestion_type = models.CharField(max_length=100, choices=SUGGESTION_TYPES)
    suggested_discount_value = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    suggested_new_price = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    suggested_start_date = models.DateTimeField(blank=True, null=True)
    suggested_end_date = models.DateTimeField(blank=True, null=True)
    reasoning = models.TextField(blank=True, null=True)
    confidence_score = models.FloatField(blank=True, null=True)
    generated_at = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='PENDING_REVIEW')
    vendor_reviewed_at = models.DateTimeField(blank=True, null=True)
    is_implemented_as_deal = models.ForeignKey(Deal, on_delete=models.SET_NULL, null=True, blank=True)
    notes_from_vendor = models.TextField(blank=True, null=True)
    
class Event(models.Model):
    class EventTriggerChoices(models.TextChoices):
        WEATHER = 'weather', 'Weather'
        PRODUCT_EXPIRY = 'product_expiry', 'Product Expiry'
        HOLIDAY_SPECIAL = 'holiday_special', 'Holiday Special'
        LOCAL_EVENT = 'local_event', 'Local Event'
        COMPETITOR_ACTION = 'competitor_action', 'Competitor Action'
        STOCK_LEVEL = 'stock_level', 'Stock Level'

    event_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vendor = models.ForeignKey('main.VendorKYC', on_delete=models.CASCADE, related_name='events')
    location = models.ForeignKey('main.Address', on_delete=models.CASCADE, related_name='events')
    event_trigger_point = models.CharField(max_length=50, choices=EventTriggerChoices.choices)
    event_details_text = models.TextField()
    event_location_latitude = models.DecimalField(max_digits=10, decimal_places=8)
    event_location_longitude = models.DecimalField(max_digits=11, decimal_places=8)
    event_timestamp = models.DateTimeField()
    created_at = models.DateTimeField(default=timezone.now)
    processed_for_suggestion = models.BooleanField(default=False)

    def __str__(self):
        return f"Event {self.event_id} - {self.event_trigger_point}"
 
# class Deal(models.Model):
#     DEAL_TYPES = [
#         ('PERCENTAGE_OFF', 'Percentage Off'),
#         ('FIXED_AMOUNT_OFF', 'Fixed Amount Off'),
#         ('BUNDLE_PRICE', 'Bundle Price'),
#     ]
 
#     deal_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     item = models.ForeignKey(InventoryItem, on_delete=models.CASCADE)
#     vendor = models.ForeignKey(Vendor, on_delete=models.CASCADE)
#     deal_name = models.CharField(max_length=255)
#     deal_description = models.TextField(blank=True, null=True)
#     deal_type = models.CharField(max_length=50, choices=DEAL_TYPES)
#     discount_value = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
#     original_price_at_creation = models.DecimalField(max_digits=12, decimal_places=2)
#     deal_price = models.DecimalField(max_digits=12, decimal_places=2)
#     start_datetime = models.DateTimeField()
#     end_datetime = models.DateTimeField()
#     max_quantity_per_customer = models.IntegerField(blank=True, null=True)
#     total_quantity_for_deal = models.IntegerField(blank=True, null=True)
#     is_active = models.BooleanField(default=False)
#     created_by_suggestion = models.ForeignKey(DealSuggestion, on_delete=models.SET_NULL, null=True, blank=True)
#     created_at = models.DateTimeField(default=timezone.now)
#     updated_at = models.DateTimeField(auto_now=True)