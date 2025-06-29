# Generated by Django 5.0 on 2025-05-08 13:48

import django.db.models.deletion
import django.utils.timezone
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    # dependencies = [
    #     ('main', '0090_passwordresetotp'),
    # ]

    operations = [
        migrations.CreateModel(
            name='Supplier',
            fields=[
                ('supplier_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('supplier_name', models.CharField(max_length=255)),
                ('contact_info', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='Category',
            fields=[
                ('category_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('category_name', models.CharField(max_length=100, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('parent_category', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='deals_agent.category')),
            ],
        ),
        migrations.CreateModel(
            name='InventoryItem',
            fields=[
                ('item_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('item_type', models.CharField(choices=[('PHYSICAL_GOOD', 'Physical Good'), ('PERISHABLE_GOOD', 'Perishable Good'), ('DIGITAL_PRODUCT', 'Digital Product'), ('SERVICE', 'Service')], default='PHYSICAL_GOOD', max_length=50)),
                ('sku', models.CharField(max_length=100)),
                ('item_name', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True, null=True)),
                ('measurement_unit', models.CharField(blank=True, max_length=50, null=True)),
                ('standard_selling_price', models.DecimalField(decimal_places=2, max_digits=12)),
                ('image_url', models.URLField(blank=True, max_length=512, null=True)),
                ('attributes', models.JSONField(blank=True, null=True)),
                ('tracks_batches', models.BooleanField(default=False)),
                ('quantity_on_hand', models.IntegerField(blank=True, null=True)),
                ('cost_price', models.DecimalField(blank=True, decimal_places=2, max_digits=12, null=True)),
                ('manufacturing_date', models.DateField(blank=True, null=True)),
                ('expiry_date', models.DateField(blank=True, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('last_suggestion_check_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('category', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='deals_agent.category')),
                ('vendor', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.vendorkyc')),
            ],
            options={
                'unique_together': {('vendor', 'sku')},
            },
        ),
        migrations.CreateModel(
            name='ItemBatch',
            fields=[
                ('batch_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('batch_number', models.CharField(blank=True, max_length=100, null=True)),
                ('quantity_in_batch', models.IntegerField(default=0)),
                ('original_quantity', models.IntegerField(default=0)),
                ('cost_price_per_unit', models.DecimalField(blank=True, decimal_places=2, max_digits=12, null=True)),
                ('manufacturing_date', models.DateField(blank=True, null=True)),
                ('expiry_date', models.DateField(blank=True, null=True)),
                ('received_date', models.DateField(blank=True, default=django.utils.timezone.now, null=True)),
                ('location_in_warehouse', models.CharField(blank=True, max_length=100, null=True)),
                ('batch_attributes', models.JSONField(blank=True, null=True)),
                ('status', models.CharField(choices=[('AVAILABLE', 'Available'), ('RESERVED', 'Reserved'), ('QUARANTINED', 'Quarantined'), ('SOLD_OUT', 'Sold Out'), ('EXPIRED', 'Expired')], default='AVAILABLE', max_length=50)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('item', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='deals_agent.inventoryitem')),
                ('supplier', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='deals_agent.supplier')),
            ],
            options={
                'unique_together': {('item', 'batch_number')},
            },
        ),
        migrations.CreateModel(
            name='DealSuggestion',
            fields=[
                ('suggestion_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('suggestion_type', models.CharField(choices=[('PERCENTAGE_DISCOUNT', 'Percentage Discount'), ('FIXED_DISCOUNT', 'Fixed Discount'), ('BUNDLE', 'Bundle')], max_length=100)),
                ('suggested_discount_value', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('suggested_new_price', models.DecimalField(blank=True, decimal_places=2, max_digits=12, null=True)),
                ('suggested_start_date', models.DateTimeField(blank=True, null=True)),
                ('suggested_end_date', models.DateTimeField(blank=True, null=True)),
                ('reasoning', models.TextField(blank=True, null=True)),
                ('confidence_score', models.FloatField(blank=True, null=True)),
                ('generated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('status', models.CharField(choices=[('PENDING_REVIEW', 'Pending Review'), ('ACCEPTED', 'Accepted'), ('REJECTED', 'Rejected'), ('IMPLEMENTED', 'Implemented')], default='PENDING_REVIEW', max_length=50)),
                ('vendor_reviewed_at', models.DateTimeField(blank=True, null=True)),
                ('notes_from_vendor', models.TextField(blank=True, null=True)),
                ('is_implemented_as_deal', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='main.createdeal')),
                ('item', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='deals_agent.inventoryitem')),
                ('batch', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='deals_agent.itembatch')),
            ],
        ),
    ]
