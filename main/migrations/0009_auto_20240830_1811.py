# Generated by Django 3.2.25 on 2024-08-30 18:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0008_auto_20240830_1106'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='vendorkyc',
            options={'verbose_name_plural': 'Vendor KYCs'},
        ),
        migrations.AddField(
            model_name='activity',
            name='images',
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AlterField(
            model_name='vendorkyc',
            name='business_hours',
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AlterField(
            model_name='vendorkyc',
            name='chosen_item_category',
            field=models.CharField(blank=True, default='', max_length=100),
        ),
        migrations.AlterField(
            model_name='vendorkyc',
            name='item_name',
            field=models.CharField(blank=True, default='', max_length=255),
        ),
        migrations.AlterField(
            model_name='vendorkyc',
            name='item_price',
            field=models.DecimalField(blank=True, decimal_places=2, default=0.0, max_digits=10),
        ),
        migrations.DeleteModel(
            name='ActivityImage',
        ),
    ]