# Generated by Django 5.0 on 2024-11-11 07:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0038_rename_name_servicecategory_serv_category'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='social_id',
            field=models.CharField(blank=True, max_length=255, null=True, unique=True),
        ),
    ]
