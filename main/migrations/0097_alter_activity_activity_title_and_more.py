# Generated by Django 5.0 on 2025-06-14 07:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0096_rename_set_current_datetime_activity_is_deleted_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='activity',
            name='activity_title',
            field=models.CharField(max_length=100),
        ),
        migrations.AlterField(
            model_name='activity',
            name='category',
            field=models.CharField(choices=[('Tech and Gaming', 'Tech and Gaming'), ('Volunteer Opportunities', 'Volunteer Opportunities'), ('Cultural Exchanges', 'Cultural Exchanges'), ('Intellectual Pursuits', 'Intellectual Pursuits'), ('Sports and Recreation', 'Sports and Recreation'), ('Arts and Crafts', 'Arts and Crafts'), ('Social Gatherings', 'Social Gatherings'), ('Educational Workshops', 'Educational Workshops'), ('Music and Entertainment', 'Music and Entertainment'), ('Others', 'Others')], max_length=100),
        ),
    ]
