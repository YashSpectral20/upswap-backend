# Generated by Django 5.0 on 2025-06-27 07:05

import datetime
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('appointments', '0008_alter_service_category'),
        ('main', '0100_customuser_email_verified_alter_customuser_country_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='FavoriteService',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='FavoriteUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.RemoveField(
            model_name='favoritevendor',
            name='added_at',
        ),
        migrations.AddField(
            model_name='favoritevendor',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=datetime.datetime(2025, 6, 27, 7, 5, 58, 860666, tzinfo=datetime.timezone.utc)),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='customuser',
            name='type',
            field=models.CharField(blank=True, choices=[('google', 'Google'), ('apple', 'Apple'), ('facebook', 'Facebook')], max_length=10, null=True),
        ),
        migrations.AlterField(
            model_name='favoritevendor',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddIndex(
            model_name='favoritevendor',
            index=models.Index(fields=['user', 'vendor'], name='main_favori_user_id_f33fc0_idx'),
        ),
        migrations.AddField(
            model_name='favoriteservice',
            name='service',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='favorited_by', to='appointments.service'),
        ),
        migrations.AddField(
            model_name='favoriteservice',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='favoriteuser',
            name='favorite_user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='favorited_by', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='favoriteuser',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddIndex(
            model_name='favoriteservice',
            index=models.Index(fields=['user', 'service'], name='main_favori_user_id_f8527b_idx'),
        ),
        migrations.AlterUniqueTogether(
            name='favoriteservice',
            unique_together={('user', 'service')},
        ),
        migrations.AddIndex(
            model_name='favoriteuser',
            index=models.Index(fields=['user', 'favorite_user'], name='main_favori_user_id_114ead_idx'),
        ),
        migrations.AlterUniqueTogether(
            name='favoriteuser',
            unique_together={('user', 'favorite_user')},
        ),
    ]
