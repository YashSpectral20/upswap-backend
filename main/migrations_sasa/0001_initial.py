# Generated by Django 3.2.25 on 2024-09-11 11:07

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import main.models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='CustomUser',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('username', models.CharField(max_length=150, unique=True)),
                ('email', models.EmailField(max_length=255, unique=True)),
                ('name', models.CharField(max_length=255)),
                ('phone_number', models.CharField(max_length=15, unique=True)),
                ('country_code', models.CharField(blank=True, default='', max_length=10)),
                ('dial_code', models.CharField(blank=True, default='', max_length=10)),
                ('country', models.CharField(blank=True, default='', max_length=100)),
                ('date_of_birth', models.DateField(blank=True, null=True)),
                ('gender', models.CharField(blank=True, choices=[('M', 'Male'), ('F', 'Female'), ('O', 'Other')], max_length=10, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_staff', models.BooleanField(default=False)),
                ('is_admin', models.BooleanField(default=False)),
                ('otp_verified', models.BooleanField(default=False)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.Group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.Permission', verbose_name='user permissions')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Activity',
            fields=[
                ('activity_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('activity_title', models.CharField(max_length=50)),
                ('activity_description', models.TextField()),
                ('activity_type', models.CharField(choices=[('TECH_GAMING', 'Tech and Gaming'), ('VOLUNTEER_OPPORTUNITIES', 'Volunteer Opportunities'), ('CULTURAL_EXCHANGES', 'Cultural Exchanges'), ('INTELLECTUAL_PURSUITS', 'Intellectual Pursuits'), ('SPORTS_RECREATION', 'Sports and Recreation'), ('ARTS_CRAFTS', 'Arts and Crafts'), ('SOCIAL_GATHERINGS', 'Social Gatherings'), ('EDUCATIONAL_WORKSHOPS', 'Educational Workshops'), ('MUSIC_ENTERTAINMENT', 'Music and Entertainment'), ('OTHERS', 'Others')], max_length=50)),
                ('user_participation', models.BooleanField(default=True)),
                ('maximum_participants', models.IntegerField(default=0)),
                ('start_date', models.DateField(blank=True, null=True)),
                ('end_date', models.DateField(blank=True, null=True)),
                ('start_time', models.TimeField(blank=True, null=True)),
                ('end_time', models.TimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('infinite_time', models.BooleanField(default=True)),
                ('set_current_datetime', models.BooleanField(default=False)),
                ('images', models.JSONField(blank=True, default=list, help_text='List of image paths')),
                ('location', models.CharField(blank=True, help_text='Optional description of the location', max_length=255, null=True)),
                ('latitude', models.DecimalField(blank=True, decimal_places=6, help_text='Latitude of the location', max_digits=9, null=True)),
                ('longitude', models.DecimalField(blank=True, decimal_places=6, help_text='Longitude of the location', max_digits=9, null=True)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='VendorKYC',
            fields=[
                ('vendor_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('profile_pic', models.ImageField(blank=True, null=True, upload_to='vendor_profile_pics/')),
                ('full_name', models.CharField(max_length=255)),
                ('phone_number', models.CharField(blank=True, max_length=15)),
                ('business_email_id', models.EmailField(blank=True, max_length=255)),
                ('business_establishment_year', models.IntegerField()),
                ('business_description', models.TextField()),
                ('upload_business_related_documents', models.FileField(blank=True, null=True, upload_to='business_documents/')),
                ('same_as_personal_phone_number', models.BooleanField(default=False)),
                ('same_as_personal_email_id', models.BooleanField(default=False)),
                ('business_related_documents', models.JSONField(blank=True, default=list, help_text='List of document paths')),
                ('business_related_photos', models.JSONField(blank=True, default=list, help_text='List of photo paths')),
                ('house_no_building_name', models.CharField(blank=True, max_length=255)),
                ('road_name_area_colony', models.CharField(blank=True, max_length=255)),
                ('country', models.CharField(blank=True, max_length=100)),
                ('state', models.CharField(blank=True, max_length=100)),
                ('city', models.CharField(blank=True, max_length=100)),
                ('pincode', models.CharField(blank=True, max_length=10)),
                ('bank_account_number', models.CharField(blank=True, default='', max_length=50)),
                ('retype_bank_account_number', models.CharField(blank=True, default='', max_length=50)),
                ('bank_name', models.CharField(blank=True, default='', max_length=100)),
                ('ifsc_code', models.CharField(blank=True, default='', max_length=20)),
                ('item_name', models.CharField(max_length=255)),
                ('chosen_item_category', models.CharField(choices=[('Restaurants', 'Restaurants'), ('Consultants', 'Consultants'), ('Estate Agents', 'Estate Agents'), ('Rent & Hire', 'Rent Hire'), ('Dentist', 'Dentist'), ('Personal Care', 'Personal Care'), ('Food', 'Food'), ('Bakery', 'Bakery'), ('Groceries', 'Groceries'), ('Others', 'Others')], max_length=50)),
                ('item_description', models.TextField()),
                ('item_price', models.DecimalField(decimal_places=2, default=0.0, max_digits=10)),
                ('business_hours', models.JSONField(blank=True, default=dict, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='OTP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('otp', models.CharField(max_length=6)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField()),
                ('is_verified', models.BooleanField(default=False)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='ChatRoom',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('activity', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.activity')),
                ('participants', models.ManyToManyField(to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='ChatRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_accepted', models.BooleanField(default=False)),
                ('is_rejected', models.BooleanField(default=False)),
                ('interested', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('activity', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.activity')),
                ('from_user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sent_requests', to=settings.AUTH_USER_MODEL)),
                ('to_user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='received_requests', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='ChatMessage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('content', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('chat_room', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='messages', to='main.chatroom')),
                ('sender', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sent_messages', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='BusinessPhoto',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('photo', models.ImageField(upload_to='business_photos/')),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
                ('vendor_kyc', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='business_photos', to='main.vendorkyc')),
            ],
        ),
        migrations.CreateModel(
            name='BusinessDocument',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('document', models.FileField(upload_to='business_documents/', validators=[main.models.validate_file_type])),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
                ('vendor_kyc', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='business_documents', to='main.vendorkyc')),
            ],
        ),
        migrations.CreateModel(
            name='ActivityImage',
            fields=[
                ('image_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('image', models.ImageField(upload_to='activity_images/')),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
                ('activity', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='activity_images', to='main.activity')),
            ],
        ),
    ]