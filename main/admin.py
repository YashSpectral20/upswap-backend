from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, Activity, ActivityImage
from django.core.exceptions import ValidationError

class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('username', 'email', 'phone_number', 'date_of_birth', 'gender', 'is_staff', 'is_active',)
    list_filter = ('is_staff', 'is_active',)
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('name', 'email', 'phone_number', 'date_of_birth', 'gender')}),
        ('Permissions', {'fields': ('is_staff', 'is_active')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'phone_number', 'date_of_birth', 'gender', 'password1', 'password2', 'is_staff', 'is_active')}
        ),
    )
    search_fields = ('username', 'email', 'phone_number')
    ordering = ('username',)

admin.site.register(CustomUser, CustomUserAdmin)

# Activity Admin
@admin.register(Activity)
class ActivityAdmin(admin.ModelAdmin):
    list_display = ['activity_id', 'created_by', 'activity_title', 'activity_type', 'user_participation', 'max_participations_display', 'start_date', 'end_date', 'start_time', 'end_time', 'infinite_time', 'created_at']
    readonly_fields = ['activity_id', 'created_by']
    list_filter = ('activity_type', 'infinite_time')

    def save_model(self, request, obj, form, change):
        try:
            obj.clean()  # Ensure model's clean method is called for validation
        except ValidationError as e:
            form._errors[NON_FIELD_ERRORS] = form.error_class([str(e)])
            return
        super().save_model(request, obj, form, change)
    
    def max_participations_display(self, obj):
        return obj.maximum_participants if obj.user_participation else 0
    max_participations_display.short_description = 'Max Participations'

class ActivityImageAdmin(admin.ModelAdmin):
    list_display = ('id', 'activity', 'upload_image')
    search_fields = ('activity__title',)
    list_filter = ('activity__activity_type',)
    readonly_fields = ('id',)

admin.site.register(ActivityImage, ActivityImageAdmin)
