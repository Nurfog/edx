"""
Django Admin for Notifications
"""

from django.contrib import admin

from .models import CourseNotificationPreference, Notification


class NotificationAdmin(admin.ModelAdmin):
    """
    Admin for Notifications
    """
    raw_id_fields = ('user',)


class CourseNotificationPreferenceAdmin(admin.ModelAdmin):
    """
    Admin for Course Notification Preferences
    """
    model = CourseNotificationPreference
    raw_id_fields = ('user',)
    list_display = ['get_username', 'course_id', 'notification_preference_config']

    @admin.display(description='Username', ordering='user__username')
    def get_username(self, obj):
        return obj.user.username


admin.site.register(Notification, NotificationAdmin)
admin.site.register(CourseNotificationPreference, CourseNotificationPreferenceAdmin)
