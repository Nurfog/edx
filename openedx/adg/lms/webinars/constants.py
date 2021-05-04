"""
Constants for webinars app
"""
from django.utils.translation import gettext_lazy as _

ALLOWED_BANNER_EXTENSIONS = ('png', 'jpg', 'jpeg', 'svg')
BANNER_MAX_SIZE = 2 * 1024 * 1024

STARTING_SOON_REMINDER_ID_FIELD_NAME = 'starting_soon_mandrill_reminder_id'
ONE_WEEK_REMINDER_ID_FIELD_NAME = 'week_before_mandrill_reminder_id'

WEBINAR_STATUS_CANCELLED = _('Cancelled')
WEBINAR_STATUS_DELIVERED = _('Delivered')
WEBINAR_STATUS_UPCOMING = _('Upcoming')

WEBINARS_TIME_FORMAT = '%B %d, %Y %I:%M %p %Z'
