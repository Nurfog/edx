"""
LTI Provider API endpoint urls.
"""

from django.conf import settings
from django.conf.urls import patterns, url

urlpatterns = patterns(
    '',

    url(r'^courses/{}/{}$'.format(settings.COURSE_ID_PATTERN, settings.USAGE_ID_PATTERN),
        'lti_provider.views.lti_launch', name="lti_provider_launch"),
    url(r'^lti_run$', 'lti_provider.views.lti_run', name="lti_provider_run"),
)
