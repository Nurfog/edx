"""
URLs for Enhanced Staff Grader (ESG) backend-for-frontend (BFF)
"""

from django.urls.conf import path

from lms.djangoapps.ora_staff_grader.views import InitializeView


urlpatterns = []

urlpatterns += [
    path(
        'initialize', InitializeView.as_view(), name='initialize'
    ),
]