"""
Views to manage the Survey Reports.
"""


from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.generic import View
from .tasks import generate_survey_report
from .api import send_report_to_external_api


class SurveyReportView(View):
    """
    View for Survey Reports.
    """
    @method_decorator(login_required)
    @method_decorator(ensure_csrf_cookie)
    def post(self, _request):
        """
        Generate a new survey report using the generate_report method in api.py
        Arguments:
            _request: HTTP request
        """
        generate_survey_report.delay()
        return redirect("admin:survey_report_surveyreport_changelist")


class SurveyReportUpload(View):
    """
    View for send Survey Reports.
    """
    @method_decorator(login_required)
    def get(self, _request, report_id):
        """
        Send
        """
        send_report_to_external_api(report_id=report_id)
        return redirect("admin:survey_report_surveyreport_changelist")
