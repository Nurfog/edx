"""
Tests for waffle utils views.
"""
from django.test import TestCase
from edx_toggles.toggles import (
    LegacyWaffleFlag,
    LegacyWaffleFlagNamespace,
    SettingDictToggle,
    SettingToggle
)
from rest_framework.test import APIRequestFactory

from common.djangoapps.student.tests.factories import UserFactory

from .. import models
from .. import views as toggle_state_views

TEST_WAFFLE_FLAG_NAMESPACE = LegacyWaffleFlagNamespace("test")
TEST_WAFFLE_FLAG = LegacyWaffleFlag(TEST_WAFFLE_FLAG_NAMESPACE, "flag", __name__)


class ToggleStateViewTests(TestCase):  # lint-amnesty, pylint: disable=missing-class-docstring
    """
    Tests for the toggle state report view.
    """

    def test_success_for_staff(self):
        response = get_toggle_state_response()
        assert response.status_code == 200
        assert response.data

    def test_failure_for_non_staff(self):
        response = get_toggle_state_response(is_staff=False)
        assert response.status_code == 403

    def test_response_with_existing_setting_dict_toggle(self):
        response = get_toggle_state_response()
        assert {
            "name": "FEATURES['MILESTONES_APP']",
            "is_active": True,
            "module": "common.djangoapps.util.milestones_helpers",
            "class": "SettingDictToggle",
        } in response.data["django_settings"]

    def test_course_overrides(self):
        models.WaffleFlagCourseOverrideModel.objects.create(waffle_flag="my.flag", enabled=True)
        course_overrides = {}

        report = toggle_state_views.CourseOverrideToggleStateReport()
        report.add_waffle_flag_instances(course_overrides)
        report.add_waffle_flag_computed_status(course_overrides)

        assert 'my.flag' in course_overrides
        assert 'course_overrides' in course_overrides['my.flag']
        assert 1 == len(course_overrides['my.flag']['course_overrides'])
        assert 'None' == course_overrides['my.flag']['course_overrides'][0]['course_id']
        assert 'on' == course_overrides['my.flag']['course_overrides'][0]['force']
        assert 'both' == course_overrides['my.flag']['computed_status']

    def test_computed_status(self):
        models.WaffleFlagCourseOverrideModel.objects.create(
            waffle_flag="my.overriddenflag1", enabled=True, course_id="org/course/id"
        )
        models.WaffleFlagCourseOverrideModel.objects.create(
            waffle_flag="my.overriddenflag2", enabled=True
        )
        models.WaffleFlagCourseOverrideModel.objects.create(
            waffle_flag="my.disabledflag1", enabled=False, course_id="org/course/id"
        )

        course_overrides = {}
        report = toggle_state_views.CourseOverrideToggleStateReport()
        report.add_waffle_flag_instances(course_overrides)
        report.add_waffle_flag_computed_status(course_overrides)

        assert "both" == course_overrides["my.overriddenflag1"]["computed_status"]
        assert "org/course/id" == course_overrides["my.overriddenflag1"]["course_overrides"][0]["course_id"]
        assert "on" == course_overrides["my.overriddenflag1"]["course_overrides"][0]["force"]

        assert "both" == course_overrides["my.overriddenflag2"]["computed_status"]
        assert "None" == course_overrides["my.overriddenflag2"]["course_overrides"][0]["course_id"]
        assert "on" == course_overrides["my.overriddenflag2"]["course_overrides"][0]["force"]

        assert "my.disabledflag1" not in course_overrides


def get_toggle_state_response(is_staff=True):
    """
    Query the toggle state API endpoint.
    """
    request = APIRequestFactory().get('/api/toggles/state/')
    request.user = UserFactory(is_staff=is_staff)
    view = toggle_state_views.ToggleStateView.as_view()
    response = view(request)
    return response
