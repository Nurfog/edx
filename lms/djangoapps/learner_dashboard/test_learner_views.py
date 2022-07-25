"""Test for learner views and related functions"""

import json
import ddt

from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

from django.urls import reverse
from lms.djangoapps.learner_dashboard.test_serializers import random_url
from rest_framework.test import APITestCase

from lms.djangoapps.learner_dashboard.learner_views import (
    get_platform_settings,
    get_user_account_confirmation_info,
)
from common.djangoapps.student.tests.factories import UserFactory
from xmodule.modulestore.tests.django_utils import (
    TEST_DATA_SPLIT_MODULESTORE,
    SharedModuleStoreTestCase,
)
from xmodule.modulestore.tests.factories import CourseFactory


class TestGetPlatformSettings(TestCase):
    """Tests for get_platform_settings"""

    MOCK_SETTINGS = {
        "DEFAULT_FEEDBACK_EMAIL": f"{uuid4()}@example.com",
        "PAYMENT_SUPPORT_EMAIL": f"{uuid4()}@example.com",
    }

    @patch.multiple("django.conf.settings", **MOCK_SETTINGS)
    @patch("lms.djangoapps.learner_dashboard.learner_views.marketing_link")
    def test_happy_path(self, mock_marketing_link):
        # Given email/search info exists
        mock_marketing_link.return_value = mock_search_url = f"/{uuid4()}"

        # When I request those settings
        return_data = get_platform_settings()

        # Then I return them in the appropriate format
        self.assertDictEqual(
            return_data,
            {
                "supportEmail": self.MOCK_SETTINGS["DEFAULT_FEEDBACK_EMAIL"],
                "billingEmail": self.MOCK_SETTINGS["PAYMENT_SUPPORT_EMAIL"],
                "courseSearchUrl": mock_search_url,
            },
        )


@ddt.ddt
class TestGetUserAccountConfirmationInfo(SharedModuleStoreTestCase):
    """Tests for get_user_account_confirmation_info"""

    MOCK_SETTINGS = {
        "ACTIVATION_EMAIL_SUPPORT_LINK": "activation.example.com",
        "SUPPORT_SITE_LINK": "support.example.com",
    }

    @classmethod
    def mock_response(self):
        return {
            "isNeeded": False,
            "sendEmailUrl": random_url(),
        }

    def setUp(self):
        super().setUp()
        self.user = UserFactory()

    @patch.multiple("django.conf.settings", **MOCK_SETTINGS)
    @ddt.data(True, False)
    def test_is_needed(self, user_is_active):
        """Email confirmation is needed when the user is not active"""
        self.user.is_active = user_is_active

        user_account_confirmation_info = get_user_account_confirmation_info(self.user)

        assert user_account_confirmation_info["isNeeded"] == (not user_is_active)

    @patch(
        "django.conf.settings.ACTIVATION_EMAIL_SUPPORT_LINK",
        "example.com/activate-email",
    )
    def test_email_url_support_link(self):
        # Given an ACTIVATION_EMAIL_SUPPORT_LINK is supplied
        # When I get user account confirmation info
        user_account_confirmation_info = get_user_account_confirmation_info(self.user)

        # Then that link should be returned as the sendEmailUrl
        assert (
            user_account_confirmation_info["sendEmailUrl"]
            == "example.com/activate-email"
        )

    @patch("lms.djangoapps.learner_dashboard.learner_views.configuration_helpers")
    @patch("django.conf.settings.SUPPORT_SITE_LINK", "example.com/support")
    def test_email_url_support_link(self, mock_config_helpers):
        # Given an ACTIVATION_EMAIL_SUPPORT_LINK is NOT supplied
        mock_config_helpers.get_value.return_value = None

        # When I get user account confirmation info
        user_account_confirmation_info = get_user_account_confirmation_info(self.user)

        # Then sendEmailUrl falls back to SUPPORT_SITE_LINK
        assert user_account_confirmation_info["sendEmailUrl"] == "example.com/support"


class TestDashboardView(SharedModuleStoreTestCase, APITestCase):
    """Tests for the dashboard view"""

    MODULESTORE = TEST_DATA_SPLIT_MODULESTORE

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # Get view URL
        cls.view_url = reverse("dashboard_view")

        # Set up a course
        cls.course = CourseFactory.create()
        cls.course_key = cls.course.location.course_key

        # Set up a user
        cls.username = "alan"
        cls.password = "enigma"
        cls.user = UserFactory(username=cls.username, password=cls.password)

    def log_in(self):
        """Log in as a test user"""
        self.client.login(username=self.username, password=self.password)

    def setUp(self):
        super().setUp()
        self.log_in()

    def test_response_structure(self):
        """Basic test for correct response structure"""

        # Given I am logged in
        self.log_in()

        # When I request the dashboard
        response = self.client.get(self.view_url)

        # Then I get the expected success response
        assert response.status_code == 200

        response_data = json.loads(response.content)
        expected_keys = set(
            [
                "emailConfirmation",
                "enterpriseDashboards",
                "platformSettings",
                "enrollments",
                "unfulfilledEntitlements",
                "suggestedCourses",
            ]
        )

        assert expected_keys == response_data.keys()

    @patch("lms.djangoapps.learner_dashboard.learner_views.get_user_account_confirmation_info")
    def test_mocked(self, mock_user_conf_info):
        """High level tests with mocked data"""

        # Given I am logged in
        self.log_in()

        # (and we have tons of mocks to avoid integration tests)
        mock_user_conf_info_response = (
            TestGetUserAccountConfirmationInfo.mock_response()
        )
        mock_user_conf_info.return_value = mock_user_conf_info_response

        # When I request the dashboard
        response = self.client.get(self.view_url)

        # Then I get the expected success response
        assert response.status_code == 200
        response_data = json.loads(response.content)

        self.assertDictEqual(
            response_data["emailConfirmation"],
            {
                "isNeeded": mock_user_conf_info_response["isNeeded"],
                "sendEmailUrl": mock_user_conf_info_response["sendEmailUrl"],
            },
        )
