"""
Tests for toggles, where there is logic beyond enable/disable.
"""

from unittest.mock import patch
import ddt

from django.test import override_settings

from common.djangoapps.student.tests.factories import UserFactory
from lms.djangoapps.learner_home.waffle import should_redirect_to_learner_home_mfe
from xmodule.modulestore.tests.django_utils import SharedModuleStoreTestCase


@ddt.ddt
class TestLearnerHomeRedirect(SharedModuleStoreTestCase):
    """
    Tests for should_redirect_to_learner_home, used for experimental rollout.
    """

    def setUp(self):
        super().setUp()

        # Set up a user for testing
        self.user = UserFactory

    @patch("lms.djangoapps.learner_home.waffle.ENABLE_LEARNER_HOME_MFE")
    def test_should_redirect_to_learner_home_disabled(self, mock_enable_learner_home):
        # Given Learner Home MFE feature is not enabled
        mock_enable_learner_home.is_enabled.return_value = False

        # When I check if I should redirect
        redirect_choice = should_redirect_to_learner_home_mfe()

        # Then I never redirect
        self.assertFalse(redirect_choice)

    @patch("lms.djangoapps.learner_home.waffle.ENABLE_LEARNER_HOME_MFE")
    def test_should_redirect_to_learner_home_enabled(self, mock_enable_learner_home):
        # Given Learner Home MFE feature is enabled
        mock_enable_learner_home.is_enabled.return_value = True

        # When I check if I should redirect
        redirect_choice = should_redirect_to_learner_home_mfe()

        # Then I redirect based on configuration
        # (currently user ID % 100 < redirect percentage)
        self.assertEqual(mock_enable_learner_home, redirect_choice)
