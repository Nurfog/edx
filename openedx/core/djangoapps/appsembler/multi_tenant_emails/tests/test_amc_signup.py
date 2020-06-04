import json
from unittest import skipUnless
from mock import patch
import uuid

from django.conf import settings
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from openedx.core.djangolib.testing.utils import skip_unless_lms

from .test_utils import with_organization_context


@skip_unless_lms
@skipUnless(settings.FEATURES['APPSEMBLER_MULTI_TENANT_EMAILS'], 'This only tests multi-tenancy')
@patch(
    # Patch to avoids error when importing from CMS
    'student.views.management.add_course_creator_role'
)
class MultiTenantAMCSignupTest(APITestCase):
    """
    Tests to ensure the AMC registration end-point allow multi-tenant emails.
    """

    EMAIL = 'ali@example.com'
    PASSWORD = 'zzz'

    def setUp(self):
        super(MultiTenantAMCSignupTest, self).setUp()
        self.registration_url = reverse('user_api_registration')
        self.site_creation_url = reverse('tahoe_site_creation')

    def register_learner(self, email, username):
        response = self.client.post(self.registration_url, {
            'email': email,
            'name': 'Ali',
            'username': username,
            'password': self.PASSWORD,
            'honor_code': 'true',
        })
        assert response.status_code == status.HTTP_200_OK, '{}: {}'.format(username, response.content)
        return response

    def trial_step_1_admin_user(self, color, email, username):
        """
        Match the segmented trial workflow steps for AMC: Step 1 for SetPasswordView.
        """
        user_params = {  # Imitating AMC calling to the LMS user_api_registration endpoint.
            'email': email,
            'name': username,
            'username': username,
            'password': self.PASSWORD,
            'registered_from_amc': 'True',
            'terms_of_service': 'True',
            'honor_code': 'True',
        }
        return self.client.post(self.registration_url, user_params)

    def trial_step_2_site_configuration(self, color, username):
        """
        Match the segmented trial workflow steps for AMC: Step 2 for MicrositeCreateView.
        """
        site_params = {  # Imitating AMC calling to the LMS tahoe_site_creation endpoint.
            'username': username,
            'user_email': 'something@example.com',  # Now ignored by the lms in favor of the `username`.
            'site': {
                'name': color,
                'domain': color,
            },
            'organization': {
                'edx_uuid': str(uuid.uuid4()),
                'name': color,
                'short_name': color,
            },
            'initial_values': {
                'platform_name': 'may31 site',
            },
        }

        with patch('openedx.core.djangoapps.appsembler.sites.api.SiteCreateView.permission_classes', []):
            return self.client.post(self.site_creation_url, json.dumps(site_params), content_type='application/json')

    def register_new_amc_admin(self, color, email):
        username = 'ali_{}'.format(color)
        user_response = self.trial_step_1_admin_user(color, email, username)
        assert user_response.status_code == status.HTTP_200_OK, '{}: {}'.format(color, user_response.content)

        site_response = self.trial_step_2_site_configuration(color, username)
        assert site_response.status_code == status.HTTP_201_CREATED, '{}: {}'.format(color, site_response.content)
        return user_response, site_response

    def test_new_admin_with_learner(self, mock_add_creator):
        """
        Test happy scenario regardless of APPSEMBLER_MULTI_TENANT_EMAILS.
        """
        red_site = 'red1'
        self.register_new_amc_admin(red_site, self.EMAIL)
        red_site_admin = User.objects.get(email=self.EMAIL)
        mock_add_creator.assert_called_once_with(red_site_admin)

        with with_organization_context(site_color=red_site):
            self.register_learner('learner@example.com', 'learner')

    def test_learner_registers_for_trial(self, mock_add_creator):
        """
        Test learner registers for a new Tahoe trial signup when APPSEMBLER_MULTI_TENANT_EMAILS is enabled.
        """
        learner = 'learner@example.com'
        with with_organization_context(site_color='red1'):
            self.register_learner(learner, 'learner')

        self.register_new_amc_admin(color='blue', email=learner)
        assert mock_add_creator.call_count == 1
