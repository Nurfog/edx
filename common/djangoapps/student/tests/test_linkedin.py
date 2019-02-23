# -*- coding: utf-8 -*-
"""Tests for LinkedIn Add to Profile configuration. """
from urllib.parse import quote, urlencode

import ddt
from django.conf import settings
from django.test import TestCase
from opaque_keys.edx.locator import CourseLocator

from openedx.core.djangoapps.site_configuration.tests.test_util import with_site_configuration_context
from student.models import LinkedInAddToProfileConfiguration


@ddt.ddt
class LinkedInAddToProfileUrlTests(TestCase):
    """Tests for URL generation of LinkedInAddToProfileConfig. """

    COURSE_KEY = CourseLocator(org="edx", course="DemoX", run="Demo_Course")
    COURSE_NAME = "Test Course ☃"
    CERT_URL = "http://s3.edx/cert"
    SITE_CONFIGURATION = {
        'SOCIAL_SHARING_SETTINGS': {
            'CERTIFICATE_LINKEDIN_MODE_TO_CERT_NAME': {
                'honor': '{platform_name} Honor Code Credential for {course_name}',
                'verified': '{platform_name} Verified Credential for {course_name}',
                'professional': '{platform_name} Professional Credential for {course_name}',
                'no-id-professional': '{platform_name} Professional Credential for {course_name}',
            }
        }
    }

    @ddt.data(
        ('honor', 'Honor+Code+Certificate+for+Test+Course+%E2%98%83'),
        ('verified', 'Verified+Certificate+for+Test+Course+%E2%98%83'),
        ('professional', 'Professional+Certificate+for+Test+Course+%E2%98%83'),
        ('default_mode', 'Certificate+for+Test+Course+%E2%98%83')
    )
    @ddt.unpack
    def test_linked_in_url(self, cert_mode, expected_cert_name):
        config = LinkedInAddToProfileConfiguration(
            company_identifier='0_mC_o2MizqdtZEmkVXjH4eYwMj4DnkCWrZP_D9',
            enabled=True
        )

        expected_url = (
            'http://www.linkedin.com/profile/add'
            '?_ed=0_mC_o2MizqdtZEmkVXjH4eYwMj4DnkCWrZP_D9&'
            'pfCertificationName={platform_name}+{expected_cert_name}&'
            'pfCertificationUrl=http%3A%2F%2Fs3.edx%2Fcert&'
            'source=o'
        ).format(
            expected_cert_name=expected_cert_name,
            platform_name=quote(settings.PLATFORM_NAME.encode('utf-8'))
        )

        actual_url = config.add_to_profile_url(
            self.COURSE_KEY,
            self.COURSE_NAME,
            cert_mode,
            self.CERT_URL
        )

        self.assertEqual(actual_url, expected_url)

    @ddt.data(
        ('honor', 'Honor+Code+Credential+for+Test+Course+%E2%98%83'),
        ('verified', 'Verified+Credential+for+Test+Course+%E2%98%83'),
        ('professional', 'Professional+Credential+for+Test+Course+%E2%98%83'),
        ('no-id-professional', 'Professional+Credential+for+Test+Course+%E2%98%83'),
        ('default_mode', 'Certificate+for+Test+Course+%E2%98%83')
    )
    @ddt.unpack
    def test_linked_in_url_with_cert_name_override(self, cert_mode, expected_cert_name):
        config = LinkedInAddToProfileConfiguration(
            company_identifier='0_mC_o2MizqdtZEmkVXjH4eYwMj4DnkCWrZP_D9',
            enabled=True
        )

        expected_url = (
            'http://www.linkedin.com/profile/add'
            '?_ed=0_mC_o2MizqdtZEmkVXjH4eYwMj4DnkCWrZP_D9&'
            'pfCertificationName={platform_name}+{expected_cert_name}&'
            'pfCertificationUrl=http%3A%2F%2Fs3.edx%2Fcert&'
            'source=o'
        ).format(
            expected_cert_name=expected_cert_name,
            platform_name=quote(settings.PLATFORM_NAME.encode('utf-8'))
        )

        with with_site_configuration_context(configuration=self.SITE_CONFIGURATION):
            actual_url = config.add_to_profile_url(
                self.COURSE_KEY,
                self.COURSE_NAME,
                cert_mode,
                self.CERT_URL
            )

            self.assertEqual(actual_url, expected_url)

    def test_linked_in_url_tracking_code(self):
        config = LinkedInAddToProfileConfiguration(
            company_identifier="abcd123",
            trk_partner_name="edx",
            enabled=True
        )

        expected_param = urlencode({
            'trk': 'edx-{course_key}_honor-dashboard'.format(
                course_key=self.COURSE_KEY
            )
        })

        actual_url = config.add_to_profile_url(
            self.COURSE_KEY,
            self.COURSE_NAME,
            'honor',
            self.CERT_URL
        )

        self.assertIn(expected_param, actual_url)
