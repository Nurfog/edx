"""Tests for serializers for the Learner Dashboard"""

import datetime
from random import choice, getrandbits, randint
from time import time
from unittest import TestCase
from unittest import mock
from uuid import uuid4
from common.djangoapps.course_modes.models import CourseMode
from common.djangoapps.course_modes.tests.factories import CourseModeFactory
from common.djangoapps.student.tests.factories import (
    CourseEnrollmentFactory,
    UserFactory,
)

from lms.djangoapps.learner_dashboard.serializers import (
    CertificateSerializer,
    CourseProviderSerializer,
    CourseRunSerializer,
    CourseSerializer,
    EmailConfirmationSerializer,
    EnrollmentSerializer,
    EnterpriseDashboardsSerializer,
    EntitlementSerializer,
    GradeDataSerializer,
    LearnerEnrollmentSerializer,
    PlatformSettingsSerializer,
    ProgramsSerializer,
    LearnerDashboardSerializer,
    SuggestedCourseSerializer,
    UnfulfilledEntitlementSerializer,
)
from xmodule.modulestore.tests.django_utils import SharedModuleStoreTestCase
from xmodule.modulestore.tests.factories import CourseFactory


def random_bool():
    """Test util for generating a random boolean"""
    return bool(getrandbits(1))


def random_date(allow_null=False):
    """Test util for generating a random date, optionally blank"""

    # If null allowed, return null half the time
    if allow_null and random_bool():
        return None

    d = randint(1, int(time()))
    return datetime.datetime.fromtimestamp(d, tz=datetime.timezone.utc)


def random_url(allow_null=False):
    """Test util for generating a random URL, optionally blank"""

    # If null allowed, return null half the time
    if allow_null and random_bool():
        return None

    random_uuid = uuid4()
    return choice([f"{random_uuid}.example.com", f"example.com/{random_uuid}"])


def random_grade():
    """Return a random grade (0-100) with 2 decimal places of padding"""
    return randint(0, 10000) / 100


def decimal_to_grade_format(decimal):
    """Util for matching serialized grade format, pads a decimal to 2 places"""
    return "{:.2f}".format(decimal)


def datetime_to_django_format(datetime_obj):
    """Util for matching serialized Django datetime format for comparison"""
    if datetime_obj:
        return datetime_obj.strftime("%Y-%m-%dT%H:%M:%SZ")


class TestPlatformSettingsSerializer(TestCase):
    """Tests for the PlatformSettingsSerializer"""

    @classmethod
    def generate_test_platform_settings(cls):
        """Util to generate test platform settings data"""
        return {
            "feedbackEmail": f"{uuid4()}@example.com",
            "supportEmail": f"{uuid4()}@example.com",
            "billingEmail": f"{uuid4()}@example.com",
            "courseSearchUrl": f"{uuid4()}.example.com/search",
        }

    def test_happy_path(self):
        input_data = self.generate_test_platform_settings()
        output_data = PlatformSettingsSerializer(input_data).data

        assert output_data == {
            "supportEmail": input_data["supportEmail"],
            "billingEmail": input_data["billingEmail"],
            "courseSearchUrl": input_data["courseSearchUrl"],
        }


class TestCourseProviderSerializer(TestCase):
    """Tests for the CourseProviderSerializer"""

    @classmethod
    def generate_test_provider_info(cls):
        """Util to generate test provider info"""
        return {
            "name": f"{uuid4()}",
            "website": f"{uuid4()}.example.com",
            "email": f"{uuid4()}@example.com",
        }

    def test_happy_path(self):
        input_data = self.generate_test_provider_info()
        output_data = CourseProviderSerializer(input_data).data

        assert output_data == {
            "name": input_data["name"],
            "website": input_data["website"],
            "email": input_data["email"],
        }


class TestCourseSerializer(TestCase):
    """Tests for the CourseSerializer"""

    @classmethod
    def generate_test_course_info(cls):
        """Util to generate test course info"""
        return {
            "bannerImgSrc": f"example.com/assets/{uuid4()}",
            "courseName": f"{uuid4()}",
        }

    def test_happy_path(self):
        input_data = self.generate_test_course_info()
        output_data = CourseSerializer(input_data).data

        assert output_data == {
            "bannerImgSrc": input_data["bannerImgSrc"],
            "courseName": input_data["courseName"],
        }


class TestCourseRunSerializer(SharedModuleStoreTestCase):
    """Tests for the CourseRunSerializer"""

    @classmethod
    def generate_test_course_run_info(cls):
        """Util to generate test course run info"""
        return {
            "isStarted": random_bool(),
            "isArchived": random_bool(),
            "courseNumber": f"{uuid4()}-101",
            "accessExpirationDate": random_date(),
            "minPassingGrade": random_grade(),
            "endDate": random_date(),
            "homeUrl": f"{uuid4()}.example.com",
            "marketingUrl": f"{uuid4()}.example.com",
            "progressUrl": f"{uuid4()}.example.com",
            "unenrollUrl": f"{uuid4()}.example.com",
            "upgradeUrl": f"{uuid4()}.example.com",
            "resumeUrl": random_url(),
        }

    def setUp(self):
        """Create a test enrollment & data"""
        self.user = UserFactory()

        self.course = CourseFactory(self_paced=True)
        CourseModeFactory(
            course_id=self.course.id,
            mode_slug=CourseMode.AUDIT,
        )

        self.test_enrollment = CourseEnrollmentFactory(
            course_id=self.course.id, mode=CourseMode.AUDIT
        )

        # Add extra info to exercise serialization
        self.test_enrollment.course_overview.marketing_url = random_url()
        self.test_enrollment.course_overview.end = random_date()

    def test_with_data(self):
        input_data = self.test_enrollment
        input_context = {
            "resume_course_urls": {self.course.id: random_url()},
            "ecommerce_payment_page": random_url(),
            "course_mode_info": {
                self.course.id: {
                    "verified_sku": str(uuid4()),
                    "days_for_upsell": randint(0, 14),
                }
            },
        }

        serializer = CourseRunSerializer(input_data, context=input_context)
        output = serializer.data

        # Serializaiton set up so all fields will have values to make testing easy
        for key in output:
            assert output[key] is not None


class TestEnrollmentSerializer(TestCase):
    """Tests for the EnrollmentSerializer"""

    @classmethod
    def generate_test_enrollment_info(cls):
        """Util to generate test enrollment info"""
        return {
            "isAudit": random_bool(),
            "isVerified": random_bool(),
            "canUpgrade": random_bool(),
            "isAuditAccessExpired": random_bool(),
            "isEmailEnabled": random_bool(),
            "lastEnrolled": random_date(),
            "isEnrolled": random_bool(),
        }

    def test_happy_path(self):
        input_data = self.generate_test_enrollment_info()
        output_data = EnrollmentSerializer(input_data).data

        self.assertDictEqual(
            output_data,
            {
                "isAudit": input_data["isAudit"],
                "isVerified": input_data["isVerified"],
                "canUpgrade": input_data["canUpgrade"],
                "isAuditAccessExpired": input_data["isAuditAccessExpired"],
                "isEmailEnabled": input_data["isEmailEnabled"],
                "lastEnrolled": datetime_to_django_format(input_data["lastEnrolled"]),
                "isEnrolled": input_data["isEnrolled"],
            },
        )


class TestGradeDataSerializer(TestCase):
    """Tests for the GradeDataSerializer"""

    @classmethod
    def generate_test_grade_data(cls):
        """Util to generate test grade data"""
        return {
            "isPassing": random_bool(),
        }

    def test_happy_path(self):
        input_data = self.generate_test_grade_data()
        output_data = GradeDataSerializer(input_data).data

        assert output_data == {
            "isPassing": input_data["isPassing"],
        }


class TestCertificateSerializer(TestCase):
    """Tests for the CertificateSerializer"""

    @classmethod
    def generate_test_certificate_info(cls):
        """Util to generate test certificate info"""
        return {
            "availableDate": random_date(allow_null=True),
            "isRestricted": random_bool(),
            "isAvailable": random_bool(),
            "isEarned": random_bool(),
            "isDownloadable": random_bool(),
            "certPreviewUrl": random_url(allow_null=True),
            "certDownloadUrl": random_url(allow_null=True),
            "honorCertDownloadUrl": random_url(allow_null=True),
        }

    def test_happy_path(self):
        input_data = self.generate_test_certificate_info()
        output_data = CertificateSerializer(input_data).data

        assert output_data == {
            "availableDate": datetime_to_django_format(input_data["availableDate"]),
            "isRestricted": input_data["isRestricted"],
            "isAvailable": input_data["isAvailable"],
            "isEarned": input_data["isEarned"],
            "isDownloadable": input_data["isDownloadable"],
            "certPreviewUrl": input_data["certPreviewUrl"],
            "certDownloadUrl": input_data["certDownloadUrl"],
            "honorCertDownloadUrl": input_data["honorCertDownloadUrl"],
        }


class TestEntitlementSerializer(TestCase):
    """Tests for the EntitlementSerializer"""

    @classmethod
    def generate_test_session(cls):
        """Generate an test session with random dates and course run numbers"""
        return {
            "startDate": random_date(),
            "endDate": random_date(),
            "courseNumber": f"{uuid4()}-101",
        }

    @classmethod
    def generate_test_entitlement_info(cls):
        """Util to generate test entitlement info"""
        return {
            "availableSessions": [
                cls.generate_test_session() for _ in range(randint(0, 3))
            ],
            "isRefundable": random_bool(),
            "isFulfilled": random_bool(),
            "canViewCourse": random_bool(),
            "changeDeadline": random_date(),
            "isExpired": random_bool(),
            "expirationDate": random_date(),
        }

    def test_happy_path(self):
        input_data = self.generate_test_entitlement_info()
        output_data = EntitlementSerializer(input_data).data

        # Compare output sessions separately, since they're more complicated
        output_sessions = output_data.pop("availableSessions")
        for i, output_session in enumerate(output_sessions):
            input_session = input_data["availableSessions"][i]
            input_session["startDate"] = datetime_to_django_format(
                input_session["startDate"]
            )
            input_session["endDate"] = datetime_to_django_format(
                input_session["endDate"]
            )
            assert output_session == input_session

        assert output_data == {
            "isRefundable": input_data["isRefundable"],
            "isFulfilled": input_data["isFulfilled"],
            "canViewCourse": input_data["canViewCourse"],
            "changeDeadline": datetime_to_django_format(input_data["changeDeadline"]),
            "isExpired": input_data["isExpired"],
            "expirationDate": datetime_to_django_format(input_data["expirationDate"]),
        }


class TestProgramsSerializer(TestCase):
    """Tests for the ProgramsSerializer and RelatedProgramsSerializer"""

    @classmethod
    def generate_test_related_program(cls):
        """Generate a program with random test data"""
        return {
            "provider": f"{uuid4()} Inc.",
            "programUrl": random_url(),
            "bannerUrl": random_url(),
            "logoUrl": random_url(),
            "title": f"{uuid4()}",
            "programType": f"{uuid4()}",
            "programTypeUrl": random_url(),
            "numberOfCourses": randint(0, 100),
            "estimatedNumberOfWeeks": randint(0, 45),
        }

    @classmethod
    def generate_test_programs_info(cls):
        """Util to generate test programs info"""
        return {
            "relatedPrograms": [
                cls.generate_test_related_program() for _ in range(randint(0, 3))
            ],
        }

    def test_happy_path(self):
        input_data = self.generate_test_programs_info()
        output_data = ProgramsSerializer(input_data).data

        related_programs = output_data.pop("relatedPrograms")

        for i, related_program in enumerate(related_programs):
            input_program = input_data["relatedPrograms"][i]
            assert related_program == {
                "provider": input_program["provider"],
                "programUrl": input_program["programUrl"],
                "bannerUrl": input_program["bannerUrl"],
                "logoUrl": input_program["logoUrl"],
                "title": input_program["title"],
                "programType": input_program["programType"],
                "programTypeUrl": input_program["programTypeUrl"],
                "numberOfCourses": input_program["numberOfCourses"],
                "estimatedNumberOfWeeks": input_program["estimatedNumberOfWeeks"],
            }

        self.assertDictEqual(output_data, {})

    def test_empty_sessions(self):
        input_data = {"relatedPrograms": []}
        output_data = ProgramsSerializer(input_data).data

        assert output_data == {"relatedPrograms": []}


class TestLearnerEnrollmentsSerializer(SharedModuleStoreTestCase):
    """High-level tests for LearnerEnrollmentsSerializer"""

    @classmethod
    def setUpClass(cls):
        """Create a test user"""
        super().setUpClass()
        cls.user = UserFactory()

    def setUp(self):
        """Generate a test audit course and enrollment"""
        super().setUp()

        self.course = CourseFactory(self_paced=True)
        CourseModeFactory(
            course_id=self.course.id,
            mode_slug=CourseMode.AUDIT,
        )
        self.test_enrollment = CourseEnrollmentFactory(
            course_id=self.course.id, mode=CourseMode.AUDIT
        )

    @classmethod
    def generate_test_enrollments_data(cls):
        return {
            "courseProvider": TestCourseProviderSerializer.generate_test_provider_info(),
            "course": TestCourseSerializer.generate_test_course_info(),
            "courseRun": TestCourseRunSerializer.generate_test_course_run_info(),
            "enrollment": TestEnrollmentSerializer.generate_test_enrollment_info(),
            "gradeData": TestGradeDataSerializer.generate_test_grade_data(),
            "certificate": TestCertificateSerializer.generate_test_certificate_info(),
            "entitlements": TestEntitlementSerializer.generate_test_entitlement_info(),
            "programs": TestProgramsSerializer.generate_test_programs_info(),
        }

    def test_happy_path(self):
        """Test that nothing breaks and the output fields look correct"""
        input_data = self.generate_test_enrollments_data()

        enrollment = self.set_up_test_enrollment()
        input_data["courseRun"] = enrollment
        input_data["course"] = enrollment.course

        input_context = {
            "resume_course_urls": {self.course.id: random_url()},
            "ecommerce_payment_page": random_url(),
            "course_mode_info": {
                self.course.id: {
                    "verified_sku": str(uuid4()),
                    "days_for_upsell": randint(0, 14),
                }
            },
        }

        output_data = LearnerEnrollmentSerializer(
            input_data, context=input_context
        ).data

        expected_keys = [
            "courseProvider",
            "course",
            "courseRun",
            "enrollment",
            "gradeData",
            "certificate",
            "entitlements",
            "programs",
        ]
        assert output_data.keys() == set(expected_keys)


class TestUnfulfilledEntitlementSerializer(TestCase):
    """High-level tests for UnfulfilledEntitlementSerializer"""

    @classmethod
    def generate_test_entitlements_data(cls):
        return {
            "courseProvider": TestCourseProviderSerializer.generate_test_provider_info(),
            "course": TestCourseSerializer.generate_test_course_info(),
            "entitlements": TestEntitlementSerializer.generate_test_entitlement_info(),
            "programs": TestProgramsSerializer.generate_test_programs_info(),
        }

    def test_happy_path(self):
        """Test that nothing breaks and the output fields look correct"""
        input_data = self.generate_test_entitlements_data()

        output_data = UnfulfilledEntitlementSerializer(input_data).data

        expected_keys = [
            "courseProvider",
            "course",
            "entitlements",
            "programs",
        ]
        assert output_data.keys() == set(expected_keys)

    def test_allowed_empty(self):
        """Tests for allowed null fields, mostly that nothing breaks"""
        input_data = self.generate_test_entitlements_data()
        input_data["courseProvider"] = None

        output_data = UnfulfilledEntitlementSerializer(input_data).data

        expected_keys = [
            "courseProvider",
            "course",
            "entitlements",
            "programs",
        ]
        assert output_data.keys() == set(expected_keys)


class TestSuggestedCourseSerializer(TestCase):
    """High-level tests for SuggestedCourseSerializer"""

    @classmethod
    def generate_test_suggested_courses(cls):
        return {
            "bannerUrl": random_url(),
            "logoUrl": random_url(),
            "title": f"{uuid4()}",
            "courseUrl": random_url(),
        }

    def test_structure(self):
        """Test that nothing breaks and the output fields look correct"""
        input_data = self.generate_test_suggested_courses()

        output_data = SuggestedCourseSerializer(input_data).data

        expected_keys = [
            "bannerUrl",
            "logoUrl",
            "title",
            "courseUrl",
        ]
        assert output_data.keys() == set(expected_keys)

    def test_happy_path(self):
        """Test that data serializes correctly"""

        input_data = self.generate_test_suggested_courses()

        output_data = SuggestedCourseSerializer(input_data).data

        self.assertDictEqual(
            output_data,
            {
                "bannerUrl": input_data["bannerUrl"],
                "logoUrl": input_data["logoUrl"],
                "title": input_data["title"],
                "courseUrl": input_data["courseUrl"],
            },
        )


class TestEmailConfirmationSerializer(TestCase):
    """High-level tests for EmailConfirmationSerializer"""

    @classmethod
    def generate_test_data(cls):
        return {
            "isNeeded": random_bool(),
            "sendEmailUrl": random_url(),
        }

    def test_structure(self):
        """Test that nothing breaks and the output fields look correct"""
        input_data = self.generate_test_data()

        output_data = EmailConfirmationSerializer(input_data).data

        expected_keys = [
            "isNeeded",
            "sendEmailUrl",
        ]
        assert output_data.keys() == set(expected_keys)

    def test_happy_path(self):
        """Test that data serializes correctly"""

        input_data = self.generate_test_data()

        output_data = EmailConfirmationSerializer(input_data).data

        self.assertDictEqual(
            output_data,
            {
                "isNeeded": input_data["isNeeded"],
                "sendEmailUrl": input_data["sendEmailUrl"],
            },
        )


class TestEnterpriseDashboardsSerializer(TestCase):
    """High-level tests for EnterpriseDashboardsSerializer"""

    @classmethod
    def generate_test_dashboard(cls):
        return {
            "label": f"{uuid4()}",
            "url": random_url(),
        }

    @classmethod
    def generate_test_data(cls):
        return {
            "availableDashboards": [
                cls.generate_test_dashboard() for _ in range(randint(0, 3))
            ],
            "mostRecentDashboard": cls.generate_test_dashboard()
            if random_bool()
            else None,
        }

    def test_structure(self):
        """Test that nothing breaks and the output fields look correct"""
        input_data = self.generate_test_data()

        output_data = EnterpriseDashboardsSerializer(input_data).data

        expected_keys = [
            "availableDashboards",
            "mostRecentDashboard",
        ]
        assert output_data.keys() == set(expected_keys)

    def test_happy_path(self):
        """Test that data serializes correctly"""

        input_data = self.generate_test_data()

        output_data = EnterpriseDashboardsSerializer(input_data).data

        self.assertDictEqual(
            output_data,
            {
                "availableDashboards": input_data["availableDashboards"],
                "mostRecentDashboard": input_data["mostRecentDashboard"],
            },
        )


class TestLearnerDashboardSerializer(TestCase):
    """High-level tests for Learner Dashboard serialization"""

    # Show full diff for serialization issues
    maxDiff = None

    def test_empty(self):
        """Test that empty inputs return the right keys"""

        input_data = {
            "emailConfirmation": None,
            "enterpriseDashboards": None,
            "platformSettings": None,
            "enrollments": [],
            "unfulfilledEntitlements": [],
            "suggestedCourses": [],
        }
        output_data = LearnerDashboardSerializer(input_data).data

        self.assertDictEqual(
            output_data,
            {
                "emailConfirmation": None,
                "enterpriseDashboards": None,
                "platformSettings": None,
                "enrollments": [],
                "unfulfilledEntitlements": [],
                "suggestedCourses": [],
            },
        )

    @mock.patch(
        "lms.djangoapps.learner_dashboard.serializers.SuggestedCourseSerializer.to_representation"
    )
    @mock.patch(
        "lms.djangoapps.learner_dashboard.serializers.UnfulfilledEntitlementSerializer.to_representation"
    )
    @mock.patch(
        "lms.djangoapps.learner_dashboard.serializers.LearnerEnrollmentSerializer.to_representation"
    )
    @mock.patch(
        "lms.djangoapps.learner_dashboard.serializers.PlatformSettingsSerializer.to_representation"
    )
    @mock.patch(
        "lms.djangoapps.learner_dashboard.serializers.EnterpriseDashboardsSerializer.to_representation"
    )
    @mock.patch(
        "lms.djangoapps.learner_dashboard.serializers.EmailConfirmationSerializer.to_representation"
    )
    def test_linkage(
        self,
        mock_email_confirmation_serializer,
        mock_enterprise_dashboards_serializer,
        mock_platform_settings_serializer,
        mock_learner_enrollment_serializer,
        mock_entitlements_serializer,
        mock_suggestions_serializer,
    ):
        mock_email_confirmation_serializer.return_value = (
            mock_email_confirmation_serializer
        )
        mock_enterprise_dashboards_serializer.return_value = (
            mock_enterprise_dashboards_serializer
        )
        mock_platform_settings_serializer.return_value = (
            mock_platform_settings_serializer
        )
        mock_learner_enrollment_serializer.return_value = (
            mock_learner_enrollment_serializer
        )
        mock_entitlements_serializer.return_value = mock_entitlements_serializer
        mock_suggestions_serializer.return_value = mock_suggestions_serializer

        input_data = {
            "emailConfirmation": {},
            "enterpriseDashboards": [{}],
            "platformSettings": {},
            "enrollments": [{}],
            "unfulfilledEntitlements": [{}],
            "suggestedCourses": [{}],
        }
        output_data = LearnerDashboardSerializer(input_data).data

        self.assertDictEqual(
            output_data,
            {
                "emailConfirmation": mock_email_confirmation_serializer,
                "enterpriseDashboards": mock_enterprise_dashboards_serializer,
                "platformSettings": mock_platform_settings_serializer,
                "enrollments": [mock_learner_enrollment_serializer],
                "unfulfilledEntitlements": [mock_entitlements_serializer],
                "suggestedCourses": [mock_suggestions_serializer],
            },
        )
