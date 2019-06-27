"""Tests of openedx.features.discounts.applicability"""
# -*- coding: utf-8 -*-

from datetime import timedelta
import ddt
from django.utils.timezone import now

from course_modes.models import CourseMode
from course_modes.tests.factories import CourseModeFactory
from openedx.core.djangoapps.content.course_overviews.models import CourseOverview
from openedx.core.djangoapps.waffle_utils.testutils import override_waffle_flag
from openedx.features.discounts.models import DiscountRestrictionConfig
from student.tests.factories import UserFactory, CourseEnrollmentFactory
from xmodule.modulestore.tests.django_utils import ModuleStoreTestCase
from xmodule.modulestore.tests.factories import CourseFactory

from ..applicability import can_receive_discount, DISCOUNT_APPLICABILITY_FLAG


@ddt.ddt
class TestApplicability(ModuleStoreTestCase):
    """
    Applicability determines if this combination of user and course can receive a discount. Make
    sure that all of the business conditions work.
    """

    def setUp(self):
        super(TestApplicability, self).setUp()
        self.user = UserFactory.create()
        self.course = CourseFactory.create(run='test', display_name='test')
        CourseModeFactory.create(course_id=self.course.id, mode_slug='verified')

    def test_can_receive_discount(self):
        # Right now, no one should be able to receive the discount
        applicability = can_receive_discount(user=self.user, course=self.course)
        self.assertEqual(applicability, False)

    @override_waffle_flag(DISCOUNT_APPLICABILITY_FLAG, active=True)
    def test_can_receive_discount_course_requirements(self):
        """
        Ensure first purchase offer banner only displays for courses with a non-expired verified mode
        """
        applicability = can_receive_discount(user=self.user, course=self.course)
        self.assertEqual(applicability, True)

        no_verified_mode_course = CourseFactory(end=now() + timedelta(days=30))
        applicability = can_receive_discount(user=self.user, course=no_verified_mode_course)
        self.assertEqual(applicability, False)

        course_that_has_ended = CourseFactory(end=now() - timedelta(days=30))
        applicability = can_receive_discount(user=self.user, course=course_that_has_ended)
        self.assertEqual(applicability, False)

        disabled_course = CourseFactory()
        CourseModeFactory.create(course_id=disabled_course.id, mode_slug='verified')
        disabled_course_overview = CourseOverview.get_from_id(disabled_course.id)
        DiscountRestrictionConfig.objects.create(disabled=True, course=disabled_course_overview)
        applicability = can_receive_discount(user=self.user, course=disabled_course)
        self.assertEqual(applicability, False)

    @ddt.data(*(
        [[]] +
        [[mode] for mode in CourseMode.ALL_MODES] +
        [
            [mode1, mode2]
            for mode1 in CourseMode.ALL_MODES
            for mode2 in CourseMode.ALL_MODES
            if mode1 != mode2
        ]
    ))
    @override_waffle_flag(DISCOUNT_APPLICABILITY_FLAG, active=True)
    def test_can_receive_discount_previous_verified_enrollment(self, existing_enrollments):
        """
        Ensure that only users who have not already purchased courses receive the discount.
        """
        for mode in existing_enrollments:
            CourseEnrollmentFactory.create(mode=mode, user=self.user)

        applicability = can_receive_discount(user=self.user, course=self.course)
        assert applicability == all(mode in CourseMode.UPSELL_TO_VERIFIED_MODES for mode in existing_enrollments)
