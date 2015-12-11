"""
Test for course API
"""
from hashlib import md5

from django.contrib.auth.models import AnonymousUser
from opaque_keys.edx.keys import CourseKey
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from xmodule.modulestore.tests.django_utils import SharedModuleStoreTestCase, ModuleStoreTestCase
from xmodule.course_module import CourseDescriptor
from .mixins import CourseApiFactoryMixin
from ..api import course_detail, list_courses


class CourseApiTestMixin(CourseApiFactoryMixin):
    """
    Establish basic functionality for Course API tests
    """
    @classmethod
    def setUpClass(cls):
        super(CourseApiTestMixin, cls).setUpClass()
        cls.request_factory = APIRequestFactory()

    def verify_course(self, course, course_id=u'edX/toy/2012_Fall'):
        """
        Ensure that the returned course is the course we just created
        """
        self.assertIsInstance(course, CourseDescriptor)
        self.assertEqual(course_id, str(course.id))


class CourseDetailTestMixin(CourseApiTestMixin):
    """
    Common functionality for course_detail tests
    """
    def _make_api_call(self, requesting_user, target_user, course_key):
        """
        Call the `course_detail` api endpoint to get information on the course
        identified by `course_key`.
        """
        request = Request(self.request_factory.get('/'))
        request.user = requesting_user
        return course_detail(request, target_user.username, course_key)


class TestGetCourseDetail(CourseDetailTestMixin, SharedModuleStoreTestCase):
    """
    Test course_detail api function
    """
    @classmethod
    def setUpClass(cls):
        super(TestGetCourseDetail, cls).setUpClass()
        cls.course = cls.create_course()
        cls.hidden_course = cls.create_course(course=u'hidden', visible_to_staff_only=True)
        cls.honor_user = cls.create_user('honor', is_staff=False)
        cls.staff_user = cls.create_user('staff', is_staff=True)

    def test_get_existing_course(self):
        course = self._make_api_call(self.honor_user, self.honor_user, self.course.id)
        self.verify_course(course)

    def test_get_nonexistent_course(self):
        course_key = CourseKey.from_string(u'edX/toy/nope')
        with self.assertRaises(NotFound):
            self._make_api_call(self.honor_user, self.honor_user, course_key)

    def test_hidden_course_for_honor(self):
        with self.assertRaises(NotFound):
            self._make_api_call(self.honor_user, self.honor_user, self.hidden_course.id)

    def test_hidden_course_for_staff(self):
        course = self._make_api_call(self.staff_user, self.staff_user, self.hidden_course.id)
        self.verify_course(course, course_id=u'edX/hidden/2012_Fall')

    def test_hidden_course_for_staff_as_honor(self):
        with self.assertRaises(NotFound):
            self._make_api_call(self.staff_user, self.honor_user, self.hidden_course.id)


class CourseListTestMixin(CourseApiTestMixin):
    """
    Common behavior for list_courses tests
    """
    def _make_api_call(self, requesting_user, specified_user, org=None):
        """
        Call the list_courses api endpoint to get information about
        `specified_user` on behalf of `requesting_user`.
        """
        request = Request(self.request_factory.get('/'))
        request.user = requesting_user
        return list_courses(request, specified_user.username, org=org)

    def verify_courses(self, courses):
        """
        Verify that there is one course, and that it has the expected format.
        """
        self.assertEqual(len(courses), 1)
        self.verify_course(courses[0])


class TestGetCourseList(CourseListTestMixin, SharedModuleStoreTestCase):
    """
    Test the behavior of the `list_courses` api function.
    """

    @classmethod
    def setUpClass(cls):
        super(TestGetCourseList, cls).setUpClass()
        cls.course = cls.create_course()
        cls.staff_user = cls.create_user("staff", is_staff=True)
        cls.honor_user = cls.create_user("honor", is_staff=False)

    def test_as_staff(self):
        courses = self._make_api_call(self.staff_user, self.staff_user)
        self.assertEqual(len(courses), 1)
        self.verify_courses(courses)

    def test_for_honor_user_as_staff(self):
        courses = self._make_api_call(self.staff_user, self.honor_user)
        self.verify_courses(courses)

    def test_as_honor(self):
        courses = self._make_api_call(self.honor_user, self.honor_user)
        self.verify_courses(courses)

    def test_for_staff_user_as_honor(self):
        with self.assertRaises(PermissionDenied):
            self._make_api_call(self.honor_user, self.staff_user)

    def test_as_anonymous(self):
        anonuser = AnonymousUser()
        courses = self._make_api_call(anonuser, anonuser)
        self.verify_courses(courses)

    def test_for_honor_user_as_anonymous(self):
        anonuser = AnonymousUser()
        with self.assertRaises(PermissionDenied):
            self._make_api_call(anonuser, self.staff_user)

    def test_multiple_courses(self):
        self.create_course(course='second')
        courses = self._make_api_call(self.honor_user, self.honor_user)
        self.assertEqual(len(courses), 2)

    @SharedModuleStoreTestCase.modifies_courseware
    def test_filter_by_org(self):
        """Verify that CourseDescriptors are filtered by the provided org key."""
        # Create a second course to be filtered out of queries.
        alternate_course = self.create_course(
            org=md5(self.course.org).hexdigest()
        )

        self.assertNotEqual(alternate_course.org, self.course.org)

        # No filtering.
        unfiltered_courses = self._make_api_call(self.staff_user, self.staff_user)
        self.assertTrue(
            any(course.org == alternate_course.org for course in unfiltered_courses)
        )

        # With filtering.
        filtered_courses = self._make_api_call(self.staff_user, self.staff_user, org=self.course.org)
        self.assertTrue(
            all(course.org == self.course.org for course in filtered_courses)
        )


class TestGetCourseListExtras(CourseListTestMixin, ModuleStoreTestCase):
    """
    Tests of course_list api function that require alternative configurations
    of created courses.
    """
    @classmethod
    def setUpClass(cls):
        super(TestGetCourseListExtras, cls).setUpClass()
        cls.staff_user = cls.create_user("staff", is_staff=True)
        cls.honor_user = cls.create_user("honor", is_staff=False)

    def test_no_courses(self):
        courses = self._make_api_call(self.honor_user, self.honor_user)
        self.assertEqual(len(courses), 0)

    def test_hidden_course_for_honor(self):
        self.create_course(visible_to_staff_only=True)
        courses = self._make_api_call(self.honor_user, self.honor_user)
        self.assertEqual(len(courses), 0)

    def test_hidden_course_for_staff(self):
        self.create_course(visible_to_staff_only=True)
        courses = self._make_api_call(self.staff_user, self.staff_user)
        self.verify_courses(courses)
