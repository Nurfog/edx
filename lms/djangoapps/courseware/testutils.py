"""
Common test utilities for courseware functionality
"""


from abc import ABCMeta, abstractmethod
from datetime import datetime, timedelta
from unittest.mock import patch
from urllib.parse import urlencode

import ddt

from openedx.core.djangoapps.content.course_overviews.models import CourseOverview
from lms.djangoapps.courseware.tests.helpers import set_preview_mode
from openedx.features.course_experience.url_helpers import get_courseware_url
from common.djangoapps.student.tests.factories import AdminFactory, CourseEnrollmentFactory, UserFactory

from xmodule.modulestore import ModuleStoreEnum  # lint-amnesty, pylint: disable=wrong-import-order
from xmodule.modulestore.django import modulestore  # lint-amnesty, pylint: disable=wrong-import-order
from xmodule.modulestore.tests.django_utils import SharedModuleStoreTestCase  # lint-amnesty, pylint: disable=wrong-import-order
from xmodule.modulestore.tests.factories import CourseFactory, ItemFactory, check_mongo_calls  # lint-amnesty, pylint: disable=wrong-import-order

from .field_overrides import OverrideModulestoreFieldData
from .tests.helpers import MasqueradeMixin


@ddt.ddt
class RenderXBlockTestMixin(MasqueradeMixin, metaclass=ABCMeta):
    """
    Mixin for testing the courseware.render_xblock function.
    It can be used for testing any higher-level endpoint that calls this method.
    """

    # DOM elements that appear in the LMS Courseware,
    # but are excluded from the xBlock-only rendering.
    COURSEWARE_CHROME_HTML_ELEMENTS = [
        '<ol class="tabs course-tabs"',
        '<footer id="footer-openedx"',
        '<div class="window-wrap"',
        '<div class="preview-menu"',
        '<div class="container"',
    ]

    # DOM elements that appear in an xBlock,
    # but are excluded from the xBlock-only rendering.
    XBLOCK_REMOVED_HTML_ELEMENTS = [
        '<div class="wrap-instructor-info"',
    ]

    # DOM elements that appear in the LMS Courseware, but are excluded from the
    # xBlock-only rendering, and are specific to a particular block.
    BLOCK_SPECIFIC_CHROME_HTML_ELEMENTS = {
        # Although bookmarks were removed from all chromeless views of the
        # vertical, it is LTI specifically that must never include them.
        'vertical_block': ['<div class="bookmark-button-wrapper"'],
        'html_block': [],
    }

    def setUp(self):
        """
        Clear out the block to be requested/tested before each test.
        """
        super().setUp()
        # to adjust the block to be tested, update block_name_to_be_tested before calling setup_course.
        self.block_name_to_be_tested = 'html_block'

    @abstractmethod
    def get_response(self, usage_key, url_encoded_params=None):
        """
        Abstract method to get the response from the endpoint that is being tested.

        Arguments:
            usage_key: The course block usage key. This ensures that the positive and negative tests stay in sync.
            url_encoded_params: URL encoded parameters that should be appended to the requested URL.
        """
        pass  # pragma: no cover  # lint-amnesty, pylint: disable=unnecessary-pass

    def login(self):
        """
        Logs in the test user.
        """
        self.client.login(username=self.user.username, password='test')

    def course_options(self):
        """
        Options to configure the test course. Intended to be overridden by
        subclasses.
        """
        return {
            'start': datetime.now() - timedelta(days=1)
        }

    def setup_course(self, default_store=None):
        """
        Helper method to create the course.
        """
        if not default_store:
            default_store = self.store.default_modulestore.get_modulestore_type()
        with self.store.default_store(default_store):
            self.course = CourseFactory.create(**self.course_options())
            chapter = ItemFactory.create(parent=self.course, category='chapter')
            self.vertical_block = ItemFactory.create(
                parent_location=chapter.location,
                category='vertical',
                display_name="Vertical"
            )
            self.html_block = ItemFactory.create(
                parent=self.vertical_block,
                category='html',
                data="<p>Test HTML Content<p>"
            )
            self.problem_block = ItemFactory.create(
                parent=self.vertical_block,
                category='problem',
                display_name='Problem'
            )
            self.video_block = ItemFactory.create(
                parent=self.vertical_block,
                category='video',
                display_name='Video'
            )
        CourseOverview.load_from_module_store(self.course.id)

        # block_name_to_be_tested can be `html_block` or `vertical_block`.
        # These attributes help ensure the positive and negative tests are in sync.
        self.block_to_be_tested = getattr(self, self.block_name_to_be_tested)
        self.block_specific_chrome_html_elements = self.BLOCK_SPECIFIC_CHROME_HTML_ELEMENTS[
            self.block_name_to_be_tested
        ]

    def setup_user(self, admin=False, enroll=False, login=False):
        """
        Helper method to create the user.
        """
        self.user = AdminFactory() if admin else UserFactory()

        if enroll:
            CourseEnrollmentFactory(user=self.user, course_id=self.course.id)

        if login:
            self.login()

    def verify_response(self, expected_response_code=200, url_params=None):
        """
        Helper method that calls the endpoint, verifies the expected response code, and returns the response.

        Arguments:
            expected_response_code: The expected response code.
            url_params: URL parameters that will be encoded and passed to the request.

        """
        if url_params:
            url_params = urlencode(url_params)

        response = self.get_response(self.block_to_be_tested.location, url_params)
        if expected_response_code == 200:
            self.assertContains(response, self.html_block.data, status_code=expected_response_code)
            unexpected_elements = self.block_specific_chrome_html_elements
            unexpected_elements += self.COURSEWARE_CHROME_HTML_ELEMENTS + self.XBLOCK_REMOVED_HTML_ELEMENTS
            for chrome_element in unexpected_elements:
                self.assertNotContains(response, chrome_element)
        else:
            self.assertNotContains(response, self.html_block.data, status_code=expected_response_code)
        return response

    @ddt.data(
        ('vertical_block', 4),
        ('html_block', 4),
    )
    @ddt.unpack
    @set_preview_mode(True)
    def test_courseware_html(self, block_name, mongo_calls):
        """
        To verify that the removal of courseware chrome elements is working,
        we include this test here to make sure the chrome elements that should
        be removed actually exist in the full courseware page.
        If this test fails, it's probably because the HTML template for courseware
        has changed and COURSEWARE_CHROME_HTML_ELEMENTS needs to be updated.
        """
        with self.store.default_store(ModuleStoreEnum.Type.split):
            self.block_name_to_be_tested = block_name
            self.setup_course(ModuleStoreEnum.Type.split)
            self.setup_user(admin=True, enroll=True, login=True)

            with check_mongo_calls(mongo_calls):
                url = get_courseware_url(self.block_to_be_tested.location)
                response = self.client.get(url)
                expected_elements = self.block_specific_chrome_html_elements + self.COURSEWARE_CHROME_HTML_ELEMENTS
                for chrome_element in expected_elements:
                    self.assertContains(response, chrome_element)

    def test_success_enrolled_staff(self):
        self.setup_course()
        self.setup_user(admin=True, enroll=True, login=True)

        # The 5 mongoDB calls include calls for
        #   (1) structure - get_course_with_access
        #   (2) definition - get_course_with_access
        #   (3) definition - HTML block
        #   (4) definition - edx_notes decorator (original_get_html)
        with check_mongo_calls(4):
            self.verify_response()

    def test_success_unenrolled_staff(self):
        self.setup_course()
        self.setup_user(admin=True, enroll=False, login=True)
        self.verify_response()

    def test_success_unenrolled_staff_masquerading_as_student(self):
        self.setup_course()
        self.setup_user(admin=True, enroll=False, login=True)
        self.update_masquerade(role='student')
        self.verify_response()

    def test_success_enrolled_student(self):
        self.setup_course()
        self.setup_user(admin=False, enroll=True, login=True)
        self.verify_response()

    def test_unauthenticated(self):
        self.setup_course()
        self.setup_user(admin=False, enroll=True, login=False)
        self.verify_response(expected_response_code=404)

    def test_unenrolled_student(self):
        self.setup_course()
        self.setup_user(admin=False, enroll=False, login=True)
        self.verify_response(expected_response_code=404)

    @patch.dict('django.conf.settings.FEATURES', {'DISABLE_START_DATES': False})
    def test_fail_block_unreleased(self):
        self.setup_course()
        self.setup_user(admin=False, enroll=True, login=True)
        self.block_to_be_tested.start = datetime.max
        modulestore().update_item(self.block_to_be_tested, self.user.id)
        self.verify_response(expected_response_code=404)

    def test_fail_block_nonvisible(self):
        self.setup_course()
        self.setup_user(admin=False, enroll=True, login=True)
        self.block_to_be_tested.visible_to_staff_only = True
        modulestore().update_item(self.block_to_be_tested, self.user.id)
        self.verify_response(expected_response_code=404)

    @ddt.data(
        'vertical_block',
        'html_block',
    )
    def test_student_view_param(self, block_name):
        self.block_name_to_be_tested = block_name
        self.setup_course()
        self.setup_user(admin=False, enroll=True, login=True)
        self.verify_response(url_params={'view': 'student_view'})

    def test_unsupported_view_param(self):
        self.setup_course()
        self.setup_user(admin=False, enroll=True, login=True)
        self.verify_response(url_params={'view': 'author_view'}, expected_response_code=400)


class FieldOverrideTestMixin:
    """
    A Mixin helper class for classes that test Field Overrides.
    """

    def setUp(self):
        super().setUp()
        OverrideModulestoreFieldData.provider_classes = None

    def tearDown(self):
        super().tearDown()
        OverrideModulestoreFieldData.provider_classes = None


@ddt.ddt
class CoursewareUtilsTests(SharedModuleStoreTestCase):
    """
    Tests of the courseware utils file
    """
    def setUp(self):
        super().setUp()
        self.course = CourseFactory.create()
        self.user = UserFactory.create()
