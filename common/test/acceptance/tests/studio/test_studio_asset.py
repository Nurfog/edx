"""
Acceptance tests for Studio related to the asset index page.
"""

from flaky import flaky

from ...pages.studio.asset_index import AssetIndexPage

from .base_studio_test import StudioCourseTest
from ...fixtures.base import StudioApiLoginError


class AssetIndexTest(StudioCourseTest):

    """
    Tests for the Asset index page.
    """

    def setUp(self, is_staff=False):
        super(AssetIndexTest, self).setUp(is_staff=is_staff)
        self.asset_page = AssetIndexPage(
            self.browser,
            self.course_info['org'],
            self.course_info['number'],
            self.course_info['run']
        )

    def populate_course_fixture(self, course_fixture):
        """
        Populate the children of the test course fixture.
        """
        self.course_fixture.add_asset(['image.jpg', 'textbook.pdf'])

    @flaky(max_runs=60, min_passes=60)
    def test_page_existence(self):
        """
        Make sure that the page is accessible.
        """
        self.asset_page.visit()

    @flaky(max_runs=20, min_passes=20)  # TODO fix this, see SOL-1160
    def test_type_filter_exists(self):
        """
        Make sure type filter is on the page.
        """
        self.asset_page.visit()
        self.asset_page.wait_for_element_presence('#asset-paging-header', 'Assets loaded', timeout=600)
        assert self.asset_page.type_filter_on_page() is True

    def test_filter_results(self):
        """
        Make sure type filter actually filters the results.
        """
        self.asset_page.visit()
        all_results = len(self.asset_page.return_results_set())
        if self.asset_page.select_type_filter(1):
            filtered_results = len(self.asset_page.return_results_set())
            assert self.asset_page.type_filter_header_label_visible()
            assert all_results > filtered_results
        else:
            msg = "Could not open select Type filter"
            raise StudioApiLoginError(msg)
