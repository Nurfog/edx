"""
Course Updates page.
"""

from common.test.acceptance.pages.studio.course_page import CoursePage


class CourseUpdatesPage(CoursePage):
    """
    Course Updates page.
    """

    url_path = "course_info"

    def is_browser_on_page(self):
        return self.q(css='body.view-updates').present
