# -*- coding: utf-8 -*-
"""
Student dashboard page.
"""

from bok_choy.page_object import PageObject
from bok_choy.promise import Promise, EmptyPromise, fulfill_after, fulfill
from . import BASE_URL


class DashboardPage(PageObject):
    """
    Student dashboard, where the student can view
    courses she/he has registered for.
    """

    url = BASE_URL + "/dashboard"

    def is_browser_on_page(self):
        return self.is_css_present('section.my-courses')

    @property
    def available_courses(self):
        """
        Return list of the names of available courses (e.g. "999 edX Demonstration Course")
        """
        def _get_course_name(el):
            # The first component in the link text is the course number
            _, course_name = el.text.split(' ', 1)
            return course_name

        return self.css_map('section.info > hgroup > h3 > a', _get_course_name)

    def change_language(self, code):
        """
        Change the language on the dashboard to the language corresponding with `code`.
        """
        # Get the current section heading, so we can compare it to the heading
        # when we change the language.
        old_text = self.current_courses_text

        lang_changed = EmptyPromise(
            lambda: old_text != self.current_courses_text,
            "Current courses text changed"
        )

        with fulfill_after(lang_changed):
            self.css_click(".edit-language")
            self.select_option("language", code)
            self.css_click("#submit-lang")

    @property
    def is_dummy_lang(self):
        """
        Return a boolean indicating whether dashboard is displaying dummy translation strings.
        """
        return u"ÇÜRRÉNT".encode('utf-8') in self.current_courses_text.encode('utf-8')

    @property
    def current_courses_text(self):
        """
        Return the text of the "current courses" title.
        """
        def _check_func():
            text_items = self.css_text('section#my-courses')
            if len(text_items) < 1:
                return (False, None)
            elif not text_items[0]:
                return (False, None)
            else:
                return (True, text_items[0])

        return fulfill(Promise(_check_func, "Retrieved current courses title"))

    def view_course(self, course_id):
        """
        Go to the course with `course_id` (e.g. edx/Open_DemoX/edx_demo_course)
        """
        link_css = self._link_css(course_id)

        if link_css is not None:
            self.css_click(link_css)
        else:
            msg = "No links found for course {0}".format(course_id)
            self.warning(msg)

    def _link_css(self, course_id):
        """
        Return a CSS selector for the link to the course with `course_id`.
        """
        # Get the link hrefs for all courses
        all_links = self.css_map('a.enter-course', lambda el: el['href'])

        # Search for the first link that matches the course id
        link_index = None
        for index in range(len(all_links)):
            if course_id in all_links[index]:
                link_index = index
                break

        if link_index is not None:
            return "a.enter-course:nth-of-type({0})".format(link_index + 1)
        else:
            return None
