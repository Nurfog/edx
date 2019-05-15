"""
Utilities for tests within the django_comment_client module.
"""
from __future__ import absolute_import
from mock import patch

from openedx.core.djangoapps.django_comment_common.models import ForumsConfig, Role
from openedx.core.djangoapps.django_comment_common.utils import (
    CourseDiscussionSettings, seed_permissions_roles, set_course_discussion_settings,
)
from openedx.core.djangoapps.course_groups.tests.helpers import CohortFactory
from student.tests.factories import CourseEnrollmentFactory, UserFactory
from util.testing import UrlResetMixin
from xmodule.modulestore import ModuleStoreEnum
from xmodule.modulestore.django import modulestore
from xmodule.modulestore.tests.django_utils import SharedModuleStoreTestCase
from xmodule.modulestore.tests.factories import CourseFactory


class ForumsEnableMixin(object):
    """
    Ensures that the forums are enabled for a given test class.
    """
    def setUp(self):
        super(ForumsEnableMixin, self).setUp()

        config = ForumsConfig.current()
        config.enabled = True
        config.save()


class CohortedTestCase(ForumsEnableMixin, UrlResetMixin, SharedModuleStoreTestCase):
    """
    Sets up a course with a student, a moderator and their cohorts.
    """
    @classmethod
    @patch.dict("django.conf.settings.FEATURES", {"ENABLE_DISCUSSION_SERVICE": True})
    def setUpClass(cls):
        super(CohortedTestCase, cls).setUpClass()
        cls.course = CourseFactory.create(
            cohort_config={
                "cohorted": True,
                "cohorted_discussions": ["cohorted_topic"]
            }
        )
        cls.course.discussion_topics["cohorted topic"] = {"id": "cohorted_topic"}
        cls.course.discussion_topics["non-cohorted topic"] = {"id": "non_cohorted_topic"}
        fake_user_id = 1
        cls.store.update_item(cls.course, fake_user_id)

    @patch.dict("django.conf.settings.FEATURES", {"ENABLE_DISCUSSION_SERVICE": True})
    def setUp(self):
        super(CohortedTestCase, self).setUp()

        seed_permissions_roles(self.course.id)
        self.student = UserFactory.create()
        self.moderator = UserFactory.create()
        CourseEnrollmentFactory(user=self.student, course_id=self.course.id)
        CourseEnrollmentFactory(user=self.moderator, course_id=self.course.id)
        self.moderator.roles.add(Role.objects.get(name="Moderator", course_id=self.course.id))
        self.student_cohort = CohortFactory.create(
            name="student_cohort",
            course_id=self.course.id,
            users=[self.student]
        )
        self.moderator_cohort = CohortFactory.create(
            name="moderator_cohort",
            course_id=self.course.id,
            users=[self.moderator]
        )


# pylint: disable=dangerous-default-value
def config_course_discussions(
        course,
        discussion_topics={},
        divided_discussions=[],
        always_divide_inline_discussions=False
):
    """
    Set discussions and configure divided discussions for a course.

    Arguments:
        course: CourseDescriptor
        discussion_topics (Dict): Discussion topic names. Picks ids and
            sort_keys automatically.
        divided_discussions: Discussion topics to divide. Converts the
            list to use the same ids as discussion topic names.
        always_divide_inline_discussions (bool): Whether inline discussions
            should be divided by default.

    Returns:
        Nothing -- modifies course in place.
    """

    def to_id(name):
        """Convert name to id."""
        return topic_name_to_id(course, name)

    set_course_discussion_settings(
        course.id,
        divided_discussions=[to_id(name) for name in divided_discussions],
        always_divide_inline_discussions=always_divide_inline_discussions,
        division_scheme=CourseDiscussionSettings.COHORT,
    )

    course.discussion_topics = dict((name, {"sort_key": "A", "id": to_id(name)})
                                    for name in discussion_topics)
    try:
        # Not implemented for XMLModulestore, which is used by test_cohorts.
        modulestore().update_item(course, ModuleStoreEnum.UserID.test)
    except NotImplementedError:
        pass


def topic_name_to_id(course, name):
    """
    Given a discussion topic name, return an id for that name (includes
    course and url_name).
    """
    return "{course}_{run}_{name}".format(
        course=course.location.course,
        run=course.url_name,
        name=name
    )
