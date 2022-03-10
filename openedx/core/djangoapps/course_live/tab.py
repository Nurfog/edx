from common.lib.xmodule.xmodule.course_module import CourseBlock
from common.lib.xmodule.xmodule.tabs import TabFragmentViewMixin
from lms.djangoapps.courseware.tabs import EnrolledTab
from openedx.core.djangoapps.course_live.models import CourseLiveConfiguration
from openedx.features.lti_course_tab.tab import LtiCourseLaunchMixin
from django.utils.translation import get_language, gettext_lazy, to_locale
from lti_consumer.models import LtiConfiguration


class CourseLiveTab(LtiCourseLaunchMixin, TabFragmentViewMixin, EnrolledTab):
    """
    Course tab that loads the associated LTI-based live provider in a tab.
    """
    type = 'lti_live'
    priority = 42
    allow_multiple = False
    is_dynamic = True
    title = gettext_lazy("Live")

    def _get_lti_config(self, course: CourseBlock) -> LtiConfiguration:
        """
        Get course live configurations
        """
        return CourseLiveConfiguration.get(course.id).lti_configuration


    @classmethod
    def is_enabled(cls, course, user=None):
        """
        Check if the tab is enabled.
        """
        return super().is_enabled(course, user) and CourseLiveConfiguration.get(course.id).enabled
