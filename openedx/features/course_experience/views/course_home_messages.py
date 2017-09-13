"""
View logic for handling course messages.
"""
import math

from babel.dates import format_date, format_timedelta
from datetime import datetime

from course_modes.models import CourseMode
from courseware.courses import get_course_with_access
from django.core.urlresolvers import reverse
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.http import urlquote_plus
from django.utils.timezone import UTC
from django.utils.translation import get_language, to_locale
from django.utils.translation import ugettext as _
from openedx.core.djangolib.markup import Text, HTML
from opaque_keys.edx.keys import CourseKey
from web_fragments.fragment import Fragment

from course_goals.views import CourseGoalType
from openedx.core.djangoapps.plugin_api.views import EdxFragmentView
from openedx.features.course_experience import CourseHomeMessages
from student.models import CourseEnrollment
from .. import ENABLE_COURSE_GOALS


class CourseHomeMessageFragmentView(EdxFragmentView):
    """
    A fragment that displays a course message with an alert and call
    to action for three types of users:

    1) Not logged in users are given a link to sign in or register.
    2) Unenrolled users are given a link to enroll.
    3) Enrolled users who get to the page before the course start date
    are given the option to add the start date to their calendar.

    This fragment requires a user_access map as follows:

    user_access = {
        'is_anonymous': True if the user is logged in, False otherwise
        'is_enrolled': True if the user is enrolled in the course, False otherwise
        'is_staff': True if the user is a staff member of the course, False otherwise
    }
    """
    def render_to_fragment(self, request, course_id, user_access, **kwargs):
        """
        Renders a course message fragment for the specified course.
        """
        course_key = CourseKey.from_string(course_id)
        course = get_course_with_access(request.user, 'load', course_key)

        # Get time until the start date, if already started, or no start date, value will be zero or negative
        now = datetime.now(UTC())
        already_started = course.start and now > course.start
        days_until_start_string = "started" if already_started else format_timedelta(course.start - now, locale=to_locale(get_language()))
        course_start_data = {
            'course_start_date': format_date(course.start, locale=to_locale(get_language())),
            'already_started': already_started,
            'days_until_start_string': days_until_start_string
        }

        # Register the course home messages to be loaded on the page
        self.register_course_home_messages(self, request, course_id, user_access, course_start_data)

        # Grab the relevant messages
        course_home_messages = list(CourseHomeMessages.user_messages(request))

        # Pass in the url used to set a course goal
        set_goal_url = reverse(
            'course_goals:set_course_goal',
            kwargs={
                'course_id': course_id,
            }
        )

        # Grab the logo
        image_src = "course_experience/images/home_message_author.png"

        context = {
            'course_home_messages': course_home_messages,
            'set_goal_url': set_goal_url,
            'image_src': image_src,
        }

        html = render_to_string('course_experience/course-messages-fragment.html', context)
        return Fragment(html)

    @staticmethod
    def register_course_home_messages(self, request, course_id, user_access, course_start_data):
        """
        Register messages to be shown in the course home content page.
        """
        course_key = CourseKey.from_string(course_id)
        course = get_course_with_access(request.user, 'load', course_key)
        if user_access['is_anonymous']:
            CourseHomeMessages.register_info_message(
                request,
                Text(_(
                    " {sign_in_link} or {register_link} and then enroll in this course."
                )).format(
                    sign_in_link=HTML("<a href='/login?next={current_url}'>{sign_in_label}</a>").format(
                        sign_in_label=_("Sign in"),
                        current_url=urlquote_plus(request.path),
                    ),
                    register_link=HTML("<a href='/register?next={current_url}'>{register_label}</a>").format(
                        register_label=_("register"),
                        current_url=urlquote_plus(request.path),
                    )
                ),
                title='You must be enrolled in the course to see course content.'
            )
        if not user_access['is_anonymous'] and not user_access['is_staff'] and not user_access['is_enrolled']:
            CourseHomeMessages.register_info_message(
                request,
                Text(_(
                    "{open_enroll_link} Enroll now{close_enroll_link} to access the full course."
                )).format(
                    open_enroll_link='',
                    close_enroll_link=''
                ),
                title=Text('Welcome to {course_display_name}').format(
                    course_display_name=course.display_name
                )
            )
        if user_access['is_enrolled'] and not course_start_data['already_started']:
            CourseHomeMessages.register_info_message(
                request,
                Text(_(
                    "Don't forget to add a calendar reminder!"
                )),
                title=Text("Course starts in {days_until_start_string} on {course_start_date}.").format(
                    days_until_start_string=course_start_data['days_until_start_string'],
                    course_start_date=course_start_data['course_start_date']
                )
            )

        is_already_verified = CourseEnrollment.is_enrolled_as_verified(request.user, course_key)
        # available_modes = CourseMode.modes_for_course_dict(unicode(course.id))
        # has_verified_mode = CourseMode.has_verified_mode(available_modes)
        # user_goal = get_course_goal(request.user, course_id)
        # waffle_flag_enabled = ENABLE_COURSE_GOALS.is_enabled(course_key)
        has_verified_mode = True
        user_goal = None
        waffle_flag_enabled = True

        # Only show the set course goal message for enrolled, unverified
        # users that have not yet set a goal in a course that allows for
        # verified statuses.
        if settings.FEATURES.get('ENABLE_COURSE_GOALS') and not user_goal and user_access['is_enrolled'] \
                and has_verified_mode and not is_already_verified and waffle_flag_enabled:
            goal_choices_html = HTML(_(
                'To start, set a course goal by selecting the option below that best describes '
                'your learning plan. {goal_options_container}'
            )).format(
                goal_options_container=HTML('<div class="row goal-options-container">')
            )

            # Add the dismissible option for users that are unsure of their goal
            goal_choices_html += HTML(
                '{initial_tag}{choice}{closing_tag}'
            ).format(
                initial_tag=HTML(
                    '<div tabindex="0" aria-label="{aria_label_choice}" class="goal-option dismissible" '
                    'data-choice="{goal}">'
                ).format(
                    goal=CourseGoalType.UNSURE.value,
                    aria_label_choice=Text(_("Set goal to, {choice}")).format(
                        choice=self.get_goal_text(CourseGoalType.UNSURE.value)
                    ),
                ),
                choice=Text(_('{choice}')).format(
                    choice=self.get_goal_text(CourseGoalType.UNSURE.value),
                ),
                closing_tag=HTML('</div>'),
            )

            # Add the option to set a goal to earn a certificate,
            # complete the course or explore the course
            goal_options = [CourseGoalType.CERTIFY.value, CourseGoalType.COMPLETE.value, CourseGoalType.EXPLORE.value]
            for goal in goal_options:
                goal_text = self.get_goal_text(goal)
                goal_choices_html += HTML(
                    '{initial_tag}{goal_text}{closing_tag}'
                ).format(
                    initial_tag=HTML(
                        '<div tabindex="0" aria-label="{aria_label_choice}" class="goal-option {col_sel} btn" '
                        'data-choice="{goal}">'
                    ).format(
                        goal=goal,
                        aria_label_choice=Text(_("Set goal to, {goal_text}")).format(
                            goal_text=Text(_(goal_text))
                        ),
                        col_sel='col-' + str(int(math.floor(12 / len(goal_options))))
                    ),
                    goal_text=goal_text,
                    closing_tag=HTML('</div>')
                )

            CourseHomeMessages.register_info_message(
                request,
                HTML('{goal_choices_html}{closing_tag}').format(
                    goal_choices_html=goal_choices_html,
                    closing_tag=HTML('</div>')
                ),
                title=Text(_('Welcome to {course_display_name}')).format(
                    course_display_name=course.display_name
                )
            )

    @staticmethod
    def get_goal_text(goal_type):
        return {
            CourseGoalType.CERTIFY.value: Text(_('Earn a certificate')),
            CourseGoalType.COMPLETE.value: Text(_('Complete the course')),
            CourseGoalType.EXPLORE.value: Text(_('Explore the course')),
            CourseGoalType.UNSURE.value: Text(_('Not sure yet')),
        }[goal_type]
