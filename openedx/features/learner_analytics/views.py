"""
Learner analytics dashboard views
"""
import math
import json

from django.contrib.auth.decorators import login_required
from django.template.context_processors import csrf
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_control
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.generic import View

from opaque_keys.edx.keys import CourseKey
from lms.djangoapps.course_api.blocks.api import get_blocks
from lms.djangoapps.courseware.courses import get_course_with_access
from lms.djangoapps.discussion.views import create_user_profile_context
from lms.djangoapps.grades.course_grade_factory import CourseGradeFactory
from openedx.features.course_experience import default_course_url_name
from student.models import CourseEnrollment
from xmodule.modulestore.django import modulestore
from util.views import ensure_valid_course_key


class LearnerAnalyticsView(View):

    @method_decorator(login_required)
    @method_decorator(ensure_csrf_cookie)
    @method_decorator(cache_control(no_cache=True, no_store=True, must_revalidate=True))
    @method_decorator(ensure_valid_course_key)
    def get(self, request, course_id):
        """
        Displays the user's bookmarks for the specified course.

        Arguments:
            request: HTTP request
            course_id (unicode): course id
        """
        course_key = CourseKey.from_string(course_id)
        course = get_course_with_access(request.user, 'load', course_key, check_if_enrolled=True)
        course_url_name = default_course_url_name(course.id)
        course_url = reverse(course_url_name, kwargs={'course_id': unicode(course.id)})

        grading_policy = course.grading_policy

        # Render the course bookmarks page
        context = {
            'csrf': csrf(request)['csrf_token'],
            'course': course,
            'course_url': course_url,
            'disable_courseware_js': True,
            'uses_pattern_library': True,
            'is_self_paced': course.self_paced,
            'is_verified': CourseEnrollment.is_enrolled_as_verified(request.user, course_key),
            'grading_policy': grading_policy,
            'assignment_grades': self.get_grade_data(request.user, course_key, grading_policy['GRADE_CUTOFFS']),
            'assignment_schedule': self.get_schedule(request, course_key),
            'discussion_info': self.get_discussion_data(request, course_key),
        }
        return render_to_response('learner_analytics/dashboard.html', context)

    def get_grade_data(self, user, course_key, grade_cutoffs):
        """
        Collects and formats the grades data for a particular user and course.

        Args:
            user: User
            course_key: CourseKey
        """
        course_grade = CourseGradeFactory().read(user, course_key=course_key)
        grades = []
        for (location, subsection_grade) in course_grade.subsection_grades.iteritems():
            if subsection_grade.format is not None:
                possible = subsection_grade.graded_total.possible
                passing_grade = math.ceil(possible * grade_cutoffs['Pass'])
                grades.append({
                    'assignment_type': subsection_grade.format,
                    'total_earned': subsection_grade.graded_total.earned,
                    'total_possible': possible,
                    'passing_grade': passing_grade,
                    'assigment_url': reverse('jump_to_id', kwargs={
                        'course_id': unicode(course_key),
                        'module_id': unicode(location),
                    })
                })
        return grades

    def get_discussion_data(self, request, course_key):
        """
        Collects and formats the discussion data from a particular user and course.

        Args:
            user: User
            course_key: CourseKey
        """
        context = create_user_profile_context(request, course_key, request.user.id)
        threads = context['threads']
        profiled_user = context['profiled_user']
        content_authored = profiled_user['threads_count'] +profiled_user['comments_count']
        thread_votes = 0
        for thread in threads:
            if thread['user_id'] == profiled_user['external_id']:
                thread_votes += thread['votes']['count']
        discussion_data = {
            'content_authored': content_authored,
            'thread_votes': thread_votes,
        }
        return discussion_data

    def get_schedule(self, request, course_key):
        """
        Get the schedule of graded assignments in the course.

        Args:
            request: HttpRequest
            course_key: CourseKey
        """
        course_usage_key = modulestore().make_course_usage_key(course_key)
        all_blocks = get_blocks(
            request,
            course_usage_key,
            user=request.user,
            nav_depth=3,
            requested_fields=['display_name', 'due', 'graded', 'format'],
            block_types_filter=['sequential']
        )
        graded_blocks = []
        for (_, block) in all_blocks['blocks'].iteritems():
            if block.get('graded', False) and block.get('due') is not None:
                graded_blocks.append(block)
                block['due'] = block['due'].isoformat()
        return graded_blocks
