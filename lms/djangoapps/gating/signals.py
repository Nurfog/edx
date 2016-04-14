"""
Signal handlers for the gating djangoapp
"""
from django.dispatch import receiver
from opaque_keys.edx.keys import UsageKey
from util.course_key_utils import course_key_from_string_or_404
from xmodule.modulestore.django import modulestore
from courseware.models import SCORE_CHANGED
from gating import api as gating_api


@receiver(SCORE_CHANGED)
def handle_score_changed(**kwargs):
    """
    Receives the SCORE_CHANGED signal sent by LMS when a student's score has changed
    for a given component and triggers the evaluation of any milestone relationships
    which are attached to the updated content.

    Arguments:
        kwargs (dict): Contains user ID, course key, and content usage key

    Returns:
        None
    """
    course = modulestore().get_course(course_key_from_string_or_404(kwargs.get('course_id')))
    if course.enable_subsection_gating:
        gating_api.evaluate_prerequisite(
            course,
            UsageKey.from_string(kwargs.get('usage_id')),
            kwargs.get('user_id'),
        )
