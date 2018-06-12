"""
Student Custom Dashboard View
"""

from django.core.exceptions import ObjectDoesNotExist

from common.lib.nodebb_client.client import NodeBBClient
from courseware.courses import get_courses
from custom_settings.models import CustomSettings
from xmodule.modulestore.django import modulestore
from student.models import CourseEnrollment


def get_recommended_courses(user):
    """
    Helper function to get recommended courses for a user based on his interests
    """
    recommended_courses = []
    all_courses = get_courses(user)
    try:
        user_interests = user.extended_profile.get_user_selected_interests()
        for course in all_courses:
            try:
                tags = CustomSettings.objects.filter(id=course.id).first().tags
                tags = tags.split('|')
                tags = [tag.strip() for tag in tags]
                if set(user_interests) & set(tags) and not CourseEnrollment.is_enrolled(user, course.id):
                    recommended_courses.append(course)
            except AttributeError:
                pass
    except ObjectDoesNotExist:
        pass
    return recommended_courses


def get_enrolled_past_courses(course_enrollments):
    """
    Helper function to separate past courses from all enrolled courses
    """
    #TODO move this function out of core code
    enrolled, past = [], []

    for course in course_enrollments:
        if course.course_overview.has_ended():
            past.append(course)
        else:
            enrolled.append(course)

    return enrolled, past


def get_recommended_xmodule_courses(user):
    """
    Helper function to get recommended courses based on the user interests and add details from xmodule to
    the recommended courses
    """
    recommended_courses = []
    all_courses = get_courses(user)
    user_interests = user.extended_profile.get_user_selected_interests()
    if not user_interests:
        return []

    for course in all_courses:
        settings = CustomSettings.objects.filter(id=course.id).first()
        if not settings:
            continue

        tags = settings.tags
        if not tags:
            continue

        tags = tags.split('|')
        tags = [tag.strip() for tag in tags]
        matched_interests = set(user_interests) & set(tags)
        if matched_interests and not CourseEnrollment.is_enrolled(user, course.id):
            detailed_course = modulestore().get_course(course.id)
            detailed_course.short_description = course.short_description
            detailed_course.interests = '/ '.join(list(matched_interests))
            recommended_courses.append(detailed_course)

    return recommended_courses


def get_recommended_communities(user):
    """
    Helper function to get recommended communities from NodeBB API
    """
    status, categories = NodeBBClient().categories.recommended(user)
    return categories if status == 200 else []


def get_joined_communities(user):
    """
    Helper function to get joined communities from NodeBB API
    """
    status, categories = NodeBBClient().categories.joined(user)
    return categories if status == 200 else []
