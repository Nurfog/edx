"""
API library for Django REST Framework permissions-oriented workflows
"""
from rest_framework.permissions import BasePermission

from common.djangoapps.student.models import CourseEnrollment
from common.djangoapps.student.roles import CourseInstructorRole, CourseStaffRole, GlobalStaff
from openedx.core.lib.api.view_utils import validate_course_key
from openedx.core.djangoapps.course_roles import course_permission_check, course_permissions_list_check_any

class IsStaffOrInstructor(BasePermission):
    """
    Check if user is global or course staff

    Permission that checks to see if the user is global staff, course
    staff, course admin,If none of those conditions are met, HTTP403 is returned.
    """

    def has_permission(self, request, view):
        course_key_string = view.kwargs.get('course_id')
        course_key = validate_course_key(course_key_string)

        if GlobalStaff().has_user(request.user):
            return True

        return (
            CourseInstructorRole(course_key).has_user(request.user) or
            CourseStaffRole(course_key).has_user(request.user) or 
            course_permission_check(request.user, "manage_content", course_key)
        )


class IsEnrolledOrStaff(BasePermission):
    """
    Check if user is enrolled in the course or staff
    """

    def has_permission(self, request, view):
        course_key_string = view.kwargs.get('course_id')
        course_key = validate_course_key(course_key_string)

        if GlobalStaff().has_user(request.user):
            return True

        permissions = ["view_all_content","view_only_live_published_content","view_all_published_content"]
        return (
            CourseInstructorRole(course_key).has_user(request.user) or
            CourseStaffRole(course_key).has_user(request.user) or
            course_permissions_list_check_any(request.user, permissions, course_key) or
            CourseEnrollment.is_enrolled(request.user, course_key)
        )
