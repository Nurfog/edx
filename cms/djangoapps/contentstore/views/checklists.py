# lint-amnesty, pylint: disable=missing-module-docstring
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.views.decorators.csrf import ensure_csrf_cookie
from opaque_keys.edx.keys import CourseKey

from common.djangoapps.student.auth import has_course_author_access

__all__ = ['checklists_handler']


@login_required
@ensure_csrf_cookie
def checklists_handler(request, course_key_string=None):
    '''
    The restful handler for course checklists.
    It allows retrieval of the checklists (as an HTML page).
    '''
    course_key = CourseKey.from_string(course_key_string)
    if not has_course_author_access(request.user, course_key):
        raise PermissionDenied()
    mfe_base_url = settings.COURSE_AUTHORING_MICROFRONTEND_URL
    if mfe_base_url:
        studio_home_url = f'{mfe_base_url}/checklist'
        redirect(studio_home_url)
