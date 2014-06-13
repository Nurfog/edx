import json
import copy

from util.json_request import JsonResponse
from django.http import HttpResponseBadRequest
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django_future.csrf import ensure_csrf_cookie
from edxmako.shortcuts import render_to_response
from django.http import HttpResponseNotFound
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from opaque_keys.edx.keys import CourseKey
from xmodule.modulestore.django import modulestore

from .access import has_course_access
from .xblock import get_course_xblock_type_info, get_xblock_type_display_name

__all__ = ['dashboard_handler']


# pylint: disable=unused-argument
@require_http_methods(("GET", "POST", "PUT"))
@login_required
@ensure_csrf_cookie
def dashboard_handler(request, course_key_string, xblock_type_name=None):
    """
    The restful handler for checklists.

    GET
        html: return html page for all checklists
        json: return json representing all checklists. checklist_index is not supported for GET at this time.
    POST or PUT
        json: updates the checked state for items within a particular checklist. checklist_index is required.
    """
    course_key = CourseKey.from_string(course_key_string)
    if not has_course_access(request.user, course_key):
        raise PermissionDenied()

    course_module = modulestore().get_course(course_key)

    json_request = 'application/json' in request.META.get('HTTP_ACCEPT', 'application/json')
    if request.method == 'GET':
        if json_request:
            return HttpResponseBadRequest(
                "JSON support not implemented yet",
                content_type="text/plain"
            )
        else:
            dashboard_url = reverse('contentstore.views.dashboard_handler', kwargs={
                'course_key_string': course_module.id
            })
            xblock_type_info = get_course_xblock_type_info(course_module)
            has_admin_view = xblock_type_name
            return render_to_response(
                'dashboard.html',
                {
                    'context_course': course_module,
                    'xblock_type_info': xblock_type_info,
                    'xblock_type_name': xblock_type_name,
                    'xblock_type_display_name':
                        get_xblock_type_display_name(xblock_type_name) if xblock_type_name else None,
                    'dashboard_url': dashboard_url,
                    'has_admin_view': has_admin_view,
                })
    elif json_request:
        return HttpResponseBadRequest(
            "JSON support not implemented yet",
            content_type="text/plain"
        )
    else:
        return HttpResponseNotFound()
