""" Views for a student's profile information. """

from django.http import (
    QueryDict, HttpResponse,
    HttpResponseBadRequest, HttpResponseServerError
)
from django.conf import settings
from django_future.csrf import ensure_csrf_cookie
from django.contrib.auth.decorators import login_required
from edxmako.shortcuts import render_to_response
from user_api.api import profile as profile_api
from third_party_auth import pipeline


@login_required
def index(request):
    """View or modify the student's profile.

    GET: Retrieve the user's profile information.
    PUT: Update the user's profile information.  Currently the only accept param is "fullName".

    Args:
        request (HttpRequest)

    Returns:
        HttpResponse: 200 if successful on GET
        HttpResponse: 204 if successful on PUT
        HttpResponse: 302 if not logged in (redirect to login page)
        HttpResponse: 400 if the updated information is invalid
        HttpResponse: 405 if using an unsupported HTTP method
        HttpResponse: 500 if an unexpected error occurs.

    """
    if request.method == "GET":
        return _get_profile(request)
    elif request.method == "PUT":
        return _update_profile(request)
    else:
        return HttpResponse(status=405)


def _get_profile(request):
    """Retrieve the user's profile information, including an HTML form
    that students can use to update the information.

    Args:
        request (HttpRequest)

    Returns:
        HttpResponse

    """
    user = request.user

    context = {
        'disable_courseware_js': True
    }

    if settings.FEATURES.get('ENABLE_THIRD_PARTY_AUTH'):
        context['provider_user_states'] = pipeline.get_provider_user_states(user)

    return render_to_response('student_profile/index.html', context)


@ensure_csrf_cookie
def _update_profile(request):
    """Update a user's profile information.

    Args:
        request (HttpRequest)

    Returns:
        HttpResponse

    """
    put = QueryDict(request.body)

    username = request.user.username
    new_name = put.get('fullName')

    if new_name is None:
        return HttpResponseBadRequest("Missing param 'fullName'")

    try:
        profile_api.update_profile(username, full_name=new_name)
    except profile_api.ProfileInvalidField:
        return HttpResponseBadRequest()
    except profile_api.ProfileUserNotFound:
        return HttpResponseServerError()

    # A 204 is intended to allow input for actions to take place
    # without causing a change to the user agent's active document view.
    return HttpResponse(status=204)
