""" API implementation for user-oriented interactions. """

import logging

from django.contrib.auth.models import User, Group
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

from api_manager.permissions import ApiKeyHeaderPermission
from courseware import module_render
from courseware.model_data import FieldDataCache
from courseware.views import get_module_for_descriptor, save_child_position, get_current_child
from student.models import CourseEnrollment
from xmodule.modulestore.django import modulestore

log = logging.getLogger(__name__)


def _generate_base_uri(request):
    """
    Constructs the protocol:host:path component of the resource uri
    """
    protocol = 'http'
    if request.is_secure():
        protocol = protocol + 's'
    resource_uri = '{}://{}{}'.format(
        protocol,
        request.get_host(),
        request.path
    )
    return resource_uri


def _serialize_user(response_data, user):
    """
    Loads the object data into the response dict
    This should probably evolve to use DRF serializers
    """
    response_data['email'] = user.email
    response_data['username'] = user.username
    response_data['first_name'] = user.first_name
    response_data['last_name'] = user.last_name
    response_data['id'] = user.id
    return response_data


def _save_module_position(request, user, course_id, course_descriptor, position):
    """
    Records the indicated position for the specified course
    Really no reason to generalize this out of user_courses_detail aside from pylint complaining
    """
    field_data_cache = FieldDataCache([course_descriptor], course_id, user)
    if course_id == position['parent_module_id']:
        parent_module = get_module_for_descriptor(
            user,
            request,
            course_descriptor,
            field_data_cache,
            course_id
        )
    else:
        parent_module = module_render.get_module(
            user,
            request,
            position['parent_module_id'],
            field_data_cache,
            course_id
        )
    child_module = module_render.get_module(
        user,
        request,
        position['child_module_id'],
        field_data_cache,
        course_id
    )
    save_child_position(parent_module, child_module.location.name)
    saved_module = get_current_child(parent_module)
    return saved_module.id


@api_view(['POST'])
@permission_classes((ApiKeyHeaderPermission,))
def user_list(request):
    """
    POST creates a new user in the system
    """
    response_data = {}
    base_uri = _generate_base_uri(request)
    email = request.DATA['email']
    username = request.DATA['username']
    password = request.DATA['password']
    first_name = request.DATA.get('first_name', '')
    last_name = request.DATA.get('last_name', '')
    try:
        user = User.objects.create(email=email, username=username)
    except IntegrityError:
        user = None
    else:
        user.set_password(password)
        user.first_name = first_name
        user.last_name = last_name
        user.save()

    if user:
        status_code = status.HTTP_201_CREATED
        response_data = _serialize_user(response_data, user)
        response_data['uri'] = '{}/{}'.format(base_uri, str(user.id))
    else:
        status_code = status.HTTP_409_CONFLICT
        response_data['message'] = "User '%s' already exists", username
        response_data['field_conflict'] = "username"
    return Response(response_data, status=status_code)


@api_view(['GET', 'DELETE'])
@permission_classes((ApiKeyHeaderPermission,))
def user_detail(request, user_id):
    """
    GET retrieves an existing user from the system
    DELETE removes/inactivates/etc. an existing user
    """
    if request.method == 'GET':
        response_data = {}
        base_uri = _generate_base_uri(request)
        try:
            existing_user = User.objects.get(id=user_id, is_active=True)
            _serialize_user(response_data, existing_user)
            response_data['uri'] = base_uri
            response_data['resources'] = []
            resource_uri = '{}/groups'.format(base_uri)
            response_data['resources'].append({'uri': resource_uri})
            resource_uri = '{}/courses'.format(base_uri)
            response_data['resources'].append({'uri': resource_uri})
            return Response(response_data, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response(response_data, status=status.HTTP_404_NOT_FOUND)
    elif request.method == 'DELETE':
        response_data = {}
        try:
            existing_user = User.objects.get(id=user_id, is_active=True)
            existing_user.is_active = False
            existing_user.save()
        except ObjectDoesNotExist:
            # It's ok if we don't find a match
            pass
        return Response(response_data, status=status.HTTP_204_NO_CONTENT)


@api_view(['POST'])
@permission_classes((ApiKeyHeaderPermission,))
def user_groups_list(request, user_id):
    """
    POST creates a new user-group relationship in the system
    """
    response_data = {}
    group_id = request.DATA['group_id']
    base_uri = _generate_base_uri(request)
    response_data['uri'] = '{}/{}'.format(base_uri, str(group_id))
    try:
        existing_user = User.objects.get(id=user_id)
        existing_group = Group.objects.get(id=group_id)
    except ObjectDoesNotExist:
        existing_user = None
        existing_group = None
    if existing_user and existing_group:
        try:
            existing_relationship = existing_user.groups.get(id=existing_group.id)
        except ObjectDoesNotExist:
            existing_relationship = None
        if existing_relationship is None:
            existing_user.groups.add(existing_group.id)
            response_data['uri'] = '{}/{}'.format(base_uri, existing_user.id)
            response_data['group_id'] = str(existing_group.id)
            response_data['user_id'] = str(existing_user.id)
            response_status = status.HTTP_201_CREATED
        else:
            response_data['uri'] = '{}/{}'.format(base_uri, existing_group.id)
            response_data['message'] = "Relationship already exists."
            response_status = status.HTTP_409_CONFLICT
    else:
        response_status = status.HTTP_404_NOT_FOUND
    return Response(response_data, status=response_status)


@api_view(['GET', 'DELETE'])
@permission_classes((ApiKeyHeaderPermission,))
def user_groups_detail(request, user_id, group_id):
    """
    GET retrieves an existing user-group relationship from the system
    DELETE removes/inactivates/etc. an existing user-group relationship
    """
    if request.method == 'GET':
        response_data = {}
        base_uri = _generate_base_uri(request)
        try:
            existing_user = User.objects.get(id=user_id, is_active=True)
            existing_relationship = existing_user.groups.get(id=group_id)
        except ObjectDoesNotExist:
            existing_user = None
            existing_relationship = None
        if existing_user and existing_relationship:
            response_data['user_id'] = existing_user.id
            response_data['group_id'] = existing_relationship.id
            response_data['uri'] = base_uri
            response_status = status.HTTP_200_OK
        else:
            response_status = status.HTTP_404_NOT_FOUND
        return Response(response_data, status=response_status)
    elif request.method == 'DELETE':
        existing_user = User.objects.get(id=user_id, is_active=True)
        existing_user.groups.remove(group_id)
        existing_user.save()
        return Response({}, status=status.HTTP_204_NO_CONTENT)


@api_view(['POST', 'GET'])
@permission_classes((ApiKeyHeaderPermission,))
def user_courses_list(request, user_id):
    """
    POST creates a new course enrollment for a user
    GET creates the list of enrolled courses for a user
    """
    if request.method == 'POST':
        store = modulestore()
        response_data = {}
        user_id = user_id
        course_id = request.DATA['course_id']
        try:
            user = User.objects.get(id=user_id)
            course_descriptor = store.get_course(course_id)
        except (ObjectDoesNotExist, ValueError):
            user = None
            course_descriptor = None
        if user and course_descriptor:
            base_uri = _generate_base_uri(request)
            course_enrollment = CourseEnrollment.enroll(user, course_id)
            response_data['uri'] = '{}/{}'.format(base_uri, course_id)
            response_data['id'] = course_id
            response_data['name'] = course_descriptor.display_name
            response_data['is_active'] = course_enrollment.is_active
            status_code = status.HTTP_201_CREATED
        else:
            status_code = status.HTTP_404_NOT_FOUND
        return Response(response_data, status=status_code)
    elif request.method == 'GET':
        store = modulestore()
        response_data = []
        base_uri = _generate_base_uri(request)
        try:
            user = User.objects.get(id=user_id)
        except ObjectDoesNotExist:
            user = None
        if user:
            enrollments = CourseEnrollment.enrollments_for_user(user=user)
            for enrollment in enrollments:
                descriptor = store.get_course(enrollment.course_id)
                course_data = {
                    "id": enrollment.course_id,
                    "uri": '{}/{}'.format(base_uri, enrollment.course_id),
                    "is_active": enrollment.is_active,
                    "name": descriptor.display_name
                }
                response_data.append(course_data)
            return Response(response_data, status=status.HTTP_200_OK)
        else:
            status_code = status.HTTP_404_NOT_FOUND
        return Response(response_data, status=status_code)


@api_view(['GET', 'POST', 'DELETE'])
@permission_classes((ApiKeyHeaderPermission,))
def user_courses_detail(request, user_id, course_id):
    """
    GET identifies an ACTIVE course enrollment for the specified user
    DELETE unenrolls the specified user from a course
    """
    if request.method == 'GET':
        store = modulestore()
        response_data = {}
        base_uri = _generate_base_uri(request)
        try:
            user = User.objects.get(id=user_id, is_active=True)
            course_descriptor = store.get_course(course_id)
        except (ObjectDoesNotExist, ValueError):
            user = None
            course_descriptor = None
        if user and CourseEnrollment.is_enrolled(user, course_id):
            response_data['user_id'] = user.id
            response_data['course_id'] = course_id
            response_data['uri'] = base_uri
            field_data_cache = FieldDataCache([course_descriptor], course_id, user)
            course_module = module_render.get_module(
                user,
                request,
                course_descriptor.location,
                field_data_cache,
                course_id)
            response_data['position'] = course_module.position
            response_status = status.HTTP_200_OK
        else:
            response_status = status.HTTP_404_NOT_FOUND
        return Response(response_data, status=response_status)
    elif request.method == 'POST':
        store = modulestore()
        base_uri = _generate_base_uri(request)
        response_data = {}
        response_data['uri'] = base_uri
        try:
            user = User.objects.get(id=user_id)
            course_descriptor = store.get_course(course_id)
        except (ObjectDoesNotExist, ValueError):
            user = None
            course_descriptor = None
        if user and course_descriptor:
            response_data['user_id'] = user.id
            response_data['course_id'] = course_id
            response_status = status.HTTP_201_CREATED
            if request.DATA['position']:
                response_data['position'] = _save_module_position(
                    request,
                    user,
                    course_id,
                    course_descriptor,
                    request.DATA['position']
                )
        else:
            response_status = status.HTTP_404_NOT_FOUND
        return Response(response_data, status=response_status)
    elif request.method == 'DELETE':
        try:
            user = User.objects.get(id=user_id, is_active=True)
        except ObjectDoesNotExist:
            user = None
        if user:
            CourseEnrollment.unenroll(user, course_id)
        return Response({}, status=status.HTTP_204_NO_CONTENT)
