# -*- coding: utf-8 -*-
"""
Views for block structure api endpoints.
"""
import logging

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework_oauth.authentication import OAuth2Authentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from opaque_keys import InvalidKeyError
from opaque_keys.edx.keys import CourseKey

from openedx.core.djangoapps.content.block_structure.api import\
    clear_course_from_cache

LOGGER = logging.getLogger(__name__)


class ClearCoursesCacheView(APIView):
    """
        **Use Cases**
            Given a list of courses id it will clear the courses cache
        **Example Requests**:
            POST /api/content/v1/block-structure/clear-courses-cache/
        **Response Values for POST**
            HttpResponse: 200
            Dict: {
                success_clear_courses_cache: sucessful clear courses cache
                error_clear_courses_cache: failed clear courses cache
            }
    """
    authentication_classes = (OAuth2Authentication, SessionAuthentication,)

    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        """
            Clear cache of a list of courses
            Payload: list of courses id
            Response:
                - 200: {
                    success_clear_courses_cache: list of courses id
                    error_clear_courses_cache: list of courses id
                }
                - 400: {
                    error_message": "No courses id, at least provide one."
                }
        """
        courses_id = request.data.get('courses_id', None)
        success_clear_courses_cache = []
        error_clear_courses_cache = []
        if courses_id and len(courses_id) > 0:
            for course_id in courses_id:
                try:
                    course_key = CourseKey.from_string(course_id)
                    clear_course_from_cache(course_key)
                    success_clear_courses_cache.append(course_id)
                except InvalidKeyError:
                    LOGGER.error("Invalid course key: {}".format(courses_id))
                    error_clear_courses_cache.append(course_id)

            return Response(
                {
                    "success_clear_courses_cache": success_clear_courses_cache,
                    "error_clear_courses_cache": error_clear_courses_cache
                },
                status=status.HTTP_200_OK
            )

        return Response(
            {"error_message": "No courses id, at least provide one."},
            status=status.HTTP_400_BAD_REQUEST
        )
