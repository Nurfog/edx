# -*- coding: utf-8 -*-
"""
ProgramEnrollment Views
"""
from __future__ import unicode_literals

from functools import wraps

from django.http import Http404
from edx_rest_framework_extensions import permissions
from edx_rest_framework_extensions.auth.jwt.authentication import JwtAuthentication
from edx_rest_framework_extensions.auth.session.authentication import SessionAuthenticationAllowInactiveUser
from opaque_keys.edx.keys import CourseKey
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.pagination import CursorPagination
from rest_framework.response import Response

from lms.djangoapps.program_enrollments.api.v1.constants import CourseEnrollmentResponseStatuses, MAX_ENROLLMENT_RECORDS
from lms.djangoapps.program_enrollments.api.v1.serializers import (
    ProgramCourseEnrollmentListSerializer,
    ProgramCourseEnrollmentRequestSerializer,
    ProgramEnrollmentListSerializer,
)
from lms.djangoapps.program_enrollments.models import ProgramCourseEnrollment, ProgramEnrollment
from openedx.core.djangoapps.catalog.utils import get_programs
from openedx.core.djangoapps.content.course_overviews.models import CourseOverview
from openedx.core.lib.api.authentication import OAuth2AuthenticationAllowInactiveUser
from openedx.core.lib.api.view_utils import DeveloperErrorViewMixin, PaginatedAPIView, verify_course_exists
from util.query import use_read_replica_if_available


def verify_program_exists(view_func):
    """
    Raises:
        An API error if the `program_uuid` kwarg in the wrapped function
        does not exist in the catalog programs cache.
    """
    @wraps(view_func)
    def wrapped_function(self, request, **kwargs):
        """
        Wraps the given view_function.
        """
        program_uuid = kwargs['program_uuid']
        program = get_programs(uuid=program_uuid)
        if not program:
            raise self.api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                developer_message='no program exists with given key',
                error_code='program_does_not_exist'
            )
        return view_func(self, request, **kwargs)
    return wrapped_function


class ProgramEnrollmentPagination(CursorPagination):
    """
    Pagination class for Program Enrollments.
    """
    ordering = 'id'
    page_size = 100
    page_size_query_param = 'page_size'

    def get_page_size(self, request):
        """
        Get the page size based on the defined page size parameter if defined.
        """
        try:
            page_size_string = request.query_params[self.page_size_query_param]
            return int(page_size_string)
        except (KeyError, ValueError):
            pass

        return self.page_size


class ProgramEnrollmentsView(DeveloperErrorViewMixin, PaginatedAPIView):
    """
    A view for Create/Read/Update methods on Program Enrollment data.

    Path: `/api/program_enrollments/v1/programs/{program_uuid}/enrollments/`
    The path can contain an optional `page_size?=N` query parameter.  The default page size is 100.

    Returns:
      * 200: OK - Contains a paginated set of program enrollment data.
      * 401: The requesting user is not authenticated.
      * 403: The requesting user lacks access for the given program.
      * 404: The requested program does not exist.

    Response:
    In the case of a 200 response code, the response will include a paginated
    data set.  The `results` section of the response consists of a list of
    program enrollment records, where each record contains the following keys:
      * student_key: The identifier of the student enrolled in the program.
      * status: The student's enrollment status.
      * account_exists: A boolean indicating if the student has created an edx-platform user account.
      * curriculum_uuid: The curriculum UUID of the enrollment record for the (student, program).

    Example:
    {
        "next": null,
        "previous": "http://testserver.com/api/program_enrollments/v1/programs/{program_uuid}/enrollments/?curor=abcd",
        "results": [
            {
                "student_key": "user-0", "status": "pending",
                "account_exists": False, "curriculum_uuid": "00000000-1111-2222-3333-444444444444"
            },
            {
                "student_key": "user-1", "status": "pending",
                "account_exists": False, "curriculum_uuid": "00000001-1111-2222-3333-444444444444"
            },
            {
                "student_key": "user-2", "status": "enrolled",
                "account_exists": True, "curriculum_uuid": "00000002-1111-2222-3333-444444444444"
            },
            {
                "student_key": "user-3", "status": "enrolled",
                "account_exists": True, "curriculum_uuid": "00000003-1111-2222-3333-444444444444"
            },
        ],
    }

    """
    authentication_classes = (
        JwtAuthentication,
        OAuth2AuthenticationAllowInactiveUser,
        SessionAuthenticationAllowInactiveUser,
    )
    permission_classes = (permissions.JWT_RESTRICTED_APPLICATION_OR_USER_ACCESS,)
    pagination_class = ProgramEnrollmentPagination

    @verify_program_exists
    def get(self, request, program_uuid=None):
        """ Defines the GET list endpoint for ProgramEnrollment objects. """
        enrollments = use_read_replica_if_available(
            ProgramEnrollment.objects.filter(program_uuid=program_uuid)
        )
        paginated_enrollments = self.paginate_queryset(enrollments)
        serializer = ProgramEnrollmentListSerializer(paginated_enrollments, many=True)
        return self.get_paginated_response(serializer.data)


class ProgramSpecificViewMixin(object):
    """
    A mixin for views that operate on or within a specific program.
    """

    @property
    def program(self):
        """
        The program specified by the `program_uuid` URL parameter.
        """
        program = get_programs(uuid=self.kwargs['program_uuid'])
        if program is None:
            raise Http404()
        return program


class ProgramCourseRunSpecificViewMixin(ProgramSpecificViewMixin):
    """
    A mixin for views that operate on or within a specific course run in a program
    """

    def check_course_existence_and_membership(self):
        """
        Attempting to look up the course and program will trigger 404 responses if:
        - The program does not exist
        - The course run (course_key) does not exist
        - The course run is not part of the program
        """
        self.course_run  # pylint: disable=pointless-statement

    @property
    def course_run(self):
        """
        The course run specified by the `course_id` URL parameter.
        """
        try:
            CourseOverview.get_from_id(self.course_key)
        except CourseOverview.DoesNotExist:
            raise Http404()
        for course in self.program["courses"]:
            for course_run in course["course_runs"]:
                if self.course_key == CourseKey.from_string(course_run["key"]):
                    return course_run
        raise Http404()

    @property
    def course_key(self):
        """
        The course key for the course run specified by the `course_id` URL parameter.
        """
        return CourseKey.from_string(self.kwargs['course_id'])


# pylint: disable=line-too-long
class ProgramCourseEnrollmentsView(DeveloperErrorViewMixin, ProgramCourseRunSpecificViewMixin, PaginatedAPIView):
    """
    A view for enrolling students in a course through a program,
    modifying program course enrollments, and listing program course
    enrollments.

    Path: ``/api/program_enrollments/v1/programs/{program_uuid}/courses/{course_id}/enrollments/``

    Accepts: [GET, POST]

    For GET requests, the path can contain an optional `page_size?=N` query parameter.
    The default page size is 100.

    ------------------------------------------------------------------------------------
    POST
    ------------------------------------------------------------------------------------

    **Returns**

        * 200: Returns a map of students and their enrollment status.
        * 207: Not all students enrolled. Returns resulting enrollment status.
        * 401: User is not authenticated
        * 403: User lacks read access organization of specified program.
        * 404: Program does not exist, or course does not exist in program
        * 422: Invalid request, unable to enroll students.

    ------------------------------------------------------------------------------------
    GET
    ------------------------------------------------------------------------------------

    **Returns**

        * 200: OK - Contains a paginated set of program course enrollment data.
        * 401: The requesting user is not authenticated.
        * 403: The requesting user lacks access for the given program/course.
        * 404: The requested program or course does not exist.

    **Response**

        In the case of a 200 response code, the response will include a paginated
        data set.  The `results` section of the response consists of a list of
        program course enrollment records, where each record contains the following keys:
          * student_key: The identifier of the student enrolled in the program and course.
          * status: The student's course enrollment status.
          * account_exists: A boolean indicating if the student has created an edx-platform user account.
          * curriculum_uuid: The curriculum UUID of the enrollment record for the (student, program).

    **Example**

        {
            "next": null,
            "previous": "http://testserver.com/api/program_enrollments/v1/programs/{program_uuid}/courses/{course_id}/enrollments/?curor=abcd",
            "results": [
                {
                    "student_key": "user-0", "status": "inactive",
                    "account_exists": False, "curriculum_uuid": "00000000-1111-2222-3333-444444444444"
                },
                {
                    "student_key": "user-1", "status": "inactive",
                    "account_exists": False, "curriculum_uuid": "00000001-1111-2222-3333-444444444444"
                },
                {
                    "student_key": "user-2", "status": "active",
                    "account_exists": True, "curriculum_uuid": "00000002-1111-2222-3333-444444444444"
                },
                {
                    "student_key": "user-3", "status": "active",
                    "account_exists": True, "curriculum_uuid": "00000003-1111-2222-3333-444444444444"
                },
            ],
        }

    """
    authentication_classes = (
        JwtAuthentication,
        OAuth2AuthenticationAllowInactiveUser,
        SessionAuthenticationAllowInactiveUser,
    )
    permission_classes = (permissions.JWT_RESTRICTED_APPLICATION_OR_USER_ACCESS,)
    pagination_class = ProgramEnrollmentPagination

    @verify_course_exists
    @verify_program_exists
    def get(self, request, program_uuid=None, course_id=None):
        """ Defines the GET list endpoint for ProgramCourseEnrollment objects. """
        course_key = CourseKey.from_string(course_id)
        enrollments = use_read_replica_if_available(
            ProgramCourseEnrollment.objects.filter(
                program_enrollment__program_uuid=program_uuid, course_key=course_key
            ).select_related(
                'program_enrollment'
            )
        )
        paginated_enrollments = self.paginate_queryset(enrollments)
        serializer = ProgramCourseEnrollmentListSerializer(paginated_enrollments, many=True)
        return self.get_paginated_response(serializer.data)

    def post(self, request, program_uuid=None, course_id=None):
        """
        Enroll a list of students in a course in a program
        """
        self.check_course_existence_and_membership()
        results = {}
        seen_student_keys = set()
        enrollments = []

        if not isinstance(request.data, list):
            return Response('invalid enrollment record', status.HTTP_422_UNPROCESSABLE_ENTITY)
        if len(request.data) > MAX_ENROLLMENT_RECORDS:
            return Response(
                'enrollment limit 25', status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
            )

        try:
            for enrollment_request in request.data:
                error_status = self.check_enrollment_request(enrollment_request, seen_student_keys)
                if error_status:
                    results[enrollment_request["student_key"]] = error_status
                else:
                    enrollments.append(enrollment_request)
        except KeyError:  # student_key is not in enrollment_request
            return Response('invalid enrollment record', status.HTTP_422_UNPROCESSABLE_ENTITY)
        except TypeError:  # enrollment_request isn't a dict
            return Response('invalid enrollment record', status.HTTP_422_UNPROCESSABLE_ENTITY)
        except ValidationError:  # there was some other error raised by the serializer
            return Response('invalid enrollment record', status.HTTP_422_UNPROCESSABLE_ENTITY)

        program_enrollments = self.get_existing_program_enrollments(program_uuid, enrollments)
        for enrollment in enrollments:
            student_key = enrollment["student_key"]
            if student_key in results and results[student_key] == CourseEnrollmentResponseStatuses.DUPLICATED:
                continue
            results[student_key] = self.enroll_learner_in_course(enrollment, program_enrollments)

        good_count = sum(1 for _, v in results.items() if v not in CourseEnrollmentResponseStatuses.ERROR_STATUSES)
        if not good_count:
            return Response(results, status.HTTP_422_UNPROCESSABLE_ENTITY)
        if good_count != len(results):
            return Response(results, status.HTTP_207_MULTI_STATUS)
        else:
            return Response(results)

    def check_enrollment_request(self, enrollment, seen_student_keys):
        """
        Checks that the given enrollment record is valid and hasn't been duplicated
        """
        student_key = enrollment['student_key']
        if student_key in seen_student_keys:
            return CourseEnrollmentResponseStatuses.DUPLICATED
        seen_student_keys.add(student_key)
        enrollment_serializer = ProgramCourseEnrollmentRequestSerializer(data=enrollment)
        try:
            enrollment_serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            if enrollment_serializer.has_invalid_status():
                return CourseEnrollmentResponseStatuses.INVALID_STATUS
            else:
                raise e

    def get_existing_program_enrollments(self, program_uuid, enrollments):
        """
        Parameters:
            - enrollments: A list of enrollment requests
        Returns:
            - Dictionary mapping all student keys in the enrollment requests
              to that user's existing program enrollment in <self.program>
        """
        external_user_keys = [e["student_key"] for e in enrollments]
        existing_enrollments = ProgramEnrollment.objects.filter(
            external_user_key__in=external_user_keys,
            program_uuid=program_uuid,
        )
        existing_enrollments = existing_enrollments.prefetch_related('program_course_enrollments')
        return {enrollment.external_user_key: enrollment for enrollment in existing_enrollments}

    def enroll_learner_in_course(self, enrollment_request, program_enrollments):
        """
        Attempts to enroll the specified user into the course as a part of the
         given program enrollment with the given status

        Returns the actual status
        """
        student_key = enrollment_request['student_key']
        try:
            program_enrollment = program_enrollments[student_key]
        except KeyError:
            return CourseEnrollmentResponseStatuses.NOT_IN_PROGRAM
        if program_enrollment.get_program_course_enrollment(self.course_key):
            return CourseEnrollmentResponseStatuses.CONFLICT

        enrollment_status = ProgramCourseEnrollment.enroll(
            program_enrollment,
            self.course_key,
            enrollment_request['status']
        )
        return enrollment_status
