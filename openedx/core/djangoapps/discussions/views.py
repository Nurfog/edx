"""
Handle view-logic for the discussions app.
"""
from typing import Dict

import edx_api_doc_tools as apidocs
from edx_rest_framework_extensions.auth.jwt.authentication import JwtAuthentication
from edx_rest_framework_extensions.auth.session.authentication import SessionAuthenticationAllowInactiveUser
from rest_framework.exceptions import ValidationError
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from lms.djangoapps.discussion.toggles import ENABLE_DISCUSSIONS_MFE
from openedx.core.djangoapps.content.course_overviews.models import CourseOverview
from openedx.core.lib.api.authentication import BearerAuthenticationAllowInactiveUser
from openedx.core.lib.api.view_utils import validate_course_key
from .models import AVAILABLE_PROVIDER_MAP, DiscussionsConfiguration, Features, Provider
from .permissions import IsStaffOrCourseTeam, check_course_permissions
from .serializers import (
    DiscussionsConfigurationSerializer,
    DiscussionsProvidersSerializer,
)


class DiscussionsConfigurationView(APIView):
    """
    Handle configuration-related view-logic
    """
    authentication_classes = (
        JwtAuthentication,
        BearerAuthenticationAllowInactiveUser,
        SessionAuthenticationAllowInactiveUser
    )
    permission_classes = (IsStaffOrCourseTeam,)

    @apidocs.schema(
        parameters=[
            apidocs.string_parameter(
                'course_id',
                apidocs.ParameterLocation.PATH,
                description="The course for which to get provider list",
            ),
            apidocs.string_parameter(
                'provider_id',
                apidocs.ParameterLocation.QUERY,
                description="The provider_id to fetch data for"
            )
        ],
        responses={
            200: DiscussionsConfigurationSerializer,
            400: "Invalid provider ID",
            401: "The requester is not authenticated.",
            403: "The requester cannot access the specified course.",
            404: "The requested course does not exist.",
        },
    )
    def get(self, request: Request, course_key_string: str, **_kwargs) -> Response:
        """
        Handle HTTP/GET requests
        """
        data = self.get_configuration_data(request, course_key_string)
        return Response(data)

    @staticmethod
    def get_configuration_data(request: Request, course_key_string: str) -> Dict:
        course_key = validate_course_key(course_key_string)
        configuration = DiscussionsConfiguration.get(course_key)
        provider_type = request.query_params.get('provider_id', None)
        if provider_type and provider_type not in AVAILABLE_PROVIDER_MAP:
            raise ValidationError("Unsupported provider type")
        serializer = DiscussionsConfigurationSerializer(
            configuration,
            context={
                'user_id': request.user.id,
                'provider_type': provider_type,
            }
        )
        return serializer.data

    def post(self, request, course_key_string: str, **_kwargs) -> Response:
        """
        Handle HTTP/POST requests
        """
        data = self.update_configuration_data(request, course_key_string)
        return Response(data)

    @staticmethod
    def update_configuration_data(request, course_key_string):
        course_key = validate_course_key(course_key_string)
        configuration = DiscussionsConfiguration.get(course_key)
        course = CourseOverview.get_from_id(course_key)
        serializer = DiscussionsConfigurationSerializer(
            configuration,
            context={
                'user_id': request.user.id,
            },
            data=request.data,
            partial=True,
        )
        if serializer.is_valid(raise_exception=True):
            new_provider_type = serializer.validated_data.get('provider_type', None)
            if new_provider_type is not None and new_provider_type != configuration.provider_type:
                check_course_permissions(course, request.user, 'change_provider')

            serializer.save()
        return serializer.data


class DiscussionsProvidersView(APIView):
    """
    Handle configuration-related view-logic
    """
    authentication_classes = (
        JwtAuthentication,
        BearerAuthenticationAllowInactiveUser,
        SessionAuthenticationAllowInactiveUser
    )
    permission_classes = (IsStaffOrCourseTeam,)

    @apidocs.schema(
        parameters=[
            apidocs.string_parameter(
                'course_id',
                apidocs.ParameterLocation.PATH,
                description="The course for which to get provider list",
            )
        ],
        responses={
            200: DiscussionsProvidersSerializer,
            401: "The requester is not authenticated.",
            403: "The requester cannot access the specified course.",
            404: "The requested course does not exist.",
        },
    )
    def get(self, request, course_key_string: str, **_kwargs) -> Response:
        """
        Handle HTTP/GET requests
        """
        data = self.get_provider_data(course_key_string)
        return Response(data)

    @staticmethod
    def get_provider_data(course_key_string: str):
        course_key = validate_course_key(course_key_string)
        configuration = DiscussionsConfiguration.get(course_key)
        hidden_providers = []
        # If the user is currently using the legacy provider, don't show the new provider
        # TODO: Allow switching between legacy and new providers
        if configuration.provider_type == Provider.LEGACY:
            hidden_providers.append(Provider.OPEN_EDX)
        # If the user is currently using the new provider, don't show the legacy provider
        elif configuration.provider_type == Provider.OPEN_EDX:
            hidden_providers.append(Provider.LEGACY)
        else:
            # If this is a new course, or some other provider is selected, the new provider
            # should only show up if the MFE is enabled
            if not ENABLE_DISCUSSIONS_MFE.is_enabled(course_key):
                hidden_providers.append(Provider.OPEN_EDX)
        serializer = DiscussionsProvidersSerializer(
            {
                'features': [
                    {'id': feature.value, 'feature_support_type': feature.feature_support_type}
                    for feature in Features
                ],
                'active': configuration.provider_type,
                'available': {
                    key: value
                    for key, value in AVAILABLE_PROVIDER_MAP.items()
                    if key not in hidden_providers
                },
            }
        )
        return serializer.data


class CombinedDiscussionsConfigurationView(DiscussionsConfigurationView):
    """
    Handle configuration-related view-logic
    """

    def get(self, request: Request, course_key_string: str, **_kwargs) -> Response:
        """
        Handle HTTP/GET requests
        """
        config_data = self.get_configuration_data(request, course_key_string)
        provider_data = DiscussionsProvidersView.get_provider_data(course_key_string)
        return Response({
            **config_data,
            "features": provider_data["features"],
            "providers": {
                "active": provider_data["active"],
                "available": provider_data["available"],
            },
        })

    def post(self, request, course_key_string: str, **_kwargs) -> Response:
        """
        Handle HTTP/POST requests
        """
        config_data = self.update_configuration_data(request, course_key_string)
        provider_data = DiscussionsProvidersView.get_provider_data(course_key_string)
        return Response(
            {
                **config_data,
                "features": provider_data["features"],
                "providers": {
                    "active": provider_data["active"],
                    "available": provider_data["available"],
                },
            }
        )
