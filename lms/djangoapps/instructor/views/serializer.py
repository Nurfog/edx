""" Instructor apis serializers. """

from django.contrib.auth.models import User  # lint-amnesty, pylint: disable=imported-auth-user
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from rest_framework import serializers
from .tools import get_student_from_identifier

from lms.djangoapps.instructor.access import ROLES
import dateutil
import pytz
import datetime


class RoleNameSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """
    Serializer that describes the response of the problem response report generation API.
    """

    rolename = serializers.CharField(help_text=_("Role name"))

    def validate_rolename(self, value):
        """
        Check that the rolename is valid.
        """
        if value not in ROLES:
            raise ValidationError(_("Invalid role name."))
        return value


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']


class AccessSerializer(serializers.Serializer):
    """
    Serializer for managing user access changes.
    This serializer validates and processes the data required to modify
    user access within a system.
    """
    unique_student_identifier = serializers.CharField(
        max_length=255,
        help_text="Email or username of user to change access"
    )
    rolename = serializers.CharField(
        help_text="Role name to assign to the user"
    )
    action = serializers.ChoiceField(
        choices=['allow', 'revoke'],
        help_text="Action to perform on the user's access"
    )

    def validate_unique_student_identifier(self, value):
        """
        Validate that the unique_student_identifier corresponds to an existing user.
        """
        try:
            user = get_student_from_identifier(value)
        except User.DoesNotExist:
            return None

        return user


class ShowStudentExtensionSerializer(serializers.Serializer):
    """
    Serializer for validating and processing the student identifier.
    """
    student = serializers.CharField(write_only=True, required=True)

    def validate_student(self, value):
        """
        Validate that the student corresponds to an existing user.
        """
        try:
            user = get_student_from_identifier(value)
        except User.DoesNotExist:
            return None

        return user


class SendEmailSerializer(serializers.Serializer):
    send_to = serializers.CharField(write_only=True, required=True)
    subject = serializers.CharField(write_only=True, required=True)
    message = serializers.CharField(required=True)

    schedule = serializers.CharField(required=False)

    def validate_schedule(self, value):
        if value:
            schedule_dt = dateutil.parser.parse(value).replace(tzinfo=pytz.utc)
            if schedule_dt < datetime.datetime.now(pytz.utc):
                raise serializers.ValidationError("the requested schedule is in the past")

        return value
