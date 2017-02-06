"""
Implementation of "reverification" service to communicate with Reverification XBlock
"""

import logging

from django.core.exceptions import ObjectDoesNotExist
from django.core.urlresolvers import reverse
from django.db import IntegrityError

from opaque_keys.edx.keys import CourseKey

from student.models import User, CourseEnrollment
from student.helpers import check_verify_status_by_course
from lms.djangoapps.verify_student.models import VerificationCheckpoint, VerificationStatus, SkippedReverification

from .models import SoftwareSecurePhotoVerification

log = logging.getLogger(__name__)


class VerificationService(object):
    """
    Learner verification XBlock service
    """

    def get_status(self, user_id):
        """
        Returns the user's current photo verification status.

        Args:
            user_id: the user's id

        Returns: one of the following strings
            'none' - no such verification exists
            'expired' - verification has expired
            'approved' - verification has been approved
            'pending' - verification process is still ongoing
            'must_reverify' - verification has been denied and user must resubmit photos
        """
        user = User.objects.get(id=user_id)
        # TODO: provide a photo verification abstraction so that this
        # isn't hard-coded to use Software Secure.
        return SoftwareSecurePhotoVerification.user_status(user)

    def reverify_url(self):
        """
        Returns the URL for a user to verify themselves.
        """
        return reverse('verify_student_reverify')


class ReverificationService(object):
    """
    Reverification XBlock service
    """

    SKIPPED_STATUS = "skipped"
    NON_VERIFIED_TRACK = "not-verified"

    def get_status(self, user_id, course_id, related_assessment_location):
        """Get verification attempt status against a user for a given
        'checkpoint' and 'course_id'.

        Args:
            user_id (str): User Id string
            course_id (str): A string of course id
            related_assessment_location (str): Location of Reverification XBlock

        Returns: str or None
        """
        user = User.objects.get(id=user_id)
        course_key = CourseKey.from_string(course_id)

        if not CourseEnrollment.is_enrolled_as_verified(user, course_key):
            return self.NON_VERIFIED_TRACK
        elif SkippedReverification.check_user_skipped_reverification_exists(user_id, course_key):
            return self.SKIPPED_STATUS

        try:
            checkpoint_status = VerificationStatus.objects.filter(
                user_id=user_id,
                checkpoint__course_id=course_key,
                checkpoint__checkpoint_location=related_assessment_location
            ).latest()
            return checkpoint_status.status
        except ObjectDoesNotExist:
            return None

    def start_verification(self, course_id, related_assessment_location):
        """Create re-verification link against a verification checkpoint.

        Args:
            course_id(str): A string of course id
            related_assessment_location(str): Location of Reverification XBlock

        Returns:
            Re-verification link
        """
        course_key = CourseKey.from_string(course_id)

        # Get-or-create the verification checkpoint
        VerificationCheckpoint.get_or_create_verification_checkpoint(course_key, related_assessment_location)

        re_verification_link = reverse(
            'verify_student_incourse_reverify',
            args=(
                unicode(course_key),
                unicode(related_assessment_location)
            )
        )
        return re_verification_link

    def skip_verification(self, user_id, course_id, related_assessment_location):
        """Add skipped verification attempt entry for a user against a given
        'checkpoint'.

        Args:
            user_id(str): User Id string
            course_id(str): A string of course_id
            related_assessment_location(str): Location of Reverification XBlock

        Returns:
            None
        """
        course_key = CourseKey.from_string(course_id)
        checkpoint = VerificationCheckpoint.objects.get(
            course_id=course_key,
            checkpoint_location=related_assessment_location
        )
        user = User.objects.get(id=user_id)

        # user can skip a reverification attempt only if that user has not already
        # skipped an attempt
        try:
            SkippedReverification.add_skipped_reverification_attempt(checkpoint, user_id, course_key)
        except IntegrityError:
            log.exception("Skipped attempt already exists for user %s: with course %s:", user_id, unicode(course_id))
            return

        try:
            # Avoid circular import
            from openedx.core.djangoapps.credit.api import set_credit_requirement_status

            # As a user skips the reverification it declines to fulfill the requirement so
            # requirement sets to declined.
            set_credit_requirement_status(
                user,
                course_key,
                'reverification',
                checkpoint.checkpoint_location,
                status='declined'
            )

        except Exception as err:  # pylint: disable=broad-except
            log.error("Unable to add credit requirement status for user with id %d: %s", user_id, err)

    def get_attempts(self, user_id, course_id, related_assessment_location):
        """Get re-verification attempts against a user for a given 'checkpoint'
        and 'course_id'.

        Args:
            user_id(str): User Id string
            course_id(str): A string of course id
            related_assessment_location(str): Location of Reverification XBlock

        Returns:
            Number of re-verification attempts of a user
        """
        course_key = CourseKey.from_string(course_id)
        return VerificationStatus.get_user_attempts(user_id, course_key, related_assessment_location)

    def get_course_verification_status(self, user_id, course_id):
        """
        This xBlock service method will return the status of the course level verification status, which
        is not the same as in-course reverification. This verification status is normally shown to the user
        in his/her dashboard.

        This will return None if that user is either not enrolled in the course
        or if the user is not enrolled in the course under a course_mode that would
        require verification
        """

        user = User.objects.get(id=user_id)

        enrollment = CourseEnrollment.get_enrollment(user, course_id)
        if not enrollment:
            return None

        status = check_verify_status_by_course(user, [enrollment])

        # check_verify_status_by_course will not return an entry for
        # the requested course_id if the user is not enrolled
        # in the course that requires verification
        return status.get(course_id, {}).get('status')
