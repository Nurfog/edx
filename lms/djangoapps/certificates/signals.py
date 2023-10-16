"""
Signal handler for enabling/disabling self-generated certificates based on the course-pacing.
"""

import logging
from django.conf import settings

from django.db.models.signals import post_save
from django.dispatch import receiver
from openedx_events.event_bus import get_producer
from edx_django_utils.monitoring import set_custom_attribute

from common.djangoapps.course_modes import api as modes_api
from common.djangoapps.student.models import CourseEnrollment
from common.djangoapps.student.signals import ENROLLMENT_TRACK_UPDATED
from lms.djangoapps.certificates.config import SEND_CERTIFICATE_CREATED_SIGNAL, SEND_CERTIFICATE_REVOKED_SIGNAL
from lms.djangoapps.certificates.generation_handler import (
    CertificateGenerationNotAllowed,
    generate_allowlist_certificate_task,
    generate_certificate_task,
    is_on_certificate_allowlist
)
from lms.djangoapps.certificates.models import (
    CertificateAllowlist,
    CertificateGenerationCourseSetting,
    CertificateStatuses,
    GeneratedCertificate
)
from lms.djangoapps.certificates.api import auto_certificate_generation_enabled
from lms.djangoapps.verify_student.services import IDVerificationService
from openedx.core.djangoapps.content.course_overviews.signals import COURSE_PACING_CHANGED
from openedx.core.lib.events import determine_producer_config_for_signal_and_topic
from openedx.core.djangoapps.signals.signals import (
    COURSE_GRADE_NOW_FAILED,
    COURSE_GRADE_NOW_PASSED,
    LEARNER_NOW_VERIFIED
)
from openedx_events.learning.signals import CERTIFICATE_CREATED, CERTIFICATE_REVOKED

log = logging.getLogger(__name__)


@receiver(COURSE_PACING_CHANGED, dispatch_uid="update_cert_settings_on_pacing_change")
def _update_cert_settings_on_pacing_change(sender, updated_course_overview, **kwargs):  # pylint: disable=unused-argument
    """
    Catches the signal that course pacing has changed and enable/disable
    the self-generated certificates according to course-pacing.
    """
    CertificateGenerationCourseSetting.set_self_generation_enabled_for_course(
        updated_course_overview.id,
        updated_course_overview.self_paced,
    )
    log.info('Certificate Generation Setting Toggled for {course_id} via pacing change'.format(
        course_id=updated_course_overview.id
    ))


@receiver(post_save, sender=CertificateAllowlist, dispatch_uid="append_certificate_allowlist")
def _listen_for_certificate_allowlist_append(sender, instance, **kwargs):  # pylint: disable=unused-argument
    """
    Listen for a user being added to or modified on the allowlist
    """
    if not auto_certificate_generation_enabled():
        return

    if is_on_certificate_allowlist(instance.user, instance.course_id):
        log.info(f'User {instance.user.id} is now on the allowlist for course {instance.course_id}. Attempt will be '
                 f'made to generate an allowlist certificate.')
        return generate_allowlist_certificate_task(instance.user, instance.course_id)


@receiver(COURSE_GRADE_NOW_PASSED, dispatch_uid="new_passing_learner")
def listen_for_passing_grade(sender, user, course_id, **kwargs):  # pylint: disable=unused-argument
    """
    Listen for a signal indicating that the user has passed a course run.

    If needed, generate a certificate task.
    """
    if not auto_certificate_generation_enabled():
        return

    cert = GeneratedCertificate.certificate_for_student(user, course_id)
    if cert is not None and CertificateStatuses.is_passing_status(cert.status):
        log.info(f'The cert status is already passing for user {user.id} : {course_id}. Passing grade signal will be '
                 f'ignored.')
        return
    log.info(f'Attempt will be made to generate a course certificate for {user.id} : {course_id} as a passing grade '
             f'was received.')
    try:
        return generate_certificate_task(user, course_id)
    except CertificateGenerationNotAllowed as e:
        log.exception(
            "Certificate generation not allowed for user %s in course %s",
            str(user),
            course_id,
        )
        return False


@receiver(COURSE_GRADE_NOW_FAILED, dispatch_uid="new_failing_learner")
def _listen_for_failing_grade(sender, user, course_id, grade, **kwargs):  # pylint: disable=unused-argument
    """
    Listen for a signal indicating that the user has failed a course run.

    If needed, mark the certificate as notpassing.
    """
    if is_on_certificate_allowlist(user, course_id):
        log.info(f'User {user.id} is on the allowlist for {course_id}. The failing grade will not affect the '
                 f'certificate.')
        return

    cert = GeneratedCertificate.certificate_for_student(user, course_id)
    if cert is not None:
        if CertificateStatuses.is_passing_status(cert.status):
            enrollment_mode, __ = CourseEnrollment.enrollment_mode_for_user(user, course_id)
            cert.mark_notpassing(mode=enrollment_mode, grade=grade.percent, source='notpassing_signal')
            log.info(f'Certificate marked not passing for {user.id} : {course_id} via failing grade')


@receiver(LEARNER_NOW_VERIFIED, dispatch_uid="learner_track_changed")
def _listen_for_id_verification_status_changed(sender, user, **kwargs):  # pylint: disable=unused-argument
    """
    Listen for a signal indicating that the user's id verification status has changed.
    """
    if not auto_certificate_generation_enabled():
        return

    user_enrollments = CourseEnrollment.enrollments_for_user(user=user)
    expected_verification_status = IDVerificationService.user_status(user)
    expected_verification_status = expected_verification_status['status']

    for enrollment in user_enrollments:
        log.info(f'Attempt will be made to generate a course certificate for {user.id} : {enrollment.course_id}. Id '
                 f'verification status is {expected_verification_status}')
        try:
            generate_certificate_task(user, enrollment.course_id)
        except CertificateGenerationNotAllowed as e:
            log.exception(
                "Certificate generation not allowed for user %s in course %s",
                str(user),
                enrollment.course_id,
            )


@receiver(ENROLLMENT_TRACK_UPDATED)
def _listen_for_enrollment_mode_change(sender, user, course_key, mode, **kwargs):  # pylint: disable=unused-argument
    """
    Listen for the signal indicating that a user's enrollment mode has changed.

    If possible, grant the user a course certificate. Note that we intentionally do not revoke certificates here, even
    if the user has moved to the audit track.
    """
    if modes_api.is_eligible_for_certificate(mode):
        log.info(f'Attempt will be made to generate a course certificate for {user.id} : {course_key} since the '
                 f'enrollment mode is now {mode}.')
        try:
            return generate_certificate_task(user, course_key)
        except CertificateGenerationNotAllowed as e:
            log.exception(
                "Certificate generation not allowed for user %s in course %s",
                str(user),
                course_key,
            )
            return False


def _determine_producer_config_for_signal_and_topic(signal, topic):
    """
    Utility method to determine the setting for the given signal and topic in EVENT_BUS_PRODUCER_CONFIG

    Records to New Relic for later analysis.

    Parameters
        signal (OpenEdxPublicSignal): The signal being sent to the event bus
        topic (string): The topic to which the signal is being sent (without environment prefix)

    Returns
        True if the signal is enabled for that topic in EVENT_BUS_PRODUCER_CONFIG
        False if the signal is explicitly disabled for that topic in EVENT_BUS_PRODUCER_CONFIG
        None if the signal/topic pair is not present in EVENT_BUS_PRODUCER_CONFIG
    """
    event_type_producer_configs = getattr(settings, "EVENT_BUS_PRODUCER_CONFIG",
                                          {}).get(signal.event_type, {})
    topic_config = event_type_producer_configs.get(topic, {})
    topic_setting = topic_config.get('enabled', None)
    set_custom_attribute(f'producer_config_setting_{topic}_{signal.event_type}',
                         topic_setting if topic_setting is not None else 'Unset')
    return topic_setting


@receiver(CERTIFICATE_CREATED)
def listen_for_certificate_created_event(sender, signal, **kwargs):  # pylint: disable=unused-argument
    """
    Publish `CERTIFICATE_CREATED` events to the event bus.
    """
    # temporary: defer to EVENT_BUS_PRODUCER_CONFIG if present
    producer_config_setting = determine_producer_config_for_signal_and_topic(CERTIFICATE_CREATED,
                                                                             'learning-certificate-lifecycle')
    if producer_config_setting is True:
        log.info("Producing certificate-created event via config")
        return
    if SEND_CERTIFICATE_CREATED_SIGNAL.is_enabled():
        log.info("Producing certificate-created event via manual send")
        get_producer().send(
            signal=CERTIFICATE_CREATED,
            topic='learning-certificate-lifecycle',
            event_key_field='certificate.course.course_key',
            event_data={'certificate': kwargs['certificate']},
            event_metadata=kwargs['metadata']
        )


@receiver(CERTIFICATE_REVOKED)
def listen_for_certificate_revoked_event(sender, signal, **kwargs):  # pylint: disable=unused-argument
    """
    Publish `CERTIFICATE_REVOKED` events to the event bus.
    """
    # temporary: defer to EVENT_BUS_PRODUCER_CONFIG if present
    producer_config_setting = determine_producer_config_for_signal_and_topic(CERTIFICATE_REVOKED,
                                                                             'learning-certificate-lifecycle')
    if producer_config_setting is True:
        log.info("Producing certificate-revoked event via config")
        return
    if SEND_CERTIFICATE_REVOKED_SIGNAL.is_enabled():
        log.info("Producing certificate-revoked event via manual send")
        get_producer().send(
            signal=CERTIFICATE_REVOKED,
            topic='learning-certificate-lifecycle',
            event_key_field='certificate.course.course_key',
            event_data={'certificate': kwargs['certificate']},
            event_metadata=kwargs['metadata']
        )
