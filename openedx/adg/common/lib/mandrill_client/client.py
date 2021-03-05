"""
Mandrill Client to send ADG emails
"""
import logging

import mandrill
from django.conf import settings

from .email_data import EmailData

log = logging.getLogger(__name__)


class MandrillClient(object):
    """
    Mandrill class to send ADG emails
    """
    CHANGE_USER_EMAIL_ALERT = 'adg-confirm-email-address-change'
    COURSE_ENROLLMENT_INVITATION = 'adg-invitation-course'
    ENROLLMENT_CONFIRMATION = 'adg-enrollment-confirmation'
    PASSWORD_RESET = 'adg-password-reset'
    USER_ACCOUNT_ACTIVATION = 'adg-user-activation-email'
    VERIFY_CHANGE_USER_EMAIL = 'adg-verify-email-address-change-step-2'
    APPLICATION_SUBMISSION_CONFIRMATION = 'adg-application-submission-confirmation-1'
    APPLICATION_WAITLISTED = 'adg-waitlisted-application'
    APPLICATION_ACCEPTED = 'adg-application-accepted'

    def __init__(self):
        self.mandrill_client = mandrill.Mandrill(settings.MANDRILL_API_KEY)

    def _send_mail(self, email_data):
        """
        Calls the mandrill API for the specific template and email

        Arguments:
            email_data (EmailData): all the data related to email

        Returns:
            list: list of dictionaries containing mandrill responses
        """
        try:
            result = self.mandrill_client.messages.send_template(
                template_name=email_data.template_name,
                template_content=[],
                message=email_data.message,
            )
            log.info(result)
        except mandrill.Error as e:
            log.error('A mandrill error occurred: {exception_class} - {exception}'.format(
                exception_class=e.__class__, exception=e)
            )
            raise
        return result

    def send_mandrill_email(self, template, email, context):
        """
        Creates EmailData object and calls _send_email

        Arguments:
            template (str): String containing template id
            email (str): Email address of user
            context (dict): Dictionary containing email content

        Returns:
            None
        """
        log.info(
            'Preparing data using template: %s, account: %s and context: %s for email and sending it using mandrill',
            template,
            email,
            context
        )

        email_data = EmailData(template, email, context)
        self._send_mail(email_data)
