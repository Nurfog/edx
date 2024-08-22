"""
Unit tests for the DiscussionNotificationSender class
"""
import re
import unittest
from unittest.mock import MagicMock, patch

import pytest

from lms.djangoapps.discussion.rest_api.discussions_notifications import DiscussionNotificationSender, \
    clean_thread_html_body


@patch('lms.djangoapps.discussion.rest_api.discussions_notifications.DiscussionNotificationSender'
       '._create_cohort_course_audience', return_value={})
@patch('lms.djangoapps.discussion.rest_api.discussions_notifications.DiscussionNotificationSender'
       '._send_course_wide_notification')
@pytest.mark.django_db
class TestDiscussionNotificationSender(unittest.TestCase):
    """
    Tests for the DiscussionNotificationSender class
    """

    def setUp(self):
        self.thread = MagicMock()
        self.course = MagicMock()
        self.creator = MagicMock()
        self.notification_sender = DiscussionNotificationSender(self.thread, self.course, self.creator)

    def _setup_thread(self, thread_type, body, depth):
        """
        Helper to set up the thread object
        """
        self.thread.type = thread_type
        self.thread.body = body
        self.thread.depth = depth
        self.creator.username = 'test_user'

    def _assert_send_notification_called_with(self, mock_send_notification, expected_content_type):
        """
        Helper to assert that the send_notification method was called with the correct arguments
        """
        notification_type, audience_filters, context = mock_send_notification.call_args[0]
        mock_send_notification.assert_called_once()

        self.assertEqual(notification_type, "content_reported")
        self.assertEqual(context, {
            'username': self.thread.username,
            'content_type': expected_content_type,
            'content': 'Thread body'
        })
        self.assertEqual(audience_filters, {
            'discussion_roles': ['Administrator', 'Moderator', 'Community TA']
        })
        self.assertEqual(len(audience_filters), 1)
        self.assertEqual(list(audience_filters.keys()), ['discussion_roles'])

    def test_send_reported_content_notification_for_response(self, mock_send_notification, mock_create_audience):
        """
        Test that the send_reported_content_notification method calls the send_notification method with the correct
        arguments for a comment with depth 0
        """
        self._setup_thread('comment', '<p>Thread body</p>', 0)
        mock_create_audience.return_value = {}

        self.notification_sender.send_reported_content_notification()

        self._assert_send_notification_called_with(mock_send_notification, 'response')

    def test_send_reported_content_notification_for_comment(self, mock_send_notification, mock_create_audience):
        """
        Test that the send_reported_content_notification method calls the send_notification method with the correct
        arguments for a comment with depth 1
        """
        self._setup_thread('comment', '<p>Thread body</p>', 1)
        mock_create_audience.return_value = {}

        self.notification_sender.send_reported_content_notification()

        self._assert_send_notification_called_with(mock_send_notification, 'comment')

    def test_send_reported_content_notification_for_thread(self, mock_send_notification, mock_create_audience):
        """
        Test that the send_reported_content_notification method calls the send_notification method with the correct
        """
        self._setup_thread('thread', '<p>Thread body</p>', 0)
        mock_create_audience.return_value = {}

        self.notification_sender.send_reported_content_notification()

        self._assert_send_notification_called_with(mock_send_notification, 'thread')


class TestCleanThreadHtmlBody(unittest.TestCase):
    """
    Tests for the clean_thread_html_body function
    """

    def test_html_tags_removal(self):
        """
        Test that the clean_thread_html_body function removes unwanted HTML tags
        """
        html_body = """
        <p>This is a <a href="#">link</a> to a page.</p>
        <p>Here is an image: <img src="image.jpg" alt="image"></p>
        <p>Embedded video: <iframe src="video.mp4"></iframe></p>
        <p>Script test: <script>alert('hello');</script></p>
        <p>Some other content that should remain.</p>
        """
        expected_output = ("<p>This is a link to a page.</p>"
                           "<p>Here is an image: </p>"
                           "<p>Embedded video: </p>"
                           "<p>Script test: alert('hello');</p>"
                           "<p>Some other content that should remain.</p>")

        result = clean_thread_html_body(html_body)

        def normalize_html(text):
            """
             Normalize the output by removing extra whitespace, newlines, and spaces between tags
            """
            text = re.sub(r'\s+', ' ', text).strip()  # Replace any sequence of whitespace with a single space
            text = re.sub(r'>\s+<', '><', text)  # Remove spaces between HTML tags
            return text

        normalized_result = normalize_html(result)
        normalized_expected_output = normalize_html(expected_output)

        self.assertEqual(normalized_result, normalized_expected_output)

    def test_truncate_html_body(self):
        """
        Test that the clean_thread_html_body function truncates the HTML body to 500 characters
        """
        html_body = """
        <p>This is a long text that should be truncated to 500 characters.</p>
        """ * 20  # Repeat to exceed 500 characters

        result = clean_thread_html_body(html_body)
        self.assertEqual(len(result) <= 500)

    def test_no_tags_to_remove(self):
        """
        Test that the clean_thread_html_body function does not remove any tags if there are no unwanted tags
        """
        html_body = "<p>This paragraph has no tags to remove.</p>"
        expected_output = "<p>This paragraph has no tags to remove.</p>"

        result = clean_thread_html_body(html_body)
        self.assertEqual(result, expected_output)

    def test_empty_html_body(self):
        """
        Test that the clean_thread_html_body function returns an empty string if the input is an empty string
        """
        html_body = ""
        expected_output = ""

        result = clean_thread_html_body(html_body)
        self.assertEqual(result, expected_output)

    def test_only_script_tag(self):
        """
        Test that the clean_thread_html_body function removes the script tag and its content
        """
        html_body = "<script>alert('Hello');</script>"
        expected_output = "alert('Hello');"

        result = clean_thread_html_body(html_body)
        self.assertEqual(result.strip(), expected_output)
