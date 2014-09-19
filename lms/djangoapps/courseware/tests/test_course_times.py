"""
Tests displaying of course start time for LMS
"""
import unittest
from datetime import datetime, timedelta
import xmodule.course_module
from mock import Mock, patch
from django.utils.timezone import UTC
from xmodule.tests.test_course_module import get_dummy_course

NOW = datetime.strptime('2013-01-01T01:00:00', '%Y-%m-%dT%H:%M:00').replace(tzinfo=UTC())


class LMSCourseTimeTests(unittest.TestCase):
    """ Ensure course start and end times are returned correctly """

    start_advertised_settings = [
        # start, advertised, result, is_still_default
        ('2012-12-02T12:00', None, 'Dec 02, 2012', False),
        ('2012-12-02T12:00', '2011-11-01T12:00', 'Nov 01, 2011', False),
        ('2012-12-02T12:00', 'Spring 2012', 'Spring 2012', False),
        ('2012-12-02T12:00', 'November, 2011', 'November, 2011', False),
        (xmodule.course_module.CourseFields.start.default, None, 'TBD', True),
        (xmodule.course_module.CourseFields.start.default, 'January 2014', 'January 2014', False),
    ]

    def test_start_date_text(self):
        """ Test start date returned correctly default (UTC) TZ """
        for s in self.start_advertised_settings:
            d = get_dummy_course(start=s[0], advertised_start=s[1])
            print "Checking start=%s advertised=%s" % (s[0], s[1])
            self.assertEqual(d.start_date_text, s[2])

    def test_start_date_is_default(self):
        """ Test use of default start date """
        for s in self.start_advertised_settings:
            d = get_dummy_course(start=s[0], advertised_start=s[1])
            self.assertEqual(d.start_date_is_still_default, s[3])

    pacific_timezone_start_settings = [
        # Start time in UTC, advertised in UTC, result in US/Pacific, is_still_default
        ('2014-07-10T12:00', None, 'Jul 10, 2014', False),
        ('2014-07-11T04:30', None, 'Jul 10, 2014', False),
        ('2020-08-18T09:00', None, 'Aug 18, 2020', False),
    ]

    @patch('django.conf.settings.TIME_ZONE_DISPLAYED_FOR_DEADLINES', new="US/Pacific")
    def test_start_date_text_pacific_timezone(self):
        """ Test use of set timezone, US/Pacific """
        for s in self.pacific_timezone_start_settings:
            d = get_dummy_course(start=s[0], advertised_start=s[1])
            self.assertEqual(d.start_date_text, s[2])

    eastern_timezone_start_settings = [
        # Start time in UTC, advertised in UTC, result in US/Eastern, is_still_default,
        ('2014-07-25T03:00', None, 'Jul 24, 2014', False),
        ('2020-10-10T14:00', None, 'Oct 10, 2020', False),
        ('2020-12-25T05:00', None, 'Dec 25, 2020', False),
    ]

    @patch('django.conf.settings.TIME_ZONE_DISPLAYED_FOR_DEADLINES', new="US/Eastern")
    def test_start_date_text_eastern_timezone(self):
        """ Test use of set timezone, US/Eastern """
        for s in self.eastern_timezone_start_settings:
            d = get_dummy_course(start=s[0], advertised_start=s[1])
            self.assertEqual(d.start_date_text, s[2])

    australia_timezone_start_settings = [
        # Start time in UTC, advertised in UTC, result in Australia/Sydney, is_still_default,
        ('2014-07-25T03:00', None, 'Jul 25, 2014', False),
        ('2020-10-10T14:00', None, 'Oct 11, 2020', False),
        ('2020-12-25T18:00', None, 'Dec 26, 2020', False),
        ('2020-12-25T12:00', None, 'Dec 25, 2020', False),
    ]

    @patch('django.conf.settings.TIME_ZONE_DISPLAYED_FOR_DEADLINES', new="Australia/Sydney")
    def test_start_date_text_australia_timezone(self):
        """ Test use of set timezone, international """
        for s in self.australia_timezone_start_settings:
            d = get_dummy_course(start=s[0], advertised_start=s[1])
            self.assertEqual(d.start_date_text, s[2])

    def test_end_date_text(self):
        # No end date set, returns empty string.
        d = get_dummy_course('2012-12-02T12:00')
        self.assertEqual('', d.end_date_text)

        d = get_dummy_course('2012-12-02T12:00', end='2014-9-04T12:00')
        self.assertEqual('Sep 04, 2014', d.end_date_text)
