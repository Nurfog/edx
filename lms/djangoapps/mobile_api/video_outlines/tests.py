"""
Tests for video outline API
"""
import copy
import ddt
from uuid import uuid4
from collections import namedtuple

from django.core.urlresolvers import reverse
from django.test.utils import override_settings
from django.conf import settings
from edxval import api
from rest_framework.test import APITestCase

from courseware.tests.factories import UserFactory
from xmodule.modulestore.tests.django_utils import TEST_DATA_MOCK_MODULESTORE
from xmodule.modulestore.tests.factories import CourseFactory, ItemFactory
from xmodule.video_module import transcripts_utils
from xmodule.modulestore.tests.django_utils import ModuleStoreTestCase
from xmodule.modulestore.django import modulestore

from mobile_api.tests import ROLE_CASES

TEST_DATA_CONTENTSTORE = copy.deepcopy(settings.CONTENTSTORE)
TEST_DATA_CONTENTSTORE['DOC_STORE_CONFIG']['db'] = 'test_xcontent_%s' % uuid4().hex


@ddt.ddt
@override_settings(MODULESTORE=TEST_DATA_MOCK_MODULESTORE, CONTENTSTORE=TEST_DATA_CONTENTSTORE)
class TestVideoOutline(ModuleStoreTestCase, APITestCase):
    """
    Tests for /api/mobile/v0.5/video_outlines/
    """
    def setUp(self):
        super(TestVideoOutline, self).setUp()
        self.user = UserFactory.create()
        self.course = CourseFactory.create(mobile_available=True)
        self.section = ItemFactory.create(
            parent_location=self.course.location,
            category="chapter",
            display_name=u"test factory section omega \u03a9",
        )
        self.sub_section = ItemFactory.create(
            parent_location=self.section.location,
            category="sequential",
            display_name=u"test subsection omega \u03a9",
        )

        self.unit = ItemFactory.create(
            parent_location=self.sub_section.location,
            category="vertical",
            metadata={'graded': True, 'format': 'Homework'},
            display_name=u"test unit omega \u03a9",
        )
        self.other_unit = ItemFactory.create(
            parent_location=self.sub_section.location,
            category="vertical",
            metadata={'graded': True, 'format': 'Homework'},
            display_name=u"test unit omega 2 \u03a9",
        )
        self.nameless_unit = ItemFactory.create(
            parent_location=self.sub_section.location,
            category="vertical",
            metadata={'graded': True, 'format': 'Homework'},
            display_name=None,
        )
        self.split_unit = ItemFactory.create(
            parent_location=self.sub_section.location,
            category="vertical",
            display_name=u"split test vertical\u03a9",
        )

        self.edx_video_id = 'testing-123'

        self.video_url = 'http://val.edx.org/val/video.mp4'
        self.html5_video_url = 'http://video.edx.org/html5/video.mp4'

        api.create_profile({
            'profile_name': 'youtube',
            'extension': 'mp4',
            'width': 1280,
            'height': 720
        })
        api.create_profile({
            'profile_name': 'mobile_low',
            'extension': 'mp4',
            'width': 640,
            'height': 480
        })

        # create the video in VAL
        api.create_video({
            'edx_video_id': self.edx_video_id,
            'status': 'test',
            'client_video_id': u"test video omega \u03a9",
            'duration': 12,
            'courses': [unicode(self.course.id)],
            'encoded_videos': [
                {
                    'profile': 'youtube',
                    'url': 'xyz123',
                    'file_size': 0,
                    'bitrate': 1500
                },
                {
                    'profile': 'mobile_low',
                    'url': self.video_url,
                    'file_size': 12345,
                    'bitrate': 250
                }
            ]})

        self.client.login(username=self.user.username, password='test')

    @ddt.data(*ROLE_CASES)
    @ddt.unpack
    def test_non_mobile_access(self, role, should_succeed):
        nonmobile = CourseFactory.create(mobile_available=False)

        if role:
            role(nonmobile.id).add_users(self.user)

        url = reverse('video-summary-list', kwargs={'course_id': unicode(nonmobile.id)})
        response = self.client.get(url)
        if should_succeed:
            self.assertEqual(response.status_code, 200)
        else:
            self.assertEqual(response.status_code, 403)

    def _get_video_summary_list(self):
        """
        Calls the video-summary-list endpoint, expecting a success response
        """
        url = reverse('video-summary-list', kwargs={'course_id': unicode(self.course.id)})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        return response.data  # pylint: disable=maybe-no-member

    def _create_video_with_subs(self):
        """
        Creates and returns a video with stored subtitles.
        """
        subid = uuid4().hex
        transcripts_utils.save_subs_to_store({
            'start': [100, 200, 240, 390, 1000],
            'end': [200, 240, 380, 1000, 1500],
            'text': [
                'subs #1',
                'subs #2',
                'subs #3',
                'subs #4',
                'subs #5'
            ]},
            subid,
            self.course)
        return ItemFactory.create(
            parent_location=self.unit.location,
            category="video",
            edx_video_id=self.edx_video_id,
            display_name=u"test video omega \u03a9",
            sub=subid
        )

    def test_course_list(self):
        self._create_video_with_subs()
        ItemFactory.create(
            parent_location=self.other_unit.location,
            category="video",
            display_name=u"test video omega 2 \u03a9",
            html5_sources=[self.html5_video_url]
        )
        ItemFactory.create(
            parent_location=self.other_unit.location,
            category="video",
            display_name=u"test video omega 3 \u03a9",
            source=self.html5_video_url
        )
        ItemFactory.create(
            parent_location=self.unit.location,
            category="video",
            edx_video_id=self.edx_video_id,
            display_name=u"test draft video omega \u03a9",
            visible_to_staff_only=True,
        )

        course_outline = self._get_video_summary_list()
        self.assertEqual(len(course_outline), 3)
        vid = course_outline[0]
        self.assertTrue('test_subsection_omega_%CE%A9' in vid['section_url'])
        self.assertTrue('test_subsection_omega_%CE%A9/1' in vid['unit_url'])
        self.assertTrue(u'test_video_omega_\u03a9' in vid['summary']['id'])
        self.assertEqual(vid['summary']['video_url'], self.video_url)
        self.assertEqual(vid['summary']['size'], 12345)
        self.assertTrue('en' in vid['summary']['transcripts'])
        self.assertEqual(course_outline[1]['summary']['video_url'], self.html5_video_url)
        self.assertEqual(course_outline[1]['summary']['size'], 0)
        self.assertEqual(course_outline[1]['path'][2]['name'], self.other_unit.display_name)
        self.assertEqual(course_outline[1]['path'][2]['id'], unicode(self.other_unit.location))

        self.assertEqual(course_outline[2]['summary']['video_url'], self.html5_video_url)
        self.assertEqual(course_outline[2]['summary']['size'], 0)

    def test_course_list_with_nameless_unit(self):
        ItemFactory.create(
            parent_location=self.nameless_unit.location,
            category="video",
            edx_video_id=self.edx_video_id,
            display_name=u"test draft video omega 2 \u03a9"
        )
        course_outline = self._get_video_summary_list()
        self.assertEqual(len(course_outline), 1)
        self.assertEqual(course_outline[0]['path'][2]['name'], self.nameless_unit.location.block_id)

    def test_course_list_with_video_in_sub_section(self):
        """
        Tests a non standard xml format where a video is underneath a sequential

        We are expecting to return the same unit and section url since there is
        no unit vertical.
        """
        ItemFactory.create(
            parent_location=self.sub_section.location,
            category="video",
            edx_video_id=self.edx_video_id,
            display_name=u"test draft video omega 2 \u03a9"
        )
        course_outline = self._get_video_summary_list()
        self.assertEqual(len(course_outline), 1)
        self.assertEqual(len(course_outline[0]['path']), 2)
        self.assertEqual(course_outline[0]["section_url"], course_outline[0]["unit_url"])

    def test_course_list_with_split_test(self):
        self.split_test = ItemFactory.create(
            parent_location=self.split_unit.location,
            category="split_test",
            display_name=u"split test unit"
        )
        ItemFactory.create(
            parent_location=self.split_test.location,
            category="video",
            display_name=u"split test vertical a",
        )
        ItemFactory.create(
            parent_location=self.split_test.location,
            category="video",
            display_name=u"split test vertical b",
        )
        course_outline = self._get_video_summary_list()
        self.assertEqual(len(course_outline), 2)
        self.assertEqual(len(course_outline[0]["path"]), 4)
        self.assertEqual(len(course_outline[1]["path"]), 4)
        self.assertEqual(course_outline[0]["summary"]["name"], u"split test vertical a")
        self.assertEqual(course_outline[1]["summary"]["name"], u"split test vertical b")


    def test_course_list_with_hidden_blocks(self):
        hidden_subsection = ItemFactory.create(
            parent_location=self.section.location,
            category="sequential",
            hide_from_toc=True,
        )
        unit_within_hidden_subsection = ItemFactory.create(
            parent_location=hidden_subsection.location,
            category="vertical",
        )
        hidden_unit = ItemFactory.create(
            parent_location=self.sub_section.location,
            category="vertical",
            hide_from_toc=True,
        )
        ItemFactory.create(
            parent_location=unit_within_hidden_subsection.location,
            category="video",
            edx_video_id=self.edx_video_id,
        )
        ItemFactory.create(
            parent_location=hidden_unit.location,
            category="video",
            edx_video_id=self.edx_video_id,
        )
        course_outline = self._get_video_summary_list()
        self.assertEqual(len(course_outline), 0)

    def test_course_list_language(self):
        video = ItemFactory.create(
            parent_location=self.nameless_unit.location,
            category="video",
            edx_video_id=self.edx_video_id,
            display_name=u"test draft video omega 2 \u03a9"
        )

        language_case = namedtuple('language_case', ['transcripts', 'expected_language'])
        language_cases = [
            # defaults to english
            language_case({}, "en"),
            # supports english
            language_case({"en": 1}, "en"),
            # supports another language
            language_case({"lang1": 1}, "lang1"),
            # returns first alphabetically-sorted language
            language_case({"lang1": 1, "en": 2}, "en"),
            language_case({"lang1": 1, "lang2": 2}, "lang1"),
        ]

        for case in language_cases:
            video.transcripts = case.transcripts
            modulestore().update_item(video, self.user.id)
            course_outline = self._get_video_summary_list()
            self.assertEqual(len(course_outline), 1)
            self.assertEqual(course_outline[0]['summary']['language'], case.expected_language)

    def test_course_list_transcripts(self):
        video = ItemFactory.create(
            parent_location=self.nameless_unit.location,
            category="video",
            edx_video_id=self.edx_video_id,
            display_name=u"test draft video omega 2 \u03a9"
        )

        transcript_case = namedtuple('transcript_case', ['transcripts', 'english_subtitle', 'expected_transcripts'])
        transcript_cases = [
            # defaults to english
            transcript_case({}, "", ["en"]),
            transcript_case({}, "en-sub", ["en"]),
            # supports english
            transcript_case({"en": 1}, "", ["en"]),
            transcript_case({"en": 1}, "en-sub", ["en"]),
            # keeps both english and other languages
            transcript_case({"lang1": 1, "en": 2}, "", ["lang1", "en"]),
            transcript_case({"lang1": 1, "en": 2}, "en-sub", ["lang1", "en"]),
            # adds english to list of languages only if english_subtitle is specified
            transcript_case({"lang1": 1, "lang2": 2}, "", ["lang1", "lang2"]),
            transcript_case({"lang1": 1, "lang2": 2}, "en-sub", ["lang1", "lang2", "en"]),
        ]

        for case in transcript_cases:
            video.transcripts = case.transcripts
            video.sub = case.english_subtitle
            modulestore().update_item(video, self.user.id)
            course_outline = self._get_video_summary_list()
            self.assertEqual(len(course_outline), 1)
            self.assertSetEqual(
                set(course_outline[0]['summary']['transcripts'].keys()),
                set(case.expected_transcripts)
            )

    def test_transcripts_detail(self):
        video = self._create_video_with_subs()
        kwargs = {
            'course_id': unicode(self.course.id),
            'block_id': unicode(video.scope_ids.usage_id.block_id),
            'lang': 'pl'
        }
        url = reverse('video-transcripts-detail', kwargs=kwargs)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

        kwargs['lang'] = 'en'
        url = reverse('video-transcripts-detail', kwargs=kwargs)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
