# -*- coding: utf-8 -*-
"""
Tests for custom Teams Serializers.
"""


import six
from django.core.paginator import Paginator
from django.test.client import RequestFactory

from lms.djangoapps.teams.serializers import BulkTeamCountTopicSerializer, MembershipSerializer, TopicSerializer
from lms.djangoapps.teams.tests.factories import CourseTeamFactory, CourseTeamMembershipFactory
from openedx.core.lib.teams_config import TeamsConfig
from student.tests.factories import CourseEnrollmentFactory, UserFactory
from xmodule.modulestore.tests.django_utils import SharedModuleStoreTestCase
from xmodule.modulestore.tests.factories import CourseFactory


class SerializerTestCase(SharedModuleStoreTestCase):
    """
    Base test class to set up a course with topics
    """
    def setUp(self):
        """
        Set up a course with a teams configuration.
        """
        super(SerializerTestCase, self).setUp()
        self.course = CourseFactory.create(
            teams_configuration=TeamsConfig({
                "max_team_size": 10,
                "topics": [{u'name': u'Tøpic', u'description': u'The bést topic!', u'id': u'0'}]
            }),
        )


class MembershipSerializerTestCase(SerializerTestCase):
    """
    Tests for the membership serializer.
    """

    def setUp(self):
        super(MembershipSerializerTestCase, self).setUp()
        self.team = CourseTeamFactory.create(
            course_id=self.course.id,
            topic_id=self.course.teamsets[0].teamset_id,
        )
        self.user = UserFactory.create()
        CourseEnrollmentFactory.create(user=self.user, course_id=self.course.id)
        self.team_membership = CourseTeamMembershipFactory.create(team=self.team, user=self.user)

    def test_membership_serializer_expand_user_and_team(self):
        """Verify that the serializer only expands the user and team one level."""
        data = MembershipSerializer(self.team_membership, context={
            'expand': [u'team', u'user'],
            'request': RequestFactory().get('/api/team/v0/team_membership')
        }).data
        username = self.user.username
        self.assertEqual(data['user'], {
            'url': 'http://testserver/api/user/v1/accounts/' + username,
            'username': username,
            'profile_image': {
                'image_url_full': 'http://testserver/static/default_500.png',
                'image_url_large': 'http://testserver/static/default_120.png',
                'image_url_medium': 'http://testserver/static/default_50.png',
                'image_url_small': 'http://testserver/static/default_30.png',
                'has_image': False
            },
            'account_privacy': 'private'
        })
        self.assertNotIn('membership', data['team'])


class TopicSerializerTestCase(SerializerTestCase):
    """
    Tests for the `TopicSerializer`, which should serialize team count data for
    a single topic.
    """

    def test_topic_with_no_team_count(self):
        """
        Verifies that the `TopicSerializer` correctly displays a topic with a
        team count of 0, and that it only takes one SQL query.
        """
        with self.assertNumQueries(1):
            serializer = TopicSerializer(
                self.course.teamsets[0].cleaned_data,
                context={'course_id': self.course.id},
            )
            self.assertEqual(
                serializer.data,
                {u'name': u'Tøpic', u'description': u'The bést topic!', u'id': u'0', u'team_count': 0, u'type': u'open'}
            )

    def test_topic_with_team_count(self):
        """
        Verifies that the `TopicSerializer` correctly displays a topic with a
        positive team count, and that it only takes one SQL query.
        """
        CourseTeamFactory.create(
            course_id=self.course.id, topic_id=self.course.teamsets[0].teamset_id
        )
        with self.assertNumQueries(1):
            serializer = TopicSerializer(
                self.course.teamsets[0].cleaned_data,
                context={'course_id': self.course.id},
            )
            self.assertEqual(
                serializer.data,
                {u'name': u'Tøpic', u'description': u'The bést topic!', u'id': u'0', u'team_count': 1, u'type': u'open'}
            )

    def test_scoped_within_course(self):
        """Verify that team count is scoped within a course."""
        duplicate_topic = self.course.teamsets[0].cleaned_data
        second_course = CourseFactory.create(
            teams_configuration=TeamsConfig({
                "max_team_size": 10,
                "topics": [duplicate_topic]
            }),
        )
        CourseTeamFactory.create(course_id=self.course.id, topic_id=duplicate_topic[u'id'])
        CourseTeamFactory.create(course_id=second_course.id, topic_id=duplicate_topic[u'id'])
        with self.assertNumQueries(1):
            serializer = TopicSerializer(
                self.course.teamsets[0].cleaned_data,
                context={'course_id': self.course.id},
            )
            self.assertEqual(
                serializer.data,
                {u'name': u'Tøpic', u'description': u'The bést topic!', u'id': u'0', u'team_count': 1, u'type': u'open'}
            )


class BaseTopicSerializerTestCase(SerializerTestCase):
    """
    Base class for testing the two paginated topic serializers.
    """

    __test__ = False
    PAGE_SIZE = 5
    # Extending test classes should specify their serializer class.
    serializer = None

    def _merge_dicts(self, first, second):
        """Convenience method to merge two dicts in a single expression"""
        result = first.copy()
        result.update(second)
        return result

    def setup_topics(self, num_topics=5, teams_per_topic=0):
        """
        Helper method to set up topics on the course.  Returns a list of
        created topics.
        """
        topics = [
            {
                'name': 'Tøpic {}'.format(i),
                'description': 'The bést topic! {}'.format(i),
                'id': six.text_type(i),
                'type': 'open',
            }
            for i in six.moves.range(num_topics)
        ]
        for topic in topics:
            for _ in six.moves.range(teams_per_topic):
                CourseTeamFactory.create(course_id=self.course.id, topic_id=topic['id'])
        self.course.teams_configuration = TeamsConfig({
            'max_team_size': self.course.teams_configuration.default_max_team_size,
            'topics': topics,
        })
        return topics

    def assert_serializer_output(self, topics, num_teams_per_topic, num_queries):
        """
        Verify that the serializer produced the expected topics.
        """
        with self.assertNumQueries(num_queries):
            page = Paginator(
                self.course.teams_configuration.cleaned_data_old_format['topics'],
                self.PAGE_SIZE,
            ).page(1)
            # pylint: disable=not-callable
            serializer = self.serializer(instance=page, context={'course_id': self.course.id})
            self.assertEqual(
                serializer.data['results'],
                [self._merge_dicts(topic, {u'team_count': num_teams_per_topic}) for topic in topics]
            )

    def test_no_topics(self):
        """
        Verify that we return no results and make no SQL queries for a page
        with no topics.
        """
        self.course.teams_configuration = TeamsConfig({'topics': []})
        self.assert_serializer_output([], num_teams_per_topic=0, num_queries=0)


class BulkTeamCountTopicSerializerTestCase(BaseTopicSerializerTestCase):
    """
    Tests for the `BulkTeamCountTopicSerializer`, which should serialize team_count
    data for many topics with constant time SQL queries.
    """
    __test__ = True
    serializer = BulkTeamCountTopicSerializer

    NUM_TOPICS = 6

    def test_topics_with_no_team_counts(self):
        """
        Verify that we serialize topics with no team count, making only one SQL
        query.
        """
        topics = self.setup_topics(teams_per_topic=0)
        self.assert_serializer_output(topics, num_teams_per_topic=0, num_queries=1)

    def test_topics_with_team_counts(self):
        """
        Verify that we serialize topics with a positive team count, making only
        one SQL query.
        """
        teams_per_topic = 10
        topics = self.setup_topics(teams_per_topic=teams_per_topic)
        self.assert_serializer_output(topics, num_teams_per_topic=teams_per_topic, num_queries=1)

    def test_subset_of_topics(self):
        """
        Verify that we serialize a subset of the course's topics, making only
        one SQL query.
        """
        teams_per_topic = 10
        topics = self.setup_topics(num_topics=self.NUM_TOPICS, teams_per_topic=teams_per_topic)
        self.assert_serializer_output(topics, num_teams_per_topic=teams_per_topic, num_queries=1)

    def test_scoped_within_course(self):
        """Verify that team counts are scoped within a course."""
        teams_per_topic = 10
        first_course_topics = self.setup_topics(num_topics=self.NUM_TOPICS, teams_per_topic=teams_per_topic)
        duplicate_topic = first_course_topics[0]
        second_course = CourseFactory.create(
            teams_configuration=TeamsConfig({
                "max_team_size": 10,
                "topics": [duplicate_topic]
            }),
        )
        CourseTeamFactory.create(course_id=second_course.id, topic_id=duplicate_topic[u'id'])
        self.assert_serializer_output(first_course_topics, num_teams_per_topic=teams_per_topic, num_queries=1)

    def _merge_dicts(self, first, second):
        """Convenience method to merge two dicts in a single expression"""
        result = first.copy()
        result.update(second)
        return result

    def assert_serializer_output(self, topics, num_teams_per_topic, num_queries):
        """
        Verify that the serializer produced the expected topics.
        """
        with self.assertNumQueries(num_queries):
            serializer = self.serializer(topics, context={'course_id': self.course.id}, many=True)
            self.assertEqual(
                serializer.data,
                [self._merge_dicts(topic, {u'team_count': num_teams_per_topic}) for topic in topics]
            )

    def test_no_topics(self):
        """
        Verify that we return no results and make no SQL queries for a page
        with no topics.
        """
        self.course.teams_configuration = TeamsConfig({'topics': []})
        self.assert_serializer_output([], num_teams_per_topic=0, num_queries=0)
