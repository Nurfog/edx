from __future__ import absolute_import, division, print_function, unicode_literals

import sys

from django.db import connection
from django.utils import timezone
from datetime import timedelta
from rest_framework.test import APIClient

from completion_aggregator.models import Aggregator

from xmodule.modulestore.tests.django_utils import SharedModuleStoreTestCase
from xmodule.modulestore.tests.factories import CourseFactory, ItemFactory
from student.models import CourseEnrollment
from student.tests.factories import AdminFactory, UserFactory


class AggregationRequest(SharedModuleStoreTestCase):
    chapter_count = 8  # 8
    sequential_count = 3  # 8 * 3 = 24
    vertical_count = 12  # 8 * 3 * 12 = 288
    block_count = 5  # 8 * 3 * 12 * 5 = 1440
    user_count = 10000

    @classmethod
    def setUpClass(cls):
        super(AggregationRequest, cls).setUpClass()
        cls.chapters = []
        cls.sequentials = []
        cls.verticals = []
        cls.blocks = []
        cls.course = CourseFactory.create()
        with cls.store.bulk_operations(cls.course.id):
            for _ in range(cls.chapter_count):
                chapter = ItemFactory.create(
                    parent=cls.course,
                    category="chapter",
                )
                cls.chapters.append(chapter)
                for _ in range(cls.sequential_count):
                    sequential = ItemFactory.create(
                        parent=chapter,
                        category='sequential',
                    )
                    cls.sequentials.append(sequential)
                    for _ in range(cls.vertical_count):
                        vertical = ItemFactory.create(
                            parent=sequential,
                            category="vertical",
                            display_name="vertical1"
                        )
                        cls.verticals.append(vertical)
                        for _ in range(cls.block_count):
                            block = ItemFactory.create(
                                parent=vertical,
                                category='html'
                            )
                            cls.blocks.append(block)

    def test_full_query_no_completions(self):
        start = timezone.now()
        client = APIClient()
        print("CREATING USERS", timezone.now())
        admin = AdminFactory.create(username='admin', password='admin')
        users = [UserFactory.create() for _ in range(self.user_count)]
        print("CREATING ENROLLMENTS AND AGGREGATORS", timezone.now())
        enrollments = []
        aggs = []
        for user in users:
            enrollments.append(
                CourseEnrollment(user=user, course_id=self.course.id)
            )
            aggs.append(
                Aggregator(
                    user=user,
                    course_key=self.course.id,
                    block_key=self.course.location.map_into_course(self.course.id),
                    aggregation_name='course',
                    earned=522.0,
                    possible=1044.0,
                    percent=0.5,
                    last_modified=start,
                )
            )
        CourseEnrollment.objects.bulk_create(enrollments, batch_size=500)
        Aggregator.objects.bulk_create(aggs, batch_size=500)
        client.login(username='admin', password='admin')
        startquery = timezone.now()
        print("START", timezone.now())
        results = []
        page_size = 5000

        response = client.get('/api/completion-aggregator/v1/course/{}/?page_size={}'.format(self.course.id, page_size))
        self.assertEqual(len(response.data['results']), page_size)
        results.extend(response.data['results'])
        print(connection.queries)
        print("  ", response.data['pagination'], timezone.now())
        while response.data['pagination']['next']:
            response = client.get(response.data['pagination']['next'])
            print("  ", response.data['pagination'], timezone.now())
            results.extend(response.data['results'])
        endquery = timezone.now()
        print('End collection', timezone.now())
        self.assertEqual(len(results), self.user_count)
        print("Query run time: {}s".format((endquery - startquery).total_seconds()))
        print(results[:10])
        self.assertLess(endquery - startquery, timedelta(seconds=128))
        self.assertLess(endquery - startquery, timedelta(seconds=64))
        self.assertLess(endquery - startquery, timedelta(seconds=32))
        self.assertLess(endquery - startquery, timedelta(seconds=16))
        self.assertLess(endquery - startquery, timedelta(seconds=8))
