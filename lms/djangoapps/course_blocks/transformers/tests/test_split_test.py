"""
Tests for SplitTestTransformer.
"""
from openedx.core.djangoapps.user_api.partition_schemes import RandomUserPartitionScheme
from student.tests.factories import CourseEnrollmentFactory
from xmodule.partitions.partitions import Group, UserPartition

from course_blocks.transformers.split_test import SplitTestTransformer
from course_blocks.transformers.user_partitions import UserPartitionTransformer
from course_blocks.api import get_course_blocks
from lms.djangoapps.course_blocks.transformers.tests.test_helpers import CourseStructureTestCase

from course_blocks.transformers.helpers import get_user_partition_groups


class SplitTestTransformerTestCase(CourseStructureTestCase):
    """
    SplitTestTransformer Test
    """
    def setUp(self):
        """
        Setup course structure and create user for split test transformer test.
        """
        super(SplitTestTransformerTestCase, self).setUp()

        # Set up user partitions and groups.
        self.groups = [Group(3, 'Group A'), Group(4, 'Group B')]
        self.content_groups = [3, 4]
        self.split_test_user_partition_id = 0
        self.split_test_user_partition = UserPartition(
            id=self.split_test_user_partition_id,
            name='Partition 2',
            description='This is partition 2',
            groups=self.groups,
            scheme=RandomUserPartitionScheme
        )
        self.split_test_user_partition.scheme.name = "random"

        # Build course.
        self.course_hierarchy = self.get_course_hierarchy()
        self.blocks = self.build_course(self.course_hierarchy)
        self.course = self.blocks['course']

        # Enroll user in course.
        CourseEnrollmentFactory.create(user=self.user, course_id=self.course.id, is_active=True)

        self.transformer = UserPartitionTransformer()
        
    def get_course_hierarchy(self):
        """
        Get a course hierarchy to test with.

        Assumes self.split_test_user_partition has already been initialized.

        Returns: dict[course_structure]
        """
        return {
            'org': 'SplitTestTransformer',
            'course': 'ST101F',
            'run': 'test_run',
            'user_partitions': [self.split_test_user_partition],
            '#ref': 'course',
            '#children': [
                {
                    '#type': 'chapter',
                    '#ref': 'chapter1',
                    '#children': [
                        {
                            '#type': 'sequential',
                            '#ref': 'lesson1',
                            '#children': [
                                {
                                    '#type': 'vertical',
                                    '#ref': 'vertical1',
                                    '#children': [
                                        {
                                            'metadata': {'category': 'split_test'},
                                            'user_partition_id': 0,
                                            'group_id_to_child': {
                                                "3": "i4x://SplitTestTransformer/ST101F/vertical/vertical_vertical2",
                                                "4": "i4x://SplitTestTransformer/ST101F/vertical/vertical_vertical3"
                                            },
                                            '#type': 'split_test',
                                            '#ref': 'split_test1',
                                            '#children': [
                                                {
                                                    'metadata': {'display_name': "Group ID 3"},
                                                    '#type': 'vertical',
                                                    '#ref': 'vertical2',
                                                    '#children': [
                                                        {
                                                            'metadata': {'display_name': "Group A"},
                                                            '#type': 'html',
                                                            '#ref': 'html1',
                                                        }
                                                    ]
                                                },
                                                {
                                                    'metadata': {'display_name': "Group ID 4"},
                                                    '#type': 'vertical',
                                                    '#ref': 'vertical3',
                                                    '#children': [
                                                        {
                                                            'metadata': {'display_name': "Group A"},
                                                            '#type': 'html',
                                                            '#ref': 'html2',
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        }

    def test_user(self):
        trans_block_structure = get_course_blocks(
            self.user,
            self.course.location,
            transformers={self.transformer},
        )

        # user was randomly assigned to one of the groups
        user_groups = get_user_partition_groups(
            self.course.id, [self.split_test_user_partition], self.user
        )
        self.assertEquals(len(user_groups), 1)
        group = user_groups[self.split_test_user_partition_id]

        expected_blocks = ['course', 'chapter1', 'lesson1', 'vertical1', 'split_test1']
        if group.id == 3:
            expected_blocks += ['vertical2', 'html1']
        else:
            expected_blocks += ['vertical3', 'html2']

        self.assertEqual(set(trans_block_structure.get_block_keys()), set(self.get_block_key_set(*expected_blocks)))

        # calling again should result in the same block set
        reloaded_structure = get_course_blocks(
            self.user,
            self.course.location,
            transformers={self.transformer}
        )
        self.assertEqual(set(reloaded_structure.get_block_keys()), set(self.get_block_key_set(*expected_blocks)))

