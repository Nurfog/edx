"""Grading tests"""
import unittest

from xmodule import graders
from xmodule.graders import ProblemScore, AggregatedScore, aggregate_scores


class GradesheetTest(unittest.TestCase):
    """
    Tests the aggregate_scores method
    """

    def test_weighted_grading(self):
        scores = []
        agg_fields = dict(display_name="aggregated_score", module_id=None, attempted=False)
        prob_fields = dict(
            display_name="problem_score", module_id=None, raw_earned=0, raw_possible=0, weight=0, attempted=False,
        )

        # No scores
        all_total, graded_total = aggregate_scores(scores, display_name=agg_fields['display_name'])
        self.assertEqual(
            all_total,
            AggregatedScore(tw_earned=0, tw_possible=0, graded=False, **agg_fields),
        )
        self.assertEqual(
            graded_total,
            AggregatedScore(tw_earned=0, tw_possible=0, graded=True, **agg_fields),
        )

        # (0/5 non-graded)
        scores.append(ProblemScore(weighted_earned=0, weighted_possible=5, graded=False, **prob_fields))
        all_total, graded_total = aggregate_scores(scores, display_name=agg_fields['display_name'])
        self.assertEqual(
            all_total,
            AggregatedScore(tw_earned=0, tw_possible=5, graded=False, **agg_fields),
        )
        self.assertEqual(
            graded_total,
            AggregatedScore(tw_earned=0, tw_possible=0, graded=True, **agg_fields),
        )

        # (0/5 non-graded) + (3/5 graded) = 3/10 total, 3/5 graded
        prob_fields['attempted'] = True
        agg_fields['attempted'] = True
        scores.append(ProblemScore(weighted_earned=3, weighted_possible=5, graded=True, **prob_fields))
        all_total, graded_total = aggregate_scores(scores, display_name=agg_fields['display_name'])
        self.assertAlmostEqual(
            all_total,
            AggregatedScore(tw_earned=3, tw_possible=10, graded=False, **agg_fields),
        )
        self.assertAlmostEqual(
            graded_total,
            AggregatedScore(tw_earned=3, tw_possible=5, graded=True, **agg_fields),
        )

        # (0/5 non-graded) + (3/5 graded) + (2/5 graded) = 5/15 total, 5/10 graded
        scores.append(ProblemScore(weighted_earned=2, weighted_possible=5, graded=True, **prob_fields))
        all_total, graded_total = aggregate_scores(scores, display_name=agg_fields['display_name'])
        self.assertAlmostEqual(
            all_total,
            AggregatedScore(tw_earned=5, tw_possible=15, graded=False, **agg_fields),
        )
        self.assertAlmostEqual(
            graded_total,
            AggregatedScore(tw_earned=5, tw_possible=10, graded=True, **agg_fields),
        )


class GraderTest(unittest.TestCase):
    """
    Tests grader implementations
    """

    empty_gradesheet = {
    }

    incomplete_gradesheet = {
        'Homework': [],
        'Lab': [],
        'Midterm': [],
    }

    common_fields = dict(graded=True, module_id=None, attempted=True)
    test_gradesheet = {
        'Homework': [
            AggregatedScore(tw_earned=2, tw_possible=20.0, display_name='hw1', **common_fields),
            AggregatedScore(tw_earned=16, tw_possible=16.0, display_name='hw2', **common_fields),
        ],

        # The dropped scores should be from the assignments that don't exist yet
        'Lab': [
            AggregatedScore(tw_earned=1, tw_possible=2.0, display_name='lab1', **common_fields),  # Dropped
            AggregatedScore(tw_earned=1, tw_possible=1.0, display_name='lab2', **common_fields),
            AggregatedScore(tw_earned=1, tw_possible=1.0, display_name='lab3', **common_fields),
            AggregatedScore(tw_earned=5, tw_possible=25.0, display_name='lab4', **common_fields),  # Dropped
            AggregatedScore(tw_earned=3, tw_possible=4.0, display_name='lab5', **common_fields),  # Dropped
            AggregatedScore(tw_earned=6, tw_possible=7.0, display_name='lab6', **common_fields),
            AggregatedScore(tw_earned=5, tw_possible=6.0, display_name='lab7', **common_fields),
        ],

        'Midterm': [
            AggregatedScore(tw_earned=50.5, tw_possible=100, display_name="Midterm Exam", **common_fields),
        ],
    }

    def test_assignment_format_grader(self):
        homework_grader = graders.AssignmentFormatGrader("Homework", 12, 2)
        no_drop_grader = graders.AssignmentFormatGrader("Homework", 12, 0)
        # Even though the minimum number is 3, this should grade correctly when 7 assignments are found
        overflow_grader = graders.AssignmentFormatGrader("Lab", 3, 2)
        lab_grader = graders.AssignmentFormatGrader("Lab", 7, 3)

        # Test the grading of an empty gradesheet
        for graded in [
                homework_grader.grade(self.empty_gradesheet),
                no_drop_grader.grade(self.empty_gradesheet),
                homework_grader.grade(self.incomplete_gradesheet),
                no_drop_grader.grade(self.incomplete_gradesheet),
        ]:
            self.assertAlmostEqual(graded['percent'], 0.0)
            # Make sure the breakdown includes 12 sections, plus one summary
            self.assertEqual(len(graded['section_breakdown']), 12 + 1)

        graded = homework_grader.grade(self.test_gradesheet)
        self.assertAlmostEqual(graded['percent'], 0.11)  # 100% + 10% / 10 assignments
        self.assertEqual(len(graded['section_breakdown']), 12 + 1)

        graded = no_drop_grader.grade(self.test_gradesheet)
        self.assertAlmostEqual(graded['percent'], 0.0916666666666666)  # 100% + 10% / 12 assignments
        self.assertEqual(len(graded['section_breakdown']), 12 + 1)

        graded = overflow_grader.grade(self.test_gradesheet)
        self.assertAlmostEqual(graded['percent'], 0.8880952380952382)  # 100% + 10% / 5 assignments
        self.assertEqual(len(graded['section_breakdown']), 7 + 1)

        graded = lab_grader.grade(self.test_gradesheet)
        self.assertAlmostEqual(graded['percent'], 0.9226190476190477)
        self.assertEqual(len(graded['section_breakdown']), 7 + 1)

    def test_assignment_format_grader_on_single_section_entry(self):
        midterm_grader = graders.AssignmentFormatGrader("Midterm", 1, 0)
        # Test the grading on a section with one item:
        for graded in [
                midterm_grader.grade(self.empty_gradesheet),
                midterm_grader.grade(self.incomplete_gradesheet),
        ]:
            self.assertAlmostEqual(graded['percent'], 0.0)
            # Make sure the breakdown includes just the one summary
            self.assertEqual(len(graded['section_breakdown']), 0 + 1)
            self.assertEqual(graded['section_breakdown'][0]['label'], 'Midterm')

        graded = midterm_grader.grade(self.test_gradesheet)
        self.assertAlmostEqual(graded['percent'], 0.505)
        self.assertEqual(len(graded['section_breakdown']), 0 + 1)

    def test_weighted_subsections_grader(self):
        # First, a few sub graders
        homework_grader = graders.AssignmentFormatGrader("Homework", 12, 2)
        lab_grader = graders.AssignmentFormatGrader("Lab", 7, 3)
        midterm_grader = graders.AssignmentFormatGrader("Midterm", 1, 0)

        weighted_grader = graders.WeightedSubsectionsGrader([
            (homework_grader, homework_grader.category, 0.25),
            (lab_grader, lab_grader.category, 0.25),
            (midterm_grader, midterm_grader.category, 0.5),
        ])

        over_one_weights_grader = graders.WeightedSubsectionsGrader([
            (homework_grader, homework_grader.category, 0.5),
            (lab_grader, lab_grader.category, 0.5),
            (midterm_grader, midterm_grader.category, 0.5),
        ])

        # The midterm should have all weight on this one
        zero_weights_grader = graders.WeightedSubsectionsGrader([
            (homework_grader, homework_grader.category, 0.0),
            (lab_grader, lab_grader.category, 0.0),
            (midterm_grader, midterm_grader.category, 0.5),
        ])

        # This should always have a final percent of zero
        all_zero_weights_grader = graders.WeightedSubsectionsGrader([
            (homework_grader, homework_grader.category, 0.0),
            (lab_grader, lab_grader.category, 0.0),
            (midterm_grader, midterm_grader.category, 0.0),
        ])

        empty_grader = graders.WeightedSubsectionsGrader([])

        graded = weighted_grader.grade(self.test_gradesheet)
        self.assertAlmostEqual(graded['percent'], 0.5106547619047619)
        self.assertEqual(len(graded['section_breakdown']), (12 + 1) + (7 + 1) + 1)
        self.assertEqual(len(graded['grade_breakdown']), 3)

        graded = over_one_weights_grader.grade(self.test_gradesheet)
        self.assertAlmostEqual(graded['percent'], 0.7688095238095238)
        self.assertEqual(len(graded['section_breakdown']), (12 + 1) + (7 + 1) + 1)
        self.assertEqual(len(graded['grade_breakdown']), 3)

        graded = zero_weights_grader.grade(self.test_gradesheet)
        self.assertAlmostEqual(graded['percent'], 0.2525)
        self.assertEqual(len(graded['section_breakdown']), (12 + 1) + (7 + 1) + 1)
        self.assertEqual(len(graded['grade_breakdown']), 3)

        graded = all_zero_weights_grader.grade(self.test_gradesheet)
        self.assertAlmostEqual(graded['percent'], 0.0)
        self.assertEqual(len(graded['section_breakdown']), (12 + 1) + (7 + 1) + 1)
        self.assertEqual(len(graded['grade_breakdown']), 3)

        for graded in [
                weighted_grader.grade(self.empty_gradesheet),
                weighted_grader.grade(self.incomplete_gradesheet),
                zero_weights_grader.grade(self.empty_gradesheet),
                all_zero_weights_grader.grade(self.empty_gradesheet),
        ]:
            self.assertAlmostEqual(graded['percent'], 0.0)
            self.assertEqual(len(graded['section_breakdown']), (12 + 1) + (7 + 1) + 1)
            self.assertEqual(len(graded['grade_breakdown']), 3)

        graded = empty_grader.grade(self.test_gradesheet)
        self.assertAlmostEqual(graded['percent'], 0.0)
        self.assertEqual(len(graded['section_breakdown']), 0)
        self.assertEqual(len(graded['grade_breakdown']), 0)

    def test_grader_from_conf(self):

        # Confs always produce a graders.WeightedSubsectionsGrader, so we test this by repeating the test
        # in test_graders.WeightedSubsectionsGrader, but generate the graders with confs.

        weighted_grader = graders.grader_from_conf([
            {
                'type': "Homework",
                'min_count': 12,
                'drop_count': 2,
                'short_label': "HW",
                'weight': 0.25,
            },
            {
                'type': "Lab",
                'min_count': 7,
                'drop_count': 3,
                'category': "Labs",
                'weight': 0.25
            },
            {
                'type': "Midterm",
                'name': "Midterm Exam",
                'short_label': "Midterm",
                'weight': 0.5,
            },
        ])

        empty_grader = graders.grader_from_conf([])

        graded = weighted_grader.grade(self.test_gradesheet)
        self.assertAlmostEqual(graded['percent'], 0.5106547619047619)
        self.assertEqual(len(graded['section_breakdown']), (12 + 1) + (7 + 1) + 1)
        self.assertEqual(len(graded['grade_breakdown']), 3)

        graded = empty_grader.grade(self.test_gradesheet)
        self.assertAlmostEqual(graded['percent'], 0.0)
        self.assertEqual(len(graded['section_breakdown']), 0)
        self.assertEqual(len(graded['grade_breakdown']), 0)

        # Test that graders can also be used instead of lists of dictionaries
        homework_grader = graders.AssignmentFormatGrader("Homework", 12, 2)
        homework_grader2 = graders.grader_from_conf(homework_grader)

        graded = homework_grader2.grade(self.test_gradesheet)
        self.assertAlmostEqual(graded['percent'], 0.11)
        self.assertEqual(len(graded['section_breakdown']), 12 + 1)

        # TODO: How do we test failure cases? The parser only logs an error when
        # it can't parse something. Maybe it should throw exceptions?
