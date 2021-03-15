"""
Tests for all the models in applications app.
"""
from datetime import date

import mock
import pytest

from common.djangoapps.student.tests.factories import AnonymousUserFactory, CourseEnrollmentFactory, UserFactory
from lms.djangoapps.grades.api import CourseGradeFactory
from openedx.adg.lms.applications.constants import CourseScore
from openedx.adg.lms.applications.models import MultilingualCourse, MultilingualCourseGroup, UserApplication
from openedx.core.lib.grade_utils import round_away_from_zero

from .constants import USERNAME
from .factories import ApplicationHubFactory, MultilingualCourseFactory, UserApplicationFactory


@pytest.mark.django_db
@pytest.fixture(name='application_hub')
def application_hub_fixture():
    """
    Create an ApplicationHub object for the specified test user.

    Returns:
        ApplicationHub object
    """
    user = UserFactory(username=USERNAME)
    return ApplicationHubFactory(user=user)


@pytest.mark.django_db
def test_set_is_prerequisite_courses_passed_in_application_hub(application_hub):
    """
    Test if the is_prerequisite_courses_passed is being set correctly by the model method.
    """
    application_hub.set_is_prerequisite_courses_passed()
    assert ApplicationHubFactory(user=application_hub.user).is_prerequisite_courses_passed


def mark_objectives_complete(application_hub, objectives_completed):
    """
    Mark the given objectives complete in the model object

    Args:
        objectives_completed(list): List of strings, each representing a model field i.e objective
        application_hub(ApplicationHub): The model object on which these objectives are to be set

    Returns:
        None
    """
    for objective in objectives_completed:
        setattr(application_hub, objective, True)


@pytest.mark.django_db
@pytest.mark.parametrize('objectives_completed,expected_return_value', [
    ([], 0.0),
    (['is_prerequisite_courses_passed'], 0.5),
    (['is_written_application_completed'], 0.5),
    (['is_prerequisite_courses_passed', 'is_written_application_completed'], 1.0)
])
def test_progress_of_objectives_completed_in_float_in_application_hub(
    objectives_completed,
    expected_return_value,
    application_hub
):
    """
    Test if the `percentage_of_objectives_completed` property is working as expected for all possible cases.
    """
    mark_objectives_complete(application_hub, objectives_completed)
    assert application_hub.progress_of_objectives_completed_in_float == expected_return_value


@pytest.mark.django_db
def test_submit_application_for_current_date_in_application_hub(application_hub):
    """
    Test if the `submit_application_for_current_date` model method works as expected.
    """
    application_hub.submit_application_for_current_date()
    user_application_hub = ApplicationHubFactory(user=application_hub.user)
    assert user_application_hub.is_application_submitted
    assert user_application_hub.submission_date == date.today()


@pytest.mark.django_db
@pytest.mark.parametrize('objectives_completed,expected_return_value', [
    ([], False),
    (['is_prerequisite_courses_passed'], False),
    (['is_written_application_completed'], False),
    (['is_prerequisite_courses_passed', 'is_written_application_completed'], True)
])
def test_are_application_pre_reqs_completed_in_application_hub(
    objectives_completed, expected_return_value, application_hub
):
    """
    Test if the `are_application_pre_reqs_completed` property is working as expected for all possible cases.
    """
    mark_objectives_complete(application_hub, objectives_completed)
    assert application_hub.are_application_pre_reqs_completed() is expected_return_value


@pytest.mark.django_db
def test_user_application_string_representation(user_application):
    """
    Test that the string representation of a UserApplication object translates to the the full name of the applicant.
    """
    expected_str = user_application.user.profile.name
    actual_str = user_application.__str__()

    assert expected_str == actual_str


@pytest.mark.parametrize('percent', [0.9250, 0.7649])
@pytest.mark.django_db
@mock.patch('openedx.adg.lms.applications.models.CourseGradeFactory.read')
def test_prereq_course_scores(mock_read, user_application, percent, courses):
    """
    Test that the `prereq_course_scores` property returns the correct prerequisite course names and respective scores of
    the applicant in those courses, in the correct format.
    """
    test_course_1 = courses['test_course1']
    test_course_2 = courses['test_course2']
    MultilingualCourseFactory(course=test_course_1)
    MultilingualCourseFactory(course=test_course_2)

    course_grade = CourseGradeFactory()
    course_grade.percent = percent

    mock_read.return_value = course_grade

    score = int(round_away_from_zero(course_grade.percent * 100))
    course_score_1 = CourseScore(test_course_1.display_name, score)
    course_score_2 = CourseScore(test_course_2.display_name, score)

    expected_prereq_course_scores = [course_score_1, course_score_2]
    actual_prereq_course_scores = user_application.prereq_course_scores

    assert expected_prereq_course_scores == actual_prereq_course_scores


@pytest.mark.django_db
def test_education_string_representation(education):
    """
    Test that the string representation of an Education object is an empty string.
    """
    expected_str = ''
    actual_str = education.__str__()

    assert expected_str == actual_str


@pytest.mark.django_db
def test_work_experience_string_representation(work_experience):
    """
    Test that the string representation of a WorkExperience object is an empty string.
    """
    expected_str = ''
    actual_str = work_experience.__str__()

    assert expected_str == actual_str


@pytest.mark.django_db
def test_submitted_applications_manager():
    """
    Test that the SubmittedApplicationsManager returns only submitted applications.
    """
    user_application_1 = UserApplicationFactory()
    user_application_2 = UserApplicationFactory()

    application_hub_1 = ApplicationHubFactory()
    application_hub_1.user = user_application_1.user
    application_hub_1.is_application_submitted = True
    application_hub_1.save()

    application_hub_2 = ApplicationHubFactory()
    application_hub_2.user = user_application_2.user
    application_hub_2.save()

    expected_applications = [user_application_1]
    actual_applications = list(UserApplication.submitted_applications.all())

    assert expected_applications == actual_applications


@pytest.mark.django_db
def test_is_written_application_started(application_hub):
    """
    Test application started method
    """
    assert not application_hub.is_written_application_started


@pytest.mark.django_db
def test_multilingual_course_count():
    """
    Test multilingual course count for a course group
    """
    course_group = MultilingualCourseFactory().multilingual_course_group
    assert course_group.multilingual_course_count() == 1


@pytest.mark.django_db
def test_open_multilingual_courses_count(courses):
    """
    Test open multilingual course count for a course group
    """
    course_group = MultilingualCourseFactory(course=courses['test_course1']).multilingual_course_group
    assert course_group.open_multilingual_courses_count() == 1


@pytest.mark.django_db
def test_open_multilingual_course_keys(courses):
    """
    Test course keys of a course group
    """
    course_group = MultilingualCourseFactory(course=courses['test_course1']).multilingual_course_group
    assert len(course_group.open_multilingual_course_keys()) == 1


@pytest.mark.django_db
def test_get_preferred_lang_course(courses):
    """
    Tests get_preferred_language_course course is active.
    """
    course = courses['test_course1']
    course_group = MultilingualCourseFactory(course=course).multilingual_course_group
    preferred_course = course_group.multilingual_courses.open_multilingual_courses().preferred_lang_course().course
    assert preferred_course.id == course.id


@pytest.mark.django_db
def test_get_preferred_lang_course_expired_courses(expired_course):
    """
    Tests get_preferred_language_course course is expired.
    """
    course_group = MultilingualCourseFactory(course=expired_course).multilingual_course_group
    assert course_group.multilingual_courses.open_multilingual_courses().preferred_lang_course() is None


@pytest.mark.django_db
def test_get_catalog_courses_valid_user(courses, course_group, user_with_profile):
    """
    Tests multiple courses in a single group for a valid user
    """
    MultilingualCourseFactory(
        course=courses['test_course1'],
        multilingual_course_group=course_group
    )
    MultilingualCourseFactory(
        course=courses['test_course2'],
        multilingual_course_group=course_group
    )
    assert len(MultilingualCourseGroup.objects.get_courses(user_with_profile)) == 1


@pytest.mark.django_db
def test_get_catalog_courses_enrolled_user(courses, course_group, user_with_profile):
    """
    Tests multiple courses in a single group and user enrolled in one of the courses
    """
    enrolled_course = courses['test_course2']
    MultilingualCourseFactory(
        course=courses['test_course1'],
        multilingual_course_group=course_group
    )
    MultilingualCourseFactory(
        course=enrolled_course,
        multilingual_course_group=course_group
    )
    CourseEnrollmentFactory(user=user_with_profile, course=enrolled_course)
    courses_list = MultilingualCourseGroup.objects.get_courses(user_with_profile)
    assert len(courses_list) == 1
    assert courses_list[0].id == enrolled_course.id


@pytest.mark.django_db
def test_get_catalog_courses_anonymous_user(courses, course_group):
    """
    Tests multiple courses in a single group for anonymous user
    """
    user = AnonymousUserFactory()
    MultilingualCourseFactory(
        course=courses['test_course1'],
        multilingual_course_group=course_group
    )
    MultilingualCourseFactory(
        course=courses['test_course2'],
        multilingual_course_group=course_group
    )
    assert len(MultilingualCourseGroup.objects.get_courses(user)) == 1


@pytest.mark.django_db
def test_get_catalog_courses_expired_course(expired_course, course_group, user_with_profile):
    """
    Tests expired course in a group for a valid user
    """
    MultilingualCourseFactory(
        course=expired_course,
        multilingual_course_group=course_group
    )
    assert len(MultilingualCourseGroup.objects.get_courses(user_with_profile)) == 0


@pytest.mark.django_db
def test_get_prerequisites_for_user(courses, user_with_profile):
    """
    Tests prerequisites for user
    """
    MultilingualCourseFactory(course=courses['test_course1'])
    assert len(MultilingualCourseGroup.objects.get_courses(user_with_profile, is_prereq=True)) == 1


@pytest.mark.django_db
def test_no_prerequisite_courses(user_with_profile):
    """
    Tests no prerequisites courses for user
    """
    assert len(MultilingualCourseGroup.objects.get_courses(user_with_profile, is_prereq=True)) == 0


@pytest.mark.django_db
def test_get_enrolled_prerequisites_for_user(user_with_profile, courses):
    """
    Tests enrolled prerequisites for user
    """
    MultilingualCourseFactory(course=courses['test_course1'])
    CourseEnrollmentFactory(course=courses['test_course1'], user=user_with_profile, is_active=True)
    assert len(MultilingualCourseGroup.objects.get_courses(user_with_profile, is_prereq=True)) == 1


@pytest.mark.django_db
def test_get_course_group_languages(courses, course_group):
    """
    Tests if the queryset MultilingualCourseQuerySet method `language_codes_with_course_ids()` gets all the
    languages of all the courses in a multilingual course group correctly or not
    """
    course1 = courses['test_course1']
    course2 = courses['test_course2']

    open_multilingual_courses = course_group.multilingual_courses.open_multilingual_courses()

    MultilingualCourseFactory(course=course1, multilingual_course_group=course_group)
    MultilingualCourseFactory(course=course2, multilingual_course_group=course_group)

    actual_output = open_multilingual_courses.language_codes_with_course_ids()
    expected_output = [(course1.id, 'en'), (course2.id, 'ar')]

    assert all([actual_item == expected_item for actual_item, expected_item in zip(actual_output, expected_output)])


@pytest.mark.django_db
def test_multilingual_course_with_course_id(courses):
    """
    Test if the queryset MultilingualCourseQuerySet method `multilingual_course_with_course_id()` gets the
    multilingual course associated with the id
    """
    course = courses['test_course1']
    multilingual_course = MultilingualCourseFactory(course=course)

    assert MultilingualCourse.objects.all().multilingual_course_with_course_id(course.id) == multilingual_course
