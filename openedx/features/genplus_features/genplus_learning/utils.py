import statistics
from collections import defaultdict

from django.contrib.auth.models import User
from django.conf import settings
from django.apps import apps
from django.urls import reverse
from django.test import RequestFactory

from opaque_keys.edx.keys import UsageKey
from xmodule.modulestore.django import modulestore
from common.djangoapps.student.models import CourseEnrollment
from common.djangoapps.course_modes.models import CourseMode
from openedx.features.course_experience.utils import get_course_outline_block_tree
from openedx.core.djangoapps.content.course_overviews.models import CourseOverview
from openedx.features.genplus_features.genplus.models import Student
from openedx.features.genplus_features.genplus_learning.models import (
    Program, ProgramEnrollment, Unit, ClassLesson, ClassUnit, UnitCompletion, UnitBlockCompletion
)
from openedx.features.genplus_features.genplus_learning.constants import ProgramEnrollmentStatuses
from openedx.features.genplus_features.genplus_learning.access import allow_access
from openedx.features.genplus_features.genplus_learning.roles import ProgramStaffRole, ProgramInstructorRole


def calculate_class_lesson_progress(course_key, usage_key, gen_class):
    # there are no users in this class
    user_ids = gen_class.students.all().values_list('gen_user__user', flat=True)
    if not user_ids:
        return 0

    students_lesson_progress = UnitBlockCompletion.objects.filter(
        user__in=user_ids, course_key=course_key, usage_key=usage_key, block_type='chapter'
    ).values_list('progress', flat=True)
    # no user in this class has attempted this lesson
    if not students_lesson_progress:
        return 0

    count = user_ids.count() - students_lesson_progress.count()
    students_lesson_progress = list(students_lesson_progress)
    students_lesson_progress += [0 for i in range(count)]
    return round(statistics.fmean(students_lesson_progress))


def calculate_class_unit_progress(course_key, gen_class):
    user_ids = gen_class.students.all().values_list('gen_user__user', flat=True)
    # there are no users in this class
    if not user_ids:
        return 0

    students_unit_progress = UnitCompletion.objects.filter(
        user__in=user_ids, course_key=course_key
    ).values_list('progress', flat=True)
    # no user in this class has attempted this unit
    if not students_unit_progress:
        return 0

    count = user_ids.count() - students_unit_progress.count()
    students_unit_progress = list(students_unit_progress)
    students_unit_progress += [0 for i in range(count)]
    return round(statistics.fmean(students_unit_progress))


def get_next_problem_url(course_key, user, request=None, include_lesson_block=False):
    if request is None:
        request = RequestFactory().get(u'/')
        request.user = user

    exclude_block_types = ['course', 'chapter', 'sequential', 'vertical']
    course_outline_blocks = get_course_outline_block_tree(
        request, str(course_key), request.user
    )
    unit = Unit.objects.filter(course=course_key).first()
    student = Student.objects.filter(gen_user__user=user).first()
    if unit and student:
        enrollment = ProgramEnrollment.objects.filter(student=student, program=unit.program).first()
        if enrollment:
            lessons = ClassLesson.objects.filter(class_unit__gen_class=enrollment.gen_class, course_key=course_key)
            sections = course_outline_blocks.get('children')
            for i, section in enumerate(sections):
                lesson = lessons.get(usage_key=UsageKey.from_string(section.get('id')))
                sections[i]['is_locked'] = lesson.is_locked if lesson else True
            course_outline_blocks['children'] = sections

    if not course_outline_blocks:
        return None

    return get_next_problem_url_helper(course_outline_blocks, exclude_block_types, include_lesson_block)


def get_next_problem_url_helper(course_block, exclude_block_types, include_lesson_block=False):
    block_type = course_block.get('type')
    next_block_id = None
    if block_type not in exclude_block_types:
        if not course_block.get('complete'):
            return course_block.get('id')
    else:
        course_block_children = course_block.get('children', [])
        for block in course_block_children:
            if block.get('type') == 'chapter' and block.get('is_locked'):
                continue
            next_block_id = next_block_id or get_next_problem_url_helper(block, exclude_block_types, include_lesson_block)

        if include_lesson_block and next_block_id and course_block.get('type') == 'chapter':
            return next_block_id, course_block

    return next_block_id


def get_user_next_program_lesson(user, program):
    for unit in program.units.all():
        next_problem = get_next_problem_url(str(unit.course.id), user, include_lesson_block=True)
        if not next_problem:
            continue
        next_block_id, lesson_block = next_problem
        if next_block_id and lesson_block:
            course_display_name = unit.course.display_name_with_default
            url_to_block = reverse(
                'jump_to',
                kwargs={'course_id': unit.course.id, 'location': next_block_id}
            )
            return {
                'display_name': f'{course_display_name}-{lesson_block.get("display_name")}',
                'url': f'{settings.LMS_ROOT_URL}{url_to_block}'
            }

    return None


def get_course_completion(course_key, user, include_block_children, block_id=None, request=None):
    if request is None:
        request = RequestFactory().get(u'/')
        request.user = user

    course_outline_blocks = get_course_outline_block_tree(
        request, course_key, request.user
    )

    if not course_outline_blocks:
        return None

    completion = get_course_block_completion(
        course_outline_blocks,
        include_block_children,
        block_id
    )

    return completion


def get_course_block_completion(course_block, include_block_children, block_id=None):

    if course_block is None:
        return {
            'block_type': None,
            'total_blocks': 0,
            'total_completed_blocks': 0,
        }

    course_block_children = course_block.get('children')
    block_type = course_block.get('type')
    completion = {
        'id': course_block.get('id'),
        'block_type': block_type,
    }

    if not course_block_children:
        completion['attempted'] = block_id is not None and block_id == course_block.get('block_id')
        if course_block.get('complete'):
            completion['total_blocks'] = 1
            completion['total_completed_blocks'] = 1
        else:
            completion['total_blocks'] = 1
            completion['total_completed_blocks'] = 0
        return completion

    completion['total_blocks'] = 0
    completion['total_completed_blocks'] = 0
    if block_type in include_block_children:
        completion['children'] = []

    attempted = False
    for block in course_block_children:
        child_completion = get_course_block_completion(
            block,
            include_block_children,
            block_id
        )

        completion['total_blocks'] += child_completion['total_blocks']
        completion['total_completed_blocks'] += child_completion['total_completed_blocks']
        attempted = attempted or child_completion['attempted']

        if block_type in include_block_children:
            completion['children'].append(child_completion)

    completion['attempted'] = attempted
    return completion


def get_progress_and_completion_status(total_completed_blocks, total_blocks):
    progress = round((total_completed_blocks / total_blocks) * 100) if total_blocks else 0
    is_complete = total_blocks == total_completed_blocks if total_blocks else False
    return progress, is_complete


def update_class_lessons(course_key):
    # retrieve units for all classes with course_key
    class_units = ClassUnit.objects.filter(course_key=course_key)

    course = modulestore().get_course(course_key)
    new_lesson_usage_keys = set(course.children)  # children has list of section usage keys

    old_lessons = ClassLesson.objects.filter(course_key=course_key)
    old_lesson_usage_keys = set(old_lessons.values_list('usage_key', flat=True))

    # delete removed section_usage_keys records
    removed_usage_keys = old_lesson_usage_keys - new_lesson_usage_keys
    ClassLesson.objects.filter(course_key=course_key, usage_key__in=removed_usage_keys).delete()

    new_usage_keys = new_lesson_usage_keys - old_lesson_usage_keys
    new_class_lessons = [
        ClassLesson(class_unit=class_unit, course_key=course_key, usage_key=usage_key)
        for class_unit in class_units
        for usage_key in new_usage_keys
    ]

    # bulk create new class lessons
    ClassLesson.objects.bulk_create(new_class_lessons)
    # update lesson order
    for order, usage_key in enumerate(course.children, start=1):
        ClassLesson.objects.filter(course_key=course_key, usage_key=usage_key).update(order=order)


def get_absolute_url(request, file):
    return request.build_absolute_uri(file.url) if file else None


def process_pending_student_program_enrollments(gen_user):
    pending_enrollments = ProgramEnrollment.objects.filter(
                                student__gen_user=gen_user,
                                gen_class__isnull=False,
                                status=ProgramEnrollmentStatuses.PENDING)

    for program_enrollment in pending_enrollments:
        course_ids = program_enrollment.program.all_units_ids

        for course_id in course_ids:
            course_enrollment, created = CourseEnrollment.objects.get_or_create(
                course_id=course_id,
                user_id=gen_user.user.id,
                mode=CourseMode.AUDIT,
            )

        if CourseEnrollment.objects.filter(course_id__in=course_ids, user_id=gen_user.user.id).count() == len(course_ids):
            program_enrollment.status = ProgramEnrollmentStatuses.ENROLLED
            program_enrollment.save()
            Student.objects.filter(gen_user=gen_user).update(active_class=program_enrollment.gen_class)


def process_pending_teacher_program_access(gen_user):
    user = User.objects.filter(gen_user=gen_user)
    programs = Program.get_active_programs()
    for program in programs:
        allow_access(program, ProgramStaffRole.ROLE_NAME, user)
