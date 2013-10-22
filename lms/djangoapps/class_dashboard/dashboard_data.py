"""
Computes the data to display on the Instructor Dashboard
"""

from courseware import models
from django.db.models import Count
#from queryable_student_module.models import StudentModuleExpand, Log

from xmodule.course_module import CourseDescriptor
from xmodule.modulestore.django import modulestore
from xmodule.modulestore.inheritance import own_metadata


def get_problem_grade_distribution(course_id):
    """
    Returns the grade distribution per problem for the course

    `course_id` the course ID for the course interested in

    Output is a dict, where the key is the problem 'module_id' and the value is a dict with:
        'max_grade' - max grade for this problem
        'grade_distrib' - array of tuples (`grade`,`count`).
    """
    db_query = models.StudentModule.objects.filter(
        course_id__exact=course_id,
        grade__isnull=False,
        module_type__exact="problem",
    ).values('module_state_key', 'grade', 'max_grade').annotate(count_grade=Count('grade'))

    prob_grade_distrib = {}
    for row in db_query:
        curr_problem = row['module_state_key']

        if curr_problem in prob_grade_distrib:
            prob_grade_distrib[curr_problem]['grade_distrib'].append((row['grade'], row['count_grade']))

            if (prob_grade_distrib[curr_problem]['max_grade'] != row['max_grade']) and \
                    (prob_grade_distrib[curr_problem]['max_grade'] < row['max_grade']):
                prob_grade_distrib[curr_problem]['max_grade'] = row['max_grade']

        else:
            prob_grade_distrib[curr_problem] = {
                'max_grade': row['max_grade'],
                'grade_distrib': [(row['grade'], row['count_grade'])]
            }

    return prob_grade_distrib


# def get_problem_attempt_distrib(course_id, max_attempts=10):
#     """
#     Returns the attempt distribution per problem for the course.
# 
#     `course_id` the course ID for the course interested in
# 
#     `max_attempts` any students with more attempts than this are grouped together (default 10)
#     Output is a dicts, where the key is the problem `module_id` and the value is an array where the first index is
#     the number of students that only attempted once, second is two times, etc. The last index is all students that
#     attempted more than `max_attempts` times.
#     """
# 
#     db_query = StudentModuleExpand.objects.filter(
#         course_id__exact=course_id,
#         attempts__isnull=False,
#         module_type__exact="problem",
#     ).values('module_state_key', 'attempts').annotate(count_attempts=Count('attempts'))
# 
#     prob_attempts_distrib = {}
#     for row in db_query:
#         curr_problem = row['module_state_key']
#         if curr_problem not in prob_attempts_distrib:
#             prob_attempts_distrib[curr_problem] = [0] * (max_attempts + 1)
# 
#         if row['attempts'] > max_attempts:
#             prob_attempts_distrib[curr_problem][max_attempts] += row['count_attempts']
#         else:
#             prob_attempts_distrib[curr_problem][row['attempts'] - 1] = row['count_attempts']
# 
#     return prob_attempts_distrib


def get_sequential_open_distrib(course_id):
    """
    Returns the number of students that opened each subsection/sequential of the course

    `course_id` the course ID for the course interested in

    Outputs a dict mapping the 'module_id' to the number of students that have opened that subsection/sequential.
    """

    db_query = models.StudentModule.objects.filter(
        course_id__exact=course_id,
        module_type__exact="sequential",
    ).values('module_state_key').annotate(count_sequential=Count('module_state_key'))

    sequential_open_distrib = {}
    for row in db_query:
        sequential_open_distrib[row['module_state_key']] = row['count_sequential']

    return sequential_open_distrib


# def get_last_populate(course_id, script_id):
#     """
#     Returns the timestamp when a script was last run for a course.
# 
#     `course_id` the course ID for the course interested in
# 
#     `script_id` string identifying the populate script interested in
# 
#     Returns None if there is no known time the script was last run for that course.
#     """
# 
#     db_query = Log.objects.filter(course_id__exact=course_id, script_id__exact=script_id)
# 
#     if len(db_query) > 0:
#         return db_query[0].created  # Model is sorted last first
#     else:
#         return None


def get_problem_set_grade_distribution(course_id, problem_set):
    """
    Returns the grade distribution for the problems specified in `problem_set`.

    `course_id` the course ID for the course interested in

    `problem_set` an array of strings representing problem module_id's.

    Requests from the database the a count of each grade for each problem in the `problem_set`.

    Returns a dict, where the key is the problem 'module_id' and the value is a dict with two parts:
      'max_grade' - the maximum grade possible for the course
      'grade_distrib' - array of tuples (`grade`,`count`) ordered by `grade`
    """

    db_query = models.StudentModule.objects.filter(
        course_id__exact=course_id,
        grade__isnull=False,
        module_type__exact="problem",
        module_state_key__in=problem_set,
    ).values(
        'module_state_key',
        'grade',
        'max_grade',
    ).annotate(count_grade=Count('grade')).order_by('module_state_key', 'grade')

    prob_grade_distrib = {}
    for row in db_query:
        if row['module_state_key'] not in prob_grade_distrib:
            prob_grade_distrib[row['module_state_key']] = {
                'max_grade': 0,
                'grade_distrib': [],
            }

        curr_grade_distrib = prob_grade_distrib[row['module_state_key']]
        curr_grade_distrib['grade_distrib'].append((row['grade'], row['count_grade']))

        if curr_grade_distrib['max_grade'] < row['max_grade']:
            curr_grade_distrib['max_grade'] = row['max_grade']

    return prob_grade_distrib


def get_d3_problem_grade_distribution(course_id):
    """
    Returns problem grade distribution information for each section, data already in format for d3 function.

    `course_id` the course ID for the course interested in

    Returns an array of dicts in the order of the sections. Each dict has:
      'display_name' - display name for the section
      'data' - data for the d3_stacked_bar_graph function of the grade distribution for that problem
    """

    prob_grade_distrib = get_problem_grade_distribution(course_id)
    d3_data = []

    course = modulestore().get_instance(course_id, CourseDescriptor.id_to_location(course_id), depth=4)
    for section in course.get_children():
        curr_section = {}
        curr_section['display_name'] = own_metadata(section)['display_name']
        data = []
        c_subsection = 0
        for subsection in section.get_children():
            c_subsection += 1
            c_unit = 0
            for unit in subsection.get_children():
                c_unit += 1
                c_problem = 0
                for child in unit.get_children():
                    if (child.location.category == 'problem'):
                        c_problem += 1
                        stack_data = []
                        label = "P{0}.{1}.{2}".format(c_subsection, c_unit, c_problem)

                        # Some problems have no data because students have not tried them yet
                        if child.location.url() in prob_grade_distrib:
                            problem_info = prob_grade_distrib[child.location.url()]
                            problem_name = own_metadata(child)['display_name']
                            max_grade = float(problem_info['max_grade'])
                            for (grade, count_grade) in problem_info['grade_distrib']:
                                percent = 0.0
                                if max_grade > 0:
                                    percent = (grade * 100.0) / max_grade

                                tooltip = "{0} {3} - {1} students ({2:.0f}%: {4:.0f}/{5:.0f} questions)".format(
                                    label, count_grade, percent, problem_name, grade, max_grade
                                )

                                stack_data.append({
                                    'color': percent,
                                    'value': count_grade,
                                    'tooltip': tooltip,
                                })

                        problem = {
                            'xValue': label,
                            'stackData': stack_data,
                        }
                        data.append(problem)
        curr_section['data'] = data

        d3_data.append(curr_section)

    return d3_data


def get_d3_problem_attempt_distribution(course_id, max_attempts=10):
    """
    Returns problem attempt distribution information for each section, data already in format for d3 function.

    `course_id` the course ID for the course interested in

    `max_attempts` any students with more attempts than this are grouped together (default: 10)

    Returns an array of dicts in the order of the sections. Each dict has:
      'display_name' - display name for the section
      'data' - data for the attempt distribution of problems in this section for d3_stacked_bar_graph
    """

    prob_attempts_distrib = get_problem_attempt_distrib(course_id, max_attempts)

    d3_data = []

    course = modulestore().get_instance(course_id, CourseDescriptor.id_to_location(course_id), depth=4)
    for section in course.get_children():
        curr_section = {}
        curr_section['display_name'] = own_metadata(section)['display_name']
        data = []
        c_subsection = 0
        for subsection in section.get_children():
            c_subsection += 1
            c_unit = 0
            for unit in subsection.get_children():
                c_unit += 1
                c_problem = 0
                for child in unit.get_children():
                    if (child.location.category == 'problem'):
                        c_problem += 1
                        stack_data = []
                        label = "P{0}.{1}.{2}".format(c_subsection, c_unit, c_problem)

                        if child.location.url() in prob_attempts_distrib:
                            attempts_distrib = prob_attempts_distrib[child.location.url()]
                            problem_name = own_metadata(child)['display_name']

                            for i in range(0, max_attempts + 1):
                                color = (i + 1 if i != max_attempts else "{0}+".format(max_attempts))
                                tooltip = "{0} {3} - {1} Student(s) had {2} attempt(s)".format(
                                    label, attempts_distrib[i], color, problem_name
                                )

                                stack_data.append({
                                    'color': color,
                                    'value': attempts_distrib[i],
                                    'tooltip': tooltip,
                                })

                        problem = {
                            'xValue': label,
                            'stackData': stack_data,
                        }
                        data.append(problem)
        curr_section['data'] = data

        d3_data.append(curr_section)

    return d3_data


def get_d3_sequential_open_distribution(course_id):
    """
    Returns how many students opened a sequential/subsection for each section, data already in format for d3 function.

    `course_id` the course ID for the course interested in

    Returns an array in the order of the sections and each dict has:
      'display_name' - display name for the section
      'data' - data for the d3_stacked_bar_graph function of how many students opened each sequential/subsection
    """
    sequential_open_distrib = get_sequential_open_distrib(course_id)

    d3_data = []

    course = modulestore().get_instance(course_id, CourseDescriptor.id_to_location(course_id), depth=4)
    for section in course.get_children():
        curr_section = {}
        curr_section['display_name'] = own_metadata(section)['display_name']
        data = []
        c_subsection = 0
        for subsection in section.get_children():
            c_subsection += 1
            subsection_name = own_metadata(subsection)['display_name']

            num_students = 0
            if subsection.location.url() in sequential_open_distrib:
                num_students = sequential_open_distrib[subsection.location.url()]

            stack_data = []
            tooltip = "{0} student(s) opened Subsection {1}: {2}".format(
                num_students, c_subsection, subsection_name
            )
            stack_data.append({
                'color': 0,
                'value': num_students,
                'tooltip': tooltip,
            })
            subsection = {
                'xValue': "SS {0}".format(c_subsection),
                'stackData': stack_data,
            }
            data.append(subsection)

        curr_section['data'] = data
        d3_data.append(curr_section)

    return d3_data


def get_d3_section_grade_distribution(course_id, section):
    """
    Returns the grade distribution for the problems in the `section` section in a format for the d3 code.

    `course_id` a string that is the course's ID.

    `section` an int that is a zero-based index into the course's list of sections.

    Navigates to the section specified to find all the problems associated with that section and then finds the grade
    distribution for those problems. Finally returns an object formated the way the d3_stacked_bar_graph.js expects its
    data object to be in.

    If this is requested multiple times quickly for the same course, it is better to call
    get_d3_problem_grade_distribution and pick out the sections of interest.

    Returns an array of dicts with the following keys (taken from d3_stacked_bar_graph.js's documentation)
      'xValue' - Corresponding value for the x-axis
      'stackData' - Array of objects with key, value pairs that represent a bar:
        'color' - Defines what "color" the bar will map to
        'value' - Maps to the height of the bar, along the y-axis
        'tooltip' - (Optional) Text to display on mouse hover
    """

    course = modulestore().get_instance(course_id, CourseDescriptor.id_to_location(course_id), depth=4)

    problem_set = []
    problem_info = {}
    c_subsection = 0
    for subsection in course.get_children()[section].get_children():
        c_subsection += 1
        c_unit = 0
        for unit in subsection.get_children():
            c_unit += 1
            c_problem = 0
            for child in unit.get_children():
                if (child.location.category == 'problem'):
                    c_problem += 1
                    problem_set.append(child.location.url())
                    problem_info[child.location.url()] = {
                        'id': child.location.url(),
                        'x_value': "P{0}.{1}.{2}".format(c_subsection, c_unit, c_problem),
                        'display_name': own_metadata(child)['display_name'],
                    }

    grade_distrib = get_problem_set_grade_distribution(course_id, problem_set)

    d3_data = []
    for problem in problem_set:
        stack_data = []

        if problem in grade_distrib:  # Some problems have no data because students have not tried them yet.
            max_grade = float(grade_distrib[problem]['max_grade'])
            for (grade, count_grade) in grade_distrib[problem]['grade_distrib']:
                percent = 0.0
                if max_grade > 0:
                    percent = (grade * 100.0) / max_grade

                tooltip = "{0} {3} - {1} students ({2:.0f}%: {4:.0f}/{5:.0f} questions)".format(
                    problem_info[problem]['x_value'],
                    count_grade,
                    percent,
                    problem_info[problem]['display_name'],
                    grade,
                    max_grade,
                )

                stack_data.append({
                    'color': percent,
                    'value': count_grade,
                    'tooltip': tooltip,
                })

        d3_data.append({
            'xValue': problem_info[problem]['x_value'],
            'stackData': stack_data,
        })

    return d3_data


def get_section_display_name(course_id):
    """
    Returns an array of the display names for each section in the course.

    `course_id` the course ID for the course interested in

    The ith string in the array is the display name of the ith section in the course.
    """

    course = modulestore().get_instance(course_id, CourseDescriptor.id_to_location(course_id), depth=4)

    section_display_name = [""] * len(course.get_children())
    i = 0
    for section in course.get_children():
        section_display_name[i] = own_metadata(section)['display_name']
        i += 1

    return section_display_name


def get_array_section_has_problem(course_id):
    """
    Returns an array of true/false whether each section has problems.

    `course_id` the course ID for the course interested in

    The ith value in the array is true if the ith section in the course contains problems and false otherwise.
    """

    course = modulestore().get_instance(course_id, CourseDescriptor.id_to_location(course_id), depth=4)

    b_section_has_problem = [False] * len(course.get_children())
    i = 0
    for section in course.get_children():
        for subsection in section.get_children():
            for unit in subsection.get_children():
                for child in unit.get_children():
                    if child.location.category == 'problem':
                        b_section_has_problem[i] = True
                        break  # out of child loop
                if b_section_has_problem[i]:
                    break  # out of unit loop
            if b_section_has_problem[i]:
                break  # out of subsection loop

        i += 1

    return b_section_has_problem
