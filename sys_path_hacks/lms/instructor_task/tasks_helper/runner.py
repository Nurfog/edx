from sys_path_hacks.warn import warn_deprecated_import

warn_deprecated_import('lms.djangoapps', 'instructor_task.tasks_helper.runner')

from lms.djangoapps.instructor_task.tasks_helper.runner import *
