from sys_path_hacks.warn import warn_deprecated_import

warn_deprecated_import('lms.djangoapps', 'grades.config')

from lms.djangoapps.grades.config import *
