from sys_path_hacks.warn import warn_deprecated_import

warn_deprecated_import('lms.djangoapps', 'dashboard.models')

from lms.djangoapps.dashboard.models import *
