from sys_path_hacks.warn import warn_deprecated_import

warn_deprecated_import('cms.djangoapps', 'contentstore.course_group_config')

from cms.djangoapps.contentstore.course_group_config import *
