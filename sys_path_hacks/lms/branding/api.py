from sys_path_hacks.warn import warn_deprecated_import

warn_deprecated_import('lms.djangoapps', 'branding.api')

from lms.djangoapps.branding.api import *
