from import_shims.warn import warn_deprecated_import

warn_deprecated_import('courseware.tests.test_views', 'lms.djangoapps.courseware.tests.test_views')

from lms.djangoapps.courseware.tests.test_views import *
