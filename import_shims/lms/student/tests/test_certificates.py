from import_shims.warn import warn_deprecated_import

warn_deprecated_import('student.tests.test_certificates', 'common.djangoapps.student.tests.test_certificates')

from common.djangoapps.student.tests.test_certificates import *
