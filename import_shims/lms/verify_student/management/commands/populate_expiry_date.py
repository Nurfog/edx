"""Deprecated import support. Auto-generated by import_shims/generate_shims.sh."""
# pylint: disable=redefined-builtin,wrong-import-position,wildcard-import,useless-suppression,line-too-long

from import_shims.warn import warn_deprecated_import

warn_deprecated_import('verify_student.management.commands.populate_expiry_date', 'lms.djangoapps.verify_student.management.commands.populate_expiry_date')

from lms.djangoapps.verify_student.management.commands.populate_expiry_date import *
