from import_shims.warn import warn_deprecated_import

warn_deprecated_import('third_party_auth.pipeline', 'common.djangoapps.third_party_auth.pipeline')

from common.djangoapps.third_party_auth.pipeline import *
