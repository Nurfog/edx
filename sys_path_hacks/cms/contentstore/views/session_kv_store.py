from sys_path_hacks.warn import warn_deprecated_import

warn_deprecated_import('cms.djangoapps', 'contentstore.views.session_kv_store')

from cms.djangoapps.contentstore.views.session_kv_store import *
