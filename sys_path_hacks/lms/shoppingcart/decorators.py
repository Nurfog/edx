from sys_path_hacks.warn import warn_deprecated_import

warn_deprecated_import('lms.djangoapps', 'shoppingcart.decorators')

from lms.djangoapps.shoppingcart.decorators import *
