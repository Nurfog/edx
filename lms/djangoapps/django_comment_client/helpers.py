from django.conf import settings
from .mustache_helpers import mustache_helpers
from functools import partial

from .utils import extend_content, merge_dict, render_mustache
import django_comment_client.settings as cc_settings

import pystache_custom as pystache
import urllib
import os

# This method is used to pluralize the words "discussion" and "comment"
# when referring to how many discussion threads or comments the user
# has contributed to.


def pluralize(singular_term, count):
    if int(count) >= 2 or int(count) == 0:
        return singular_term + 's'
    return singular_term

# TODO there should be a better way to handle this


def include_mustache_templates():
    mustache_dir = settings.PROJECT_ROOT / 'templates' / 'discussion' / 'mustache'
    valid_file_name = lambda file_name: file_name.endswith('.mustache')
    read_file = lambda file_name: (file_name, open(mustache_dir / file_name, "r").read())
    strip_file_name = lambda x: (x[0].rpartition('.')[0], x[1])
    wrap_in_tag = lambda x: "<script type='text/template' id='{0}'>{1}</script>".format(x[0], x[1])

    file_contents = map(read_file, filter(valid_file_name, os.listdir(mustache_dir)))
    return '\n'.join(map(wrap_in_tag, map(strip_file_name, file_contents)))
