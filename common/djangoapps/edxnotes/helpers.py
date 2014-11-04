import datetime
from uuid import uuid4
from django.conf import settings


def _now():
    """
    Returns current time in URC format.
    """
    return datetime.datetime.utcnow().replace(microsecond=0)


def get_prefix():
    """
    Returns endpoint.
    """
    url = settings.EDXNOTES_INTERFACE["url"] or "/"
    if not url.endswith("/"):
        url += "/"
    return url + "api/v1"


def get_user_id():
    """
    Returns user id.
    """
    return "edx_user"


def get_username():
    """
    Returns user name.
    """
    return "user_name"


def get_usage_id():
    """
    Returns usage id for the component.
    """
    return ""


def get_course_id():
    """
    Returns course id.
    """
    return "course_id"


def generate_uid():
    """
    Generates unique id.
    """
    return uuid4().int
