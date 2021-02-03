from django.conf.urls import url  # lint-amnesty, pylint: disable=missing-module-docstring

from .views import CourseOutlineView


urlpatterns = [
    url(
        r'^v1/course_outline/(?P<course_key_str>.+)$',
        CourseOutlineView.as_view(),
        name='course_outline',
    )
]
