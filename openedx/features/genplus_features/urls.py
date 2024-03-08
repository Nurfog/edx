"""
URLs for genplus features.
"""
from django.conf.urls import url, include
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions
from .views import file_upload_view

genplus_url_patterns = [
]

schema_view = get_schema_view(
    openapi.Info(
        title="GenZ API",
        default_version="v1",
        description="GenZ custom features API documentation",
    ),
    patterns=genplus_url_patterns,
    public=True,
    permission_classes=[permissions.AllowAny]
)

genplus_url_patterns += [
    url(r'^genplus/swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    url(r'^genplus/swagger/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    url(r'^genplus/upload-thumbnail/$', file_upload_view, name='file-upload'),
]
