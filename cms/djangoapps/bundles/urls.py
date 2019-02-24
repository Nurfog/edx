"""
URL configuration for the Studio Bundles API
"""
from django.conf.urls import include, url

from . import views

UUID_PATTERN = r'[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}'

urlpatterns = [
    url(r'^v0/', include([
        # path(r'^bundle/<uuid:bundle_uuid>/', include([  # <-- once we can use Django 2+, simplify this:
        url(r'^bundle/(?P<bundle_uuid_str>{})/'.format(UUID_PATTERN), include([
            url(r'^blocks/$', views.bundle_blocks),
        ])),
        url(r'^block/(?P<usage_key_str>gblock-v1:[^/]+)/', include([
            url(r'^$', views.bundle_block),
            url(r'^handler_url/(?P<handler_name>[\w\-]+)/$', views.bundle_xblock_handler_url),
            url(
                r'^handler/(?P<user_id>\d+)-(?P<secure_token>\w+)/(?P<handler_name>[\w\-]+)/(?P<suffix>.+)?$',
                    views.bundle_xblock_handler,
                    name='bundle_xblock_handler',
                ),
        ])),
    ])),
]
