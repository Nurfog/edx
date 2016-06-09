"""
Django admin dashboard configuration.
"""

from django.contrib import admin
from config_models.admin import ConfigurationModelAdmin
from xblock_django.models import XBlockDisableConfig, XBlockConfig, XBlockConfigFlag
from simple_history.admin import SimpleHistoryAdmin


#class XBlockConfigAdmin(SimpleHistoryAdmin):
class XBlockConfigAdmin(admin.ModelAdmin):
    """Admin for XBlock Configuration"""
    list_display = ('name', 'template', 'support_level', 'deprecated')

admin.site.register(XBlockDisableConfig, ConfigurationModelAdmin)
admin.site.register(XBlockConfigFlag, ConfigurationModelAdmin)
admin.site.register(XBlockConfig, XBlockConfigAdmin)
