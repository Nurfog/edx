# -*- coding: utf-8 -*-
from __future__ import unicode_literals

# Converted from the original South migration 0002_default_rate_limit_config.py

from django.db import migrations, models
from django.conf import settings
from django.core.files import File

def forwards(apps, schema_editor):
    """Add default modes"""
    badge_image_configuration_model = apps.get_model("certificates", "BadgeImageConfiguration")

    for mode in ['honor', 'verified', 'professional']:
        conf, created = badge_image_configuration_model.objects.get_or_create(mode=mode)
        if created:
            file_name = '{0}{1}'.format(mode, '.png')
            conf.icon.save(
                'badges/{}'.format(file_name),
                File(open(settings.PROJECT_ROOT / 'static' / 'images' / 'default-badges' / file_name))
            )

            conf.save()


class Migration(migrations.Migration):

    dependencies = [
        ('certificates', '0003_data__certificatehtmlviewconfiguration_data'),
    ]

    operations = [
        migrations.RunPython(forwards)
    ]
