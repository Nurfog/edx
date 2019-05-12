# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from __future__ import absolute_import
from django.db import migrations, models
import openedx.core.djangoapps.xmodule_django.models


class Migration(migrations.Migration):

    dependencies = [
        ('block_structure', '0003_blockstructuremodel_storage'),
    ]

    operations = [
        migrations.AlterField(
            model_name='blockstructuremodel',
            name='data_usage_key',
            field=openedx.core.djangoapps.xmodule_django.models.UsageKeyWithRunField(unique=True, max_length=255, verbose_name='Identifier of the data being collected.'),
        ),
    ]
