# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('course_overviews', '0013_courseoverview_language'),
    ]

    operations = [
        migrations.AddField(
            model_name='courseoverview',
            name='certificate_available_date',
            field=models.DateTimeField(default=None, null=True),
        ),
    ]
