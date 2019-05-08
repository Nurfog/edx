# -*- coding: utf-8 -*-
# Generated by Django 1.11.20 on 2019-03-13 16:34
from __future__ import unicode_literals

from __future__ import absolute_import
from django.db import migrations, models
import openedx.core.djangoapps.config_model_utils.models


class Migration(migrations.Migration):

    dependencies = [
        ('content_type_gating', '0007_auto_20190311_1919'),
    ]

    operations = [
        migrations.AlterField(
            model_name='contenttypegatingconfig',
            name='org_course',
            field=models.CharField(blank=True, db_index=True, help_text="Configure values for all course runs associated with this course. This is should be formatted as 'org+course' (i.e. MITx+6.002x, HarvardX+CS50).", max_length=255, null=True, validators=[openedx.core.djangoapps.config_model_utils.models.validate_course_in_org], verbose_name='Course in Org'),
        ),
    ]
