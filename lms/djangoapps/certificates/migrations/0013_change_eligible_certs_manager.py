# -*- coding: utf-8 -*-
# Generated by Django 1.10.8 on 2017-12-04 18:24
from __future__ import unicode_literals

from django.db import migrations
import django.db.models.manager


class Migration(migrations.Migration):

    dependencies = [
        ('certificates', '0012_certificategenerationcoursesetting_include_hours_of_effort'),
    ]

    operations = [
        migrations.AlterModelManagers(
            name='generatedcertificate',
            managers=[
                ('eligible_certificates', django.db.models.manager.Manager()),
            ],
        ),
    ]
