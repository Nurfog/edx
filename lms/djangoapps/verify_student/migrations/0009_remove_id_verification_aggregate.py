# -*- coding: utf-8 -*-
# Generated by Django 1.11.12 on 2018-04-27 16:27
from __future__ import absolute_import, unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('verify_student', '0008_populate_idverificationaggregate'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='idverificationaggregate',
            name='content_type',
        ),
        migrations.RemoveField(
            model_name='idverificationaggregate',
            name='user',
        ),
        migrations.DeleteModel(
            name='IDVerificationAggregate',
        ),
    ]
