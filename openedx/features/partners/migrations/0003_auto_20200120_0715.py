# -*- coding: utf-8 -*-
# Generated by Django 1.11.21 on 2020-01-20 12:15
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('partners', '0002_auto_20200101_1222'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='partner',
            options={'permissions': (('can_access_g2a_performance', 'Can access g2a performance'),), 'verbose_name': 'Partner', 'verbose_name_plural': 'Partners'},
        ),
        migrations.AddField(
            model_name='partner',
            name='performance_url',
            field=models.URLField(blank=True, default=None),
        ),
    ]
