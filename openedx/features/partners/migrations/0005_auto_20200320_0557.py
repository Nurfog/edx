# -*- coding: utf-8 -*-
# Generated by Django 1.11.21 on 2020-03-20 09:57
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('partners', '0004_auto_20200320_0542'),
    ]

    operations = [
        migrations.AlterField(
            model_name='partner',
            name='logo',
            field=models.ImageField(help_text=b'Main Logo in Landing page.', upload_to=b'media/partners/logo'),
        ),
    ]
