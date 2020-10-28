# -*- coding: utf-8 -*-
# Generated by Django 1.11.20 on 2019-05-20 20:13
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('third_party_auth', '0023_auto_20190418_2033'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ltiproviderconfig',
            name='organization',
            field=models.ForeignKey(blank=True, help_text='optional. If this provider is an Organization, this attribute can be used reference users in that Organization', null=True, on_delete=django.db.models.deletion.CASCADE, to='organizations.Organization'),
        ),
        migrations.AlterField(
            model_name='oauth2providerconfig',
            name='organization',
            field=models.ForeignKey(blank=True, help_text='optional. If this provider is an Organization, this attribute can be used reference users in that Organization', null=True, on_delete=django.db.models.deletion.CASCADE, to='organizations.Organization'),
        ),
        migrations.AlterField(
            model_name='samlproviderconfig',
            name='organization',
            field=models.ForeignKey(blank=True, help_text='optional. If this provider is an Organization, this attribute can be used reference users in that Organization', null=True, on_delete=django.db.models.deletion.CASCADE, to='organizations.Organization'),
        ),
    ]
