# -*- coding: utf-8 -*-
# Generated by Django 1.11.13 on 2018-06-21 19:52
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django_mysql.models


class Migration(migrations.Migration):

    dependencies = [
        ('organizations', '0006_auto_20171207_0259'),
        migrations.swappable_dependency(settings.OAUTH2_PROVIDER_APPLICATION_MODEL),
        ('oauth_dispatch', '0004_auto_20180620_2159'),
    ]

    operations = [
        migrations.CreateModel(
            name='ApplicationAccess',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scopes', django_mysql.models.ListCharField(models.CharField(max_length=32), help_text='Comma-separated list of scopes that this application will be allowed to request.', max_length=825, size=25)),
                ('application', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='access', to=settings.OAUTH2_PROVIDER_APPLICATION_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='ApplicationOrganization',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('provider_type', models.CharField(choices=[(b'content_org', 'Content Provider')], default=b'content_org', max_length=32)),
                ('application', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='organizations', to=settings.OAUTH2_PROVIDER_APPLICATION_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='organizations.Organization')),
            ],
        ),
        migrations.RemoveField(
            model_name='scopedapplication',
            name='user',
        ),
        migrations.RemoveField(
            model_name='scopedapplicationorganization',
            name='application',
        ),
        migrations.DeleteModel(
            name='ScopedApplication',
        ),
        migrations.DeleteModel(
            name='ScopedApplicationOrganization',
        ),
    ]
