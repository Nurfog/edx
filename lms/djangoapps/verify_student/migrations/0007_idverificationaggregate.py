# -*- coding: utf-8 -*-
# Generated by Django 1.11.12 on 2018-04-12 15:22
from __future__ import unicode_literals

from __future__ import absolute_import
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import model_utils.fields


class Migration(migrations.Migration):

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('verify_student', '0006_ssoverification'),
    ]

    operations = [
        migrations.CreateModel(
            name='IDVerificationAggregate',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', model_utils.fields.StatusField(choices=[(b'created', b'created'), (b'ready', b'ready'), (b'submitted', b'submitted'), (b'must_retry', b'must_retry'), (b'approved', b'approved'), (b'denied', b'denied')], default=b'created', max_length=100, no_check_for_status=True, verbose_name='status')),
                ('status_changed', model_utils.fields.MonitorField(default=django.utils.timezone.now, monitor='status', verbose_name='status changed')),
                ('name', models.CharField(blank=True, max_length=255)),
                ('object_id', models.PositiveIntegerField()),
                ('created_at', models.DateTimeField(db_index=True)),
                ('updated_at', models.DateTimeField(db_index=True)),
                ('content_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='contenttypes.ContentType')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
