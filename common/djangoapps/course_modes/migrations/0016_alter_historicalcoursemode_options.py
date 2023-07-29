# Generated by Django 3.2.20 on 2023-07-28 19:44

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('course_modes', '0015_expiration_datetime_explicit_admin'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='historicalcoursemode',
            options={'get_latest_by': ('history_date', 'history_id'), 'ordering': ('-history_date', '-history_id'), 'verbose_name': 'historical course mode', 'verbose_name_plural': 'historical course modes'},
        ),
    ]
