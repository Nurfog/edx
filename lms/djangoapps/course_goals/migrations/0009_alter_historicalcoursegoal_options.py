# Generated by Django 3.2.20 on 2023-07-28 19:44

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('course_goals', '0008_coursegoalreminderstatus'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='historicalcoursegoal',
            options={'get_latest_by': ('history_date', 'history_id'), 'ordering': ('-history_date', '-history_id'), 'verbose_name': 'historical course goal', 'verbose_name_plural': 'historical course goals'},
        ),
    ]
