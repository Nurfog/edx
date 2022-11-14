# Generated by Django 3.2.16 on 2022-11-07 15:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('course_modes', '0013_auto_20200115_2022'),
    ]

    operations = [
        migrations.AlterField(
            model_name='coursemode',
            name='expiration_datetime_is_explicit',
            field=models.BooleanField(default=False, help_text='OPTIONAL: Set to True if the upgrade deadline date is explicitly defined. Set to False if there is no upgrade deadline or to use the default upgrade deadline.', verbose_name='Upgrade Deadline Explicitly Defined'),
        ),
        migrations.AlterField(
            model_name='historicalcoursemode',
            name='expiration_datetime_is_explicit',
            field=models.BooleanField(default=False, help_text='OPTIONAL: Set to True if the upgrade deadline date is explicitly defined. Set to False if there is no upgrade deadline or to use the default upgrade deadline.', verbose_name='Upgrade Deadline Explicitly Defined'),
        ),
    ]
