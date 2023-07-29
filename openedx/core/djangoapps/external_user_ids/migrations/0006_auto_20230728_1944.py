# Generated by Django 3.2.20 on 2023-07-28 19:44

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('external_user_ids', '0005_add_caliper_and_xapi_lti_types'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='historicalexternalid',
            options={'get_latest_by': ('history_date', 'history_id'), 'ordering': ('-history_date', '-history_id'), 'verbose_name': 'historical external id', 'verbose_name_plural': 'historical external ids'},
        ),
        migrations.AlterModelOptions(
            name='historicalexternalidtype',
            options={'get_latest_by': ('history_date', 'history_id'), 'ordering': ('-history_date', '-history_id'), 'verbose_name': 'historical external id type', 'verbose_name_plural': 'historical external id types'},
        ),
    ]
