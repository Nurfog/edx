# Generated by Django 2.2.25 on 2023-04-17 08:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('genplus', '0010_auto_20230406_1428'),
    ]

    operations = [
        migrations.AddField(
            model_name='generror',
            name='device',
            field=models.CharField(blank=True, max_length=32, null=True),
        ),
        migrations.AddField(
            model_name='generror',
            name='os',
            field=models.CharField(blank=True, max_length=32, null=True),
        ),
    ]
