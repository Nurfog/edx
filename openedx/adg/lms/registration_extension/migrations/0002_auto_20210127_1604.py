# Generated by Django 2.2.17 on 2021-01-27 16:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registration_extension', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='extendeduserprofile',
            name='saudi_national',
            field=models.BooleanField(null=True, verbose_name='Are you a Saudi National?'),
        ),
    ]
