# Generated by Django 2.2.19 on 2021-04-01 05:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('organizations', '0003_historicalorganizationcourse'),
        ('course_creators', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='coursecreator',
            name='orgs',
            field=models.ManyToManyField(blank=True, help_text='Organizations for which content creator is a part off', to='organizations.Organization'),
        ),
    ]
