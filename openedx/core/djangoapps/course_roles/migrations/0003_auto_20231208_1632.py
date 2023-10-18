# Generated by Django 3.2.23 on 2023-12-08 16:32

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('organizations', '0004_auto_20230727_2054'),
        ('course_overviews', '0029_alter_historicalcourseoverview_options'),
        ('course_roles', '0002_data_load_course_roles_permission'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userrole',
            name='course',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='course_overviews.courseoverview'),
        ),
        migrations.AlterField(
            model_name='userrole',
            name='org',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='organizations.organization'),
        ),
    ]
