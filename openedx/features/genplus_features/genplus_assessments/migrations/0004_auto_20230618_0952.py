# Generated by Django 2.2.25 on 2023-06-18 09:52

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import jsonfield.encoder
import jsonfield.fields


class Migration(migrations.Migration):

    dependencies = [
        ('genplus', '0015_auto_20230618_0952'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('genplus_learning', '0002_auto_20221207_1157'),
        ('genplus_assessments', '0003_skillassessmentquestion_skillassessmentresponse'),
    ]

    operations = [
        migrations.AddField(
            model_name='skillassessmentquestion',
            name='skill',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='genplus.Skill'),
        ),
        migrations.AddField(
            model_name='skillassessmentresponse',
            name='question_response',
            field=jsonfield.fields.JSONField(blank=True, dump_kwargs={'cls': jsonfield.encoder.JSONEncoder, 'separators': (',', ':')}, load_kwargs={}, null=True),
        ),
        migrations.AddField(
            model_name='skillassessmentresponse',
            name='response_time',
            field=models.CharField(choices=[('start_of_year', 'start_of_year'), ('end_of_year', 'end_of_year')], max_length=32, null=True),
        ),
        migrations.AddField(
            model_name='skillassessmentresponse',
            name='skill_assessment_type',
            field=models.CharField(choices=[('single_choice', 'single_choice'), ('multiple_choice', 'multiple_choice'), ('rating', 'rating')], max_length=32, null=True),
        ),
        migrations.AlterUniqueTogether(
            name='skillassessmentquestion',
            unique_together={('program', 'start_unit_location', 'end_unit_location')},
        ),
        migrations.AlterUniqueTogether(
            name='skillassessmentresponse',
            unique_together={('user', 'question', 'response_time')},
        ),
    ]
