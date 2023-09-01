# Generated by Django 4.2.4 on 2023-09-01 10:32

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('sites', '0002_alter_domain_unique'),
        ('third_party_auth', '0011_applemigrationuseridinfo'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ltiproviderconfig',
            name='site',
            field=models.ForeignKey(default=1, help_text='The Site that this provider configuration belongs to.', on_delete=django.db.models.deletion.CASCADE, related_name='%(class)ss', to='sites.site'),
        ),
        migrations.AlterField(
            model_name='oauth2providerconfig',
            name='site',
            field=models.ForeignKey(default=1, help_text='The Site that this provider configuration belongs to.', on_delete=django.db.models.deletion.CASCADE, related_name='%(class)ss', to='sites.site'),
        ),
        migrations.AlterField(
            model_name='samlconfiguration',
            name='site',
            field=models.ForeignKey(default=1, help_text='The Site that this SAML configuration belongs to.', on_delete=django.db.models.deletion.CASCADE, related_name='%(class)ss', to='sites.site'),
        ),
        migrations.AlterField(
            model_name='samlproviderconfig',
            name='site',
            field=models.ForeignKey(default=1, help_text='The Site that this provider configuration belongs to.', on_delete=django.db.models.deletion.CASCADE, related_name='%(class)ss', to='sites.site'),
        ),
    ]
