# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


def create_dark_lang_config(apps, schema_editor):
    """
    Enable DarkLang by default when it is installed, to prevent accidental
    release of testing languages.
    """
    dark_lang_model = apps.get_model("dark_lang", "DarkLangConfig")
    db_alias = schema_editor.connection.alias

    dark_lang_model.objects.using(db_alias).get_or_create(enabled=True)

def remove_dark_lang_config(apps, schema_editor):
    """Write your backwards methods here."""
    raise RuntimeError("Cannot reverse this migration.")

class Migration(migrations.Migration):

    dependencies = [
        ('dark_lang', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(create_dark_lang_config, remove_dark_lang_config),
    ]
