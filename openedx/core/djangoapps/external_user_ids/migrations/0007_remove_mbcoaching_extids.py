# Generated by Django 3.2.23 on 2023-12-04 18:48
"""Deletes instances of deprecated mb_coaching external ID type"""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("external_user_ids", "0006_auto_20230808_0944"),
    ]

    mb_coaching_type_name = "mb_coaching"

    def delete_ids(apps, schema_editor):
        # The
        ExternalIdType = apps.get_model("external_user_ids", "ExternalIdType")
        mb_coaching_type_id = ExternalIdType.objects.get(
            name=Migration.mb_coaching_type_name
        ).id

        ExternalId = apps.get_model("external_user_ids", "ExternalId")
        ExternalId.objects.filter(external_id_type=mb_coaching_type_id).delete()

    operations = [
        migrations.RunPython(delete_ids, reverse_code=migrations.RunPython.noop)
    ]
