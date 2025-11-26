from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("Hashcat", "0003_auto_20200610_1159"),
    ]

    operations = [
        migrations.AddField(
            model_name="session",
            name="cluster",
            field=models.CharField(max_length=100, null=True, blank=True),
        ),
    ]
