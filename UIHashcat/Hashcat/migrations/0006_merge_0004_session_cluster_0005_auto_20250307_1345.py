from django.db import migrations


class Migration(migrations.Migration):

    # This migration resolves the fork in the Hashcat migration graph between
    # 0004_session_cluster (which adds the Session.cluster field) and
    # 0005_auto_20250307_1345 (which introduces the owner relations on
    # Hashfile and Search). Both branches are already reflected in
    # Hashcat.models, so we simply merge them without applying additional
    # schema changes.

    dependencies = [
        ("Hashcat", "0004_session_cluster"),
        ("Hashcat", "0005_auto_20250307_1345"),
    ]

    operations = []
