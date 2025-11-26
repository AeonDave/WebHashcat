from Nodes.models import Node
from django.contrib.auth.models import User
from django.db import models
import logging
from pathlib import Path
from django.db.models.signals import pre_delete
from django.dispatch import receiver


# Create your models here.

class Hashfile(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)  # Link to user
    name = models.CharField(max_length=30)
    hashfile = models.CharField(max_length=30)
    hash_type = models.IntegerField()
    line_count = models.IntegerField()
    cracked_count = models.IntegerField(default=0)
    username_included = models.BooleanField()


class Session(models.Model):
    name = models.CharField(max_length=100)
    hashfile = models.ForeignKey(Hashfile, on_delete=models.CASCADE)
    node = models.ForeignKey(Node, on_delete=models.CASCADE)
    potfile_line_retrieved = models.IntegerField()
    # Optional identifier used to group multiple sessions into a Brain cluster
    # so that the UI can control them with a single set of buttons.
    cluster = models.CharField(max_length=100, null=True, blank=True)


class Hash(models.Model):
    hashfile = models.ForeignKey(Hashfile, on_delete=models.CASCADE)
    hash_type = models.IntegerField()
    username = models.CharField(max_length=190, null=True)
    password = models.CharField(max_length=190, null=True)
    hash = models.TextField(max_length=4096, null=True)  # Changed from char to text
    hash_hash = models.CharField(max_length=190, null=True)  # sha1 of the hash for joins
    password_len = models.IntegerField(null=True)
    password_charset = models.CharField(max_length=100, null=True)
    password_mask = models.CharField(null=True, max_length=190)

    class Meta:
        indexes = [
            models.Index(fields=['hashfile'], name="hashfileid_index"),
            models.Index(fields=['hashfile', 'hash_hash'], name="hashfileid_hash_index"),
            models.Index(fields=['hash_hash', 'hash_type'], name="hash_index"),
        ]


class Search(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)  # Link to user
    name = models.CharField(max_length=100)
    status = models.CharField(max_length=100)
    output_lines = models.IntegerField(null=True)
    output_file = models.TextField()
    processing_time = models.IntegerField(null=True)
    json_search_info = models.TextField()


# Cleanup hooks to avoid orphaned files on disk
LOGGER = logging.getLogger(__name__)


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:  # pragma: no cover - best effort cleanup
        LOGGER.warning("Unable to delete file %s: %s", path, exc)


@receiver(pre_delete, sender=Hashfile)
def _cleanup_hashfile(sender, instance: Hashfile, **kwargs):
    base_dir = Path(__file__).resolve().parent.parent / "Files" / "Hashfiles"
    _safe_unlink(base_dir / instance.hashfile)


@receiver(pre_delete, sender=Search)
def _cleanup_search(sender, instance: Search, **kwargs):
    if instance.output_file:
        _safe_unlink(Path(instance.output_file))
