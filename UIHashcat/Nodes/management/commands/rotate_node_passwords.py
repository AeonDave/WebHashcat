import secrets
import string
import sys
from pathlib import Path

from Nodes.models import Node
from django.core.management.base import BaseCommand, CommandError

from NodeHashcat.secrets import hash_password

# Ensure project root (containing HashcatNode) is on sys.path when running manage.py from WebHashcat
ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))


def _generate_password(length: int) -> str:
    if length <= 0:
        raise CommandError("Password length must be greater than zero")
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


class Command(BaseCommand):
    help = "Rotate the HTTP Basic credentials stored for registered Hashcat nodes."

    def add_arguments(self, parser):
        parser.add_argument(
            "--node-id",
            type=int,
            help="Rotate only the node that matches the provided numeric ID.",
        )
        parser.add_argument(
            "--node-name",
            help="Rotate only the node that matches the provided name.",
        )
        parser.add_argument(
            "--length",
            type=int,
            default=32,
            help="Length of the randomly generated password (default: 32).",
        )
        parser.add_argument(
            "--password",
            help="Optional explicit password to apply (useful for testing).",
        )

    def handle(self, *args, **options):
        queryset = Node.objects.all()
        node_id = options.get("node_id")
        node_name = options.get("node_name")

        if node_id is not None:
            queryset = queryset.filter(id=node_id)
        if node_name:
            queryset = queryset.filter(name=node_name)

        if not queryset.exists():
            raise CommandError("No nodes matched the provided filters")

        length = options["length"]
        password_override = options.get("password")
        results = []
        for node in queryset:
            password = password_override or _generate_password(length)
            password_hash = hash_password(password)
            node.password = password
            node.save(update_fields=["password"])
            results.append((node, password, password_hash))

        for node, password, password_hash in results:
            self.stdout.write(
                self.style.SUCCESS(
                    f"{node.name}: username={node.username} password={password} sha256={password_hash}"
                )
            )

        if password_override:
            self.stdout.write(self.style.WARNING("Static password supplied via --password"))
