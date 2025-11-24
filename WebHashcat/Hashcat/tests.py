from pathlib import Path
from unittest.mock import patch

from Hashcat.models import Hashfile, Session
from Nodes.models import Node
from Utils.models import Task
from Utils.tasks import import_hashfile_task
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

HASHFILES_DIR = Path(__file__).resolve().parent.parent / "Files" / "Hashfiles"


class _ChunkedUpload(SimpleUploadedFile):
    """Custom upload class that exposes deterministic chunking."""

    def __init__(self, name, chunks):
        self._chunk_parts = [part if isinstance(part, bytes) else part.encode("utf-8") for part in chunks]
        super().__init__(name, b"".join(self._chunk_parts), content_type="text/plain")

    def chunks(self, chunk_size=None):  # pragma: no cover - exercised via tests
        for part in self._chunk_parts:
            yield part


class HashfileUploadViewTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        HASHFILES_DIR.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.user = User.objects.create_user(username="tester", password="pass1234")
        self.client.force_login(self.user)
        self._generated_files = set()
        self.addCleanup(self._cleanup_generated_files)

        self.hashcat_patches = [
            patch("Hashcat.views.Hashcat.get_hash_types", return_value={0: {"id": 0, "name": "MD5"}}),
            patch("Hashcat.views.Hashcat.get_rules", return_value=[]),
            patch("Hashcat.views.Hashcat.get_masks", return_value=[]),
            patch("Hashcat.views.Hashcat.get_wordlists", return_value=[]),
            patch("Hashcat.views.Node.objects.all", return_value=[]),
        ]
        for p in self.hashcat_patches:
            p.start()
            self.addCleanup(p.stop)

    def _cleanup_generated_files(self):
        for path in self._generated_files:
            if path.exists():
                path.unlink()

    def _hashfile_path(self, name="AAAAAAAAAAAA.hashfile"):
        path = HASHFILES_DIR / name
        self._generated_files.add(path)
        return path

    @patch("Hashcat.views.import_hashfile_task")
    @patch("Hashcat.views.init_hashfile_locks")
    @patch("Hashcat.views.random.choice", return_value="A")
    def test_upload_from_text_triggers_import_and_locks(self, mock_choice, mock_init_locks, mock_import_task):
        payload = {
            "action": "add",
            "hash_type": 0,
            "name": "Test Hashfile",
            "hashes": "hash1\nhash2",
        }

        response = self.client.post(reverse("Hashcat:hashfiles"), payload)
        self.assertEqual(response.status_code, 200)

        created = Hashfile.objects.get(name="Test Hashfile")
        self.assertEqual(created.owner, self.user)
        self.assertEqual(created.hashfile, "AAAAAAAAAAAA.hashfile")

        mock_init_locks.assert_called_once_with(created)
        mock_import_task.delay.assert_called_once_with(created.id)

        stored_content = self._hashfile_path().read_text(encoding="utf-8")
        self.assertEqual(stored_content, "hash1\nhash2")

    @patch("Hashcat.views.import_hashfile_task")
    @patch("Hashcat.views.init_hashfile_locks")
    @patch("Hashcat.views.random.choice", return_value="A")
    def test_text_input_takes_precedence_over_uploaded_file(self, mock_choice, mock_init_locks, mock_import_task):
        upload = SimpleUploadedFile("dup.txt", b"file-hash\n", content_type="text/plain")
        payload = {
            "action": "add",
            "hash_type": 0,
            "name": "No Duplicates",
            "hashes": "typed-hash",
            "hashfile": upload,
        }

        self.client.post(reverse("Hashcat:hashfiles"), payload)

        stored_content = self._hashfile_path().read_text(encoding="utf-8")
        self.assertEqual(stored_content, "typed-hash")

    @patch("Hashcat.views.import_hashfile_task")
    @patch("Hashcat.views.init_hashfile_locks")
    @patch("Hashcat.views.random.choice", return_value="A")
    def test_uploaded_file_is_written_chunk_by_chunk(self, mock_choice, mock_init_locks, mock_import_task):
        upload = _ChunkedUpload("chunked.txt", chunks=[b"AAA", b"BBB", b"CCC"])
        payload = {
            "action": "add",
            "hash_type": 0,
            "name": "Chunked",
            "hashes": "",
            "hashfile": upload,
        }

        self.client.post(reverse("Hashcat:hashfiles"), payload)

        stored_content = self._hashfile_path().read_text(encoding="utf-8")
        self.assertEqual(stored_content, "AAABBBCCC")


class ImportHashfileTaskTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="task-user")

    def _create_hashfile(self, **overrides):
        defaults = dict(
            owner=self.user,
            name="Uploading",
            hashfile="sample.hashfile",
            hash_type=0,
            line_count=0,
            cracked_count=0,
            username_included=False,
        )
        defaults.update(overrides)
        return Hashfile.objects.create(**defaults)

    @patch("Utils.tasks.Hashcat.compare_potfile")
    @patch("Utils.tasks.Hashcat.insert_hashes")
    def test_task_imports_hashes_and_compares_potfile(self, mock_insert_hashes, mock_compare_potfile):
        hashfile = self._create_hashfile()

        import_hashfile_task(hashfile.id)

        mock_insert_hashes.assert_called_once()
        mock_compare_potfile.assert_called_once()
        self.assertEqual(Task.objects.count(), 0)

    @patch("Utils.tasks.Hashcat.insert_plaintext")
    @patch("Utils.tasks.Hashcat.compare_potfile")
    @patch("Utils.tasks.Hashcat.insert_hashes")
    def test_plaintext_hash_type_uses_plaintext_import(self, mock_insert_hashes, mock_compare_potfile,
                                                       mock_insert_plaintext):
        hashfile = self._create_hashfile(hash_type=-1)

        import_hashfile_task(hashfile.id)

        mock_insert_plaintext.assert_called_once()
        mock_insert_hashes.assert_not_called()
        mock_compare_potfile.assert_not_called()

    @patch("Utils.tasks.Hashcat.compare_potfile")
    @patch("Utils.tasks.Hashcat.insert_hashes",
           side_effect=RuntimeError("boom"))
    def test_task_cleans_up_lock_task_on_failure(self, mock_insert_hashes, mock_compare_potfile):
        hashfile = self._create_hashfile()

        import_hashfile_task(hashfile.id)

        self.assertEqual(Task.objects.count(), 0)
        mock_compare_potfile.assert_not_called()


class SessionControlViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="owner", password="pass")
        self.client.force_login(self.user)
        self.node = Node.objects.create(name="node-1", hostname="node", port=9999, username="u", password="p")
        self.hashfile = Hashfile.objects.create(
            owner=self.user,
            name="hf",
            hashfile="view.hashfile",
            hash_type=0,
            line_count=0,
            cracked_count=0,
            username_included=False,
        )

    @patch("Hashcat.views.HashcatAPI")
    @patch("Hashcat.views.random.choice", return_value="Z")
    def test_create_dictionary_session(self, mock_choice, mock_api_cls):
        mock_api = mock_api_cls.return_value
        mock_api.create_dictionary_session.return_value = {"response": "ok"}

        payload = {
            "node": self.node.name,
            "hashfile_id": str(self.hashfile.id),
            "crack_type": "dictionary",
            "rule": "best64",
            "wordlist": "rockyou.txt",
            "device_type": "1",
            "brain_mode": "0",
            "end_datetime": "",
        }

        response = self.client.post(reverse("Hashcat:new_session"), payload)
        self.assertEqual(response.status_code, 302)

        created_session = Session.objects.get()
        self.assertTrue(created_session.name.startswith("hf-"))
        mock_api.create_dictionary_session.assert_called_once()
        called_session_name = mock_api.create_dictionary_session.call_args[0][0]
        self.assertEqual(created_session.name, called_session_name)

    @patch("Hashcat.views.HashcatAPI")
    @patch("Hashcat.views.random.choice", return_value="Y")
    def test_create_mask_session(self, mock_choice, mock_api_cls):
        mock_api = mock_api_cls.return_value
        mock_api.create_mask_session.return_value = {"response": "ok"}

        payload = {
            "node": self.node.name,
            "hashfile_id": str(self.hashfile.id),
            "crack_type": "mask",
            "mask": "?d?d?d",
            "device_type": "2",
            "brain_mode": "1",
            "end_datetime": "",
        }

        response = self.client.post(reverse("Hashcat:new_session"), payload)
        self.assertEqual(response.status_code, 302)

        self.assertEqual(Session.objects.count(), 1)
        mock_api.create_mask_session.assert_called_once()
