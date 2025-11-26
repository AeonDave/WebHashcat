import base64
import os
import tempfile
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from Hashcat.models import Hashfile, Session, Search
from Nodes.models import Node


class CacheBackedApiTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="admin",
            password="pass",
            is_staff=True,
            is_superuser=True,
        )
        self.client.force_login(self.user)

    def _mock_cache(self, snapshot, metadata=None):
        metadata = metadata or {"available": True, "age_seconds": 0, "is_stale": False}
        patcher = mock.patch("API.views.HashcatSnapshotCache")
        fake_cache_cls = patcher.start()
        self.addCleanup(patcher.stop)
        fake_cache = fake_cache_cls.return_value
        fake_cache.get_snapshot.return_value = snapshot
        fake_cache.get_metadata.return_value = metadata
        return fake_cache

    def test_node_status_uses_cached_snapshot(self):
        node = Node.objects.create(name="node-a", hostname="n1", port=9999, username="u", password="p")
        snapshot = {
            "nodes": {
                str(node.id): {
                    "version": "7.1.2",
                    "status": "Running",
                }
            }
        }
        self._mock_cache(snapshot)

        response = self.client.get(reverse("API:api_node_status"), {"draw": 1})
        payload = response.json()

        self.assertEqual(len(payload["data"]), 1)
        row = payload["data"][0]
        self.assertEqual(row["name"], node.name)
        self.assertEqual(row["version"], "7.1.2")
        self.assertEqual(row["status"], "Running")
        self.assertIn("cache", payload)

    def test_running_sessions_read_from_cache(self):
        node = Node.objects.create(name="node-b", hostname="n2", port=9999, username="u", password="p")
        hashfile = Hashfile.objects.create(
            owner=self.user,
            name="hf",
            hashfile="hf.hash",
            hash_type=1000,
            line_count=10,
            cracked_count=0,
            username_included=False,
        )
        session = Session.objects.create(name="sess123", hashfile=hashfile, node=node, potfile_line_retrieved=0)
        snapshot = {
            "sessions": {
                session.name: {
                    "response": "ok",
                    "status": "Running",
                    "crack_type": "dictionary",
                    "rule": "best64",
                    "wordlist": "rockyou.txt",
                    "time_estimated": "1m",
                    "progress": 42,
                    "speed": "123 H/s",
                    "node_name": node.name,
                }
            }
        }
        self._mock_cache(snapshot)

        response = self.client.get(reverse("API:api_running_sessions"), {"draw": 9})
        payload = response.json()

        self.assertEqual(len(payload["data"]), 1)
        row = payload["data"][0]
        self.assertEqual(row["node"], node.name)
        self.assertEqual(row["progress"], "42 %")
        self.assertEqual(row["rule_mask"], "best64")
        self.assertEqual(row["wordlist"], "rockyou.txt")

    def test_hashfile_sessions_endpoint_surfaces_cached_details(self):
        node = Node.objects.create(name="node-c", hostname="n3", port=9999, username="u", password="p")
        hashfile = Hashfile.objects.create(
            owner=self.user,
            name="hf2",
            hashfile="hf2.hash",
            hash_type=0,
            line_count=5,
            cracked_count=0,
            username_included=False,
        )
        session = Session.objects.create(name="sess999", hashfile=hashfile, node=node, potfile_line_retrieved=0)

        snapshot = {
            "nodes": {
                str(node.id): {
                    "status": "Running",
                }
            },
            "sessions": {
                session.name: {
                    "response": "ok",
                    "status": "Paused",
                    "crack_type": "dictionary",
                    "rule": "rules.rule",
                    "wordlist": "words.txt",
                    "time_estimated": "2m",
                    "progress": 10,
                    "speed": "200 H/s",
                }
            },
        }
        self._mock_cache(snapshot)

        response = self.client.get(
            reverse("API:api_hashfile_sessions"),
            {"draw": 3, "hashfile_id": f"row_{hashfile.id}"},
        )

        payload = response.json()
        self.assertEqual(len(payload["data"]), 1)
        row = payload["data"][0]
        self.assertEqual(row["node"], node.name)
        self.assertEqual(row["status"], "Paused")
        self.assertIn("resume", row["buttons"])  # Paused sessions expose resume button

    @mock.patch("API.views.Hashcat.get_hash_types", return_value={0: {"name": "MD5"}})
    def test_hashfiles_datatable_includes_pagination_and_cache(self, mock_hash_types):
        node = Node.objects.create(name="node-d", hostname="n4", port=9999, username="u", password="p")
        hashfile_a = Hashfile.objects.create(
            owner=self.user,
            name="alpha-list",
            hashfile="alpha.hash",
            hash_type=0,
            line_count=25,
            cracked_count=5,
            username_included=False,
        )
        hashfile_b = Hashfile.objects.create(
            owner=self.user,
            name="beta-list",
            hashfile="beta.hash",
            hash_type=-1,
            line_count=10,
            cracked_count=0,
            username_included=True,
        )
        Session.objects.create(name="alpha-session", hashfile=hashfile_a, node=node, potfile_line_retrieved=0)

        snapshot = {
            "nodes": {
                str(node.id): {
                    "sessions": [{"name": "alpha-session", "status": "Running"}],
                    "status": "Running",
                }
            },
        }
        metadata = {"available": True, "age_seconds": 1, "is_stale": False}
        self._mock_cache(snapshot, metadata)

        params = {
            "draw": "5",
            "order[0][column]": "0",
            "order[0][dir]": "asc",
            "search[value]": "alpha",
            "start": "0",
            "length": "10",
        }
        response = self.client.get(reverse("API:api_hashfiles"), params)
        payload = response.json()

        self.assertEqual(payload["draw"], "5")
        self.assertEqual(payload["recordsTotal"], 2)
        self.assertEqual(payload["recordsFiltered"], 1)
        self.assertEqual(len(payload["data"]), 1)
        row = payload["data"][0]
        # La tabella hashfiles usa ora pulsanti renderizzati lato frontend, quindi
        # l'API non espone più HTML legacy in una colonna "buttons".
        # Verifichiamo invece che i campi strutturali e la cache siano corretti.
        self.assertEqual(row["DT_RowId"], f"row_{hashfile_a.id}")
        self.assertIn("alpha-list", row["name"])
        self.assertEqual(row["sessions_count"], "1 / 1")
        self.assertEqual(payload["cache"], metadata)

    def test_hashfile_sessions_handles_cache_miss(self):
        node = Node.objects.create(name="node-e", hostname="n5", port=9999, username="u", password="p")
        hashfile = Hashfile.objects.create(
            owner=self.user,
            name="gamma",
            hashfile="gamma.hash",
            hash_type=0,
            line_count=1,
            cracked_count=0,
            username_included=False,
        )
        Session.objects.create(name="gamma-session", hashfile=hashfile, node=node, potfile_line_retrieved=0)

        snapshot = None
        metadata = {"available": False, "is_stale": True}
        self._mock_cache(snapshot, metadata)

        response = self.client.get(
            reverse("API:api_hashfile_sessions"),
            {"draw": "2", "hashfile_id": f"row_{hashfile.id}"},
        )
        payload = response.json()

        self.assertEqual(payload["draw"], "2")
        self.assertEqual(payload["cache"], metadata)
        self.assertEqual(payload["data"][0]["status"], "Node data unavailable")

    def test_error_sessions_surface_reason_from_snapshot(self):
        node = Node.objects.create(name="node-error", hostname="n7", port=9999, username="u", password="p")
        hashfile = Hashfile.objects.create(
            owner=self.user,
            name="epsilon",
            hashfile="epsilon.hash",
            hash_type=0,
            line_count=1,
            cracked_count=0,
            username_included=False,
        )
        Session.objects.create(name="sess-error", hashfile=hashfile, node=node, potfile_line_retrieved=0)

        snapshot = {
            "sessions": {
                "sess-error": {
                    "response": "error",
                    "status": "Error",
                    "reason": "GPU-watchdog alarm",
                    "node_name": node.name,
                },
            },
        }
        self._mock_cache(snapshot)

        response = self.client.get(reverse("API:api_error_sessions"), {"draw": "11"})
        payload = response.json()

        self.assertEqual(payload["draw"], "11")
        self.assertEqual(payload["data"][0]["reason"], "GPU-watchdog alarm")
        self.assertEqual(payload["data"][0]["status"], "Inexistant session on node")

    def test_hashfile_sessions_cache_hit_renders_controls(self):
        node = Node.objects.create(name="node-f", hostname="n6", port=9999, username="u", password="p")
        hashfile = Hashfile.objects.create(
            owner=self.user,
            name="delta",
            hashfile="delta.hash",
            hash_type=0,
            line_count=1,
            cracked_count=0,
            username_included=False,
        )
        session = Session.objects.create(name="delta-session", hashfile=hashfile, node=node, potfile_line_retrieved=0)

        snapshot = {
            "nodes": {},
            "sessions": {
                session.name: {
                    "response": "ok",
                    "status": "Running",
                    "crack_type": "dictionary",
                    "rule": "best64",
                    "wordlist": "rockyou",
                    "progress": 12,
                    "speed": "10 H/s",
                },
            },
        }
        metadata = {"available": True, "is_stale": False}
        self._mock_cache(snapshot, metadata)

        response = self.client.get(
            reverse("API:api_hashfile_sessions"),
            {"draw": "4", "hashfile_id": str(hashfile.id)},
        )
        payload = response.json()

        row = payload["data"][0]
        self.assertEqual(row["status"], "Running")
        # I controlli di sessione usano ora pulsanti testuali moderni
        self.assertIn("Pause", row["buttons"])
        self.assertEqual(row["progress"], "12 %")
        self.assertEqual(payload["cache"], metadata)

    def test_error_sessions_uses_snapshot_dataclass(self):
        node = Node.objects.create(name="node-error", hostname="n7", port=9999, username="u", password="p")
        hashfile = Hashfile.objects.create(
            owner=self.user,
            name="epsilon",
            hashfile="epsilon.hash",
            hash_type=0,
            line_count=1,
            cracked_count=0,
            username_included=False,
        )
        Session.objects.create(name="sess-error", hashfile=hashfile, node=node, potfile_line_retrieved=0)

        snapshot = {
            "sessions": {
                "sess-error": {
                    "response": "error",
                    "status": "Error",
                    "reason": "GPU-watchdog alarm",
                    "node_name": node.name,
                },
            },
        }
        self._mock_cache(snapshot)

        response = self.client.get(reverse("API:api_error_sessions"), {"draw": "11"})
        payload = response.json()

        self.assertEqual(payload["draw"], "11")
        self.assertEqual(payload["data"][0]["reason"], "GPU-watchdog alarm")
        self.assertEqual(payload["data"][0]["status"], "Inexistant session on node")

    @mock.patch("API.views.HashcatSnapshotCache")
    def test_hashfile_sessions_fallback_when_cache_missing(self, mock_cache_cls):
        node = Node.objects.create(name="node-fallback", hostname="nf", port=9999, username="u", password="p")
        hashfile = Hashfile.objects.create(
            owner=self.user,
            name="delta",
            hashfile="delta.hash",
            hash_type=0,
            line_count=1,
            cracked_count=0,
            username_included=False,
        )
        session = Session.objects.create(name="delta-session", hashfile=hashfile, node=node, potfile_line_retrieved=0)

        mock_cache = mock_cache_cls.return_value
        mock_cache.get_snapshot.return_value = None
        mock_cache.get_metadata.return_value = {"available": False, "is_stale": True}

        response = self.client.get(
            reverse("API:api_hashfile_sessions"),
            {"draw": "6", "hashfile_id": str(hashfile.id)},
        )
        payload = response.json()

        self.assertEqual(payload["draw"], "6")
        self.assertEqual(payload["cache"]["available"], False)
        # without cache, status should indicate unavailable data
        row = payload["data"][0]
        self.assertEqual(row["status"], "Node data unavailable")

    @mock.patch("API.views.HashcatSnapshotCache")
    def test_running_sessions_returns_cache_metadata(self, mock_cache_cls):
        node = Node.objects.create(name="node-x", hostname="nx", port=9999, username="u", password="p")
        hashfile = Hashfile.objects.create(
            owner=self.user,
            name="hf-x",
            hashfile="hf-x.hash",
            hash_type=0,
            line_count=1,
            cracked_count=0,
            username_included=False,
        )
        session = Session.objects.create(name="sess-x", hashfile=hashfile, node=node, potfile_line_retrieved=0)
        mock_cache = mock_cache_cls.return_value
        mock_cache.get_snapshot.return_value = {
            "sessions": {
                session.name: {
                    "response": "ok",
                    "status": "Running",
                    "crack_type": "dictionary",
                    "rule": "best64",
                    "wordlist": "wl",
                    "progress": 10,
                    "speed": "1 H/s",
                }
            }
        }
        mock_cache.get_metadata.return_value = {"available": True, "age_seconds": 1, "is_stale": False}

        response = self.client.get(reverse("API:api_running_sessions"), {"draw": "1"})
        payload = response.json()

        self.assertEqual(payload["draw"], "1")
        self.assertEqual(payload["cache"]["available"], True)
        self.assertEqual(len(payload["data"]), 1)

    def test_search_list_includes_export_buttons_and_counts(self):
        search_file = tempfile.NamedTemporaryFile(delete=False)
        search_file.write(b"results")
        search_file.close()
        self.addCleanup(lambda: os.remove(search_file.name))

        search1 = Search.objects.create(
            owner=self.user,
            name="Report One",
            status="Done",
            output_lines=5,
            output_file=search_file.name,
            processing_time=60,
        )
        Search.objects.create(
            owner=self.user,
            name="Other Report",
            status="Running",
            output_lines=None,
            output_file="/tmp/missing.csv",
            processing_time=None,
        )

        response = self.client.get(
            reverse("API:api_search_list"),
            {
                "draw": "7",
                "order[0][column]": "0",
                "order[0][dir]": "asc",
                "search[value]": "Report",
                "start": "0",
                "length": "10",
            },
        )
        payload = response.json()

        self.assertEqual(payload["draw"], "7")
        self.assertEqual(payload["recordsTotal"], 2)
        self.assertEqual(payload["recordsFiltered"], 2)
        self.assertEqual(len(payload["data"]), 2)

        # api_search_list now returns a list of objects with named columns
        names = [row["name"] for row in payload["data"]]
        self.assertIn("Report One", names)

        download_row = next(row for row in payload["data"] if row["name"] == "Report One")
        html_actions = download_row["actions"]
        # Ensure that the HTML includes both the view and download controls
        self.assertIn("data-search-action='view'", html_actions)
        self.assertIn("Download", html_actions)


class SessionActionApiTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.owner = User.objects.create_user(username="owner", password="pw")
        self.other = User.objects.create_user(username="other", password="pw")
        self.client.force_login(self.owner)

        self.node = Node.objects.create(name="node-z", hostname="n4", port=9999, username="u", password="p")
        self.hashfile = Hashfile.objects.create(
            owner=self.owner,
            name="hf-action",
            hashfile="hf-action.hash",
            hash_type=0,
            line_count=0,
            cracked_count=0,
            username_included=False,
        )
        self.session = Session.objects.create(name="sess-action", hashfile=self.hashfile, node=self.node,
                                              potfile_line_retrieved=0)

    @mock.patch("API.views.HashcatAPI")
    def test_remove_session_deletes_record(self, mock_api_cls):
        mock_api = mock_api_cls.return_value
        mock_api.action.return_value = {"response": "ok"}

        response = self.client.post(
            reverse("API:api_session_action"),
            {"session_name": self.session.name, "action": "remove"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(Session.objects.filter(pk=self.session.pk).exists())
        mock_api.action.assert_called_once_with(self.session.name, "remove")

    @mock.patch("API.views.HashcatAPI")
    def test_action_requires_owner_or_staff(self, mock_api_cls):
        self.client.force_login(self.other)

        response = self.client.post(
            reverse("API:api_session_action"),
            {"session_name": self.session.name, "action": "pause"},
        )

        self.assertEqual(response.status_code, 404)
        mock_api_cls.return_value.action.assert_not_called()

    @mock.patch("API.views.HashcatAPI")
    def test_non_remove_action_keeps_session(self, mock_api_cls):
        mock_api = mock_api_cls.return_value
        mock_api.action.return_value = {"response": "ok", "status": "Paused"}

        response = self.client.post(
            reverse("API:api_session_action"),
            {"session_name": self.session.name, "action": "pause"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(Session.objects.filter(pk=self.session.pk).exists())
        self.assertEqual(response.json()["response"], "ok")


class UploadApiTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.staff = User.objects.create_user(username="staff", password="pw", is_staff=True)
        self.endpoint = reverse("API:api_upload_file")

    def _auth_headers(self, username, password):
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"HTTP_AUTHORIZATION": f"Basic {token}"}

    def test_rejects_missing_auth(self):
        response = self.client.post(self.endpoint)
        self.assertEqual(response.status_code, 401)

    @mock.patch("API.views.import_hashfile_task.delay")
    @mock.patch("API.views.init_hashfile_locks")
    def test_hashfile_upload_creates_hashfile_and_locks(self, mock_init_locks, mock_delay):
        self.client.logout()
        file_content = b"hash1\nhash2"
        payload = {
            "name": "uploaded.hash",
            "type": "hashfile",
            "hash_type": "0",
            "username_included": "on",
        }
        payload["file"] = SimpleUploadedFile("hashes.txt", file_content)

        response = self.client.post(
            self.endpoint,
            payload,
            **self._auth_headers("staff", "pw")
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["result"], "success")
        hashfile = Hashfile.objects.get(name="uploaded.hash")
        self.assertTrue(hashfile.username_included)
        mock_init_locks.assert_called_once_with(hashfile)
        mock_delay.assert_called_once_with(hashfile.id)

    @mock.patch("API.views.Hashcat.upload_wordlist")
    def test_wordlist_upload_invokes_helper(self, mock_upload_wordlist):
        file_data = SimpleUploadedFile("wl.txt", b"one\n")
        response = self.client.post(
            self.endpoint,
            {"name": "my.wl", "type": "wordlist", "file": file_data},
            **self._auth_headers("staff", "pw")
        )

        self.assertEqual(response.status_code, 200)
        mock_upload_wordlist.assert_called_once_with("my.wl", b"one\n")

    def test_non_staff_user_denied(self):
        regular = get_user_model().objects.create_user(username="user", password="pw")
        file_data = SimpleUploadedFile("wl.txt", b"one\n")
        response = self.client.post(
            self.endpoint,
            {"name": "bad", "type": "wordlist", "file": file_data},
            **self._auth_headers("user", "pw")
        )

        self.assertEqual(response.status_code, 401)
