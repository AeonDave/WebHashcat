import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from HashcatNode import hashcatnode


class EnsureTlsMaterialTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.cert_path = Path(self.temp_dir.name) / "server.crt"
        self.key_path = Path(self.temp_dir.name) / "server.key"

    def test_returns_existing_cert_and_key_without_generating(self):
        self.cert_path.write_text("cert")
        self.key_path.write_text("key")

        with mock.patch("HashcatNode.hashcatnode.subprocess.run") as mock_run:
            cert, key = hashcatnode._ensure_tls_material(self.cert_path, self.key_path)

        self.assertEqual(cert, str(self.cert_path))
        self.assertEqual(key, str(self.key_path))
        mock_run.assert_not_called()

    def test_generates_cert_and_key_when_missing(self):
        def _fake_openssl(cmd, check):
            self.cert_path.write_text("generated cert")
            self.key_path.write_text("generated key")
            return mock.Mock()

        with mock.patch("HashcatNode.hashcatnode.subprocess.run", side_effect=_fake_openssl) as mock_run, \
                mock.patch("HashcatNode.hashcatnode.os.chmod") as mock_chmod:
            cert, key = hashcatnode._ensure_tls_material(self.cert_path, self.key_path)

        self.assertEqual(cert, str(self.cert_path))
        self.assertEqual(key, str(self.key_path))
        mock_run.assert_called_once()
        self.assertTrue(self.cert_path.exists())
        self.assertTrue(self.key_path.exists())
        mock_chmod.assert_called_once_with(self.key_path, 0o600)

    def test_tls_days_env_is_used(self):
        def _fake_openssl(cmd, check):
            self.cert_path.write_text("generated cert")
            self.key_path.write_text("generated key")
            return mock.Mock()

        with mock.patch("HashcatNode.hashcatnode.subprocess.run", side_effect=_fake_openssl) as mock_run, \
                mock.patch.dict(os.environ, {"HASHCATNODE_TLS_DAYS": "10"}, clear=False):
            hashcatnode._ensure_tls_material(self.cert_path, self.key_path)
        called_cmd = mock_run.call_args[0][0]
        self.assertIn("10", called_cmd)


class MainEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings_path = Path(self.tmp.name) / "settings.ini"
        self.cert_dir = Path(self.tmp.name) / "certs"
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        self.cert_file = self.cert_dir / "server.crt"
        self.key_file = self.cert_dir / "server.key"

        self.settings_path.write_text(
            "[General]\nloglevel=info\n"
            "[Server]\nbind=0.0.0.0\nport=9999\nusername=user\nsha256hash=\n"
            "[Hashcat]\nbinary=/bin/true\nhashes_dir=/tmp\nrule_dir=/tmp\nwordlist_dir=/tmp\nmask_dir=/tmp\nworkload_profile=2\n"
            "[Brain]\nenabled=false\nport=13743\npassword=brainpw\n",
            encoding="utf-8",
        )

    def test_main_reads_env_overrides(self):
        with mock.patch("HashcatNode.hashcatnode.SETTINGS_PATH", self.settings_path), \
                mock.patch.dict(os.environ, {
                    "HASHCATNODE_USERNAME": "envuser",
                    "HASHCATNODE_PASSWORD": "envpass",
                    "HASHCATNODE_CERT_PATH": str(self.cert_file),
                    "HASHCATNODE_KEY_PATH": str(self.key_file),
                }, clear=False), \
                mock.patch("HashcatNode.hashcatnode._ensure_tls_material",
                           return_value=(str(self.cert_file), str(self.key_file))), \
                mock.patch("HashcatNode.hashcatnode.Server") as mock_server, \
                mock.patch("HashcatNode.hashcatnode.Hashcat") as mock_hashcat:
            mock_hashcat.return_value = mock.Mock()
            hashcatnode.main(run_server=True)

        mock_server.assert_called_once()
        args, kwargs = mock_server.call_args
        self.assertIn("envuser", args)
        # args: bind, port, username, password_hash, hashes_dir, cert_file, key_file
        self.assertEqual(args[5], str(self.cert_file))
        self.assertEqual(args[6], str(self.key_file))

    def test_build_settings_constructs_dataclass(self):
        with mock.patch("HashcatNode.hashcatnode.SETTINGS_PATH", self.settings_path), \
                mock.patch.dict(os.environ, {"HASHCATNODE_PASSWORD": "pw"}, clear=False), \
                mock.patch("HashcatNode.hashcatnode._ensure_tls_material",
                        return_value=(str(self.cert_file), str(self.key_file))):
            config = hashcatnode._read_config()
            settings = hashcatnode._build_settings(config)

        self.assertEqual(settings.bind_address, "0.0.0.0")
        self.assertEqual(settings.bind_port, 9999)
        self.assertEqual(settings.username, "user")
        self.assertEqual(settings.binary, "/bin/true")
        self.assertEqual(settings.cert_file, str(self.cert_file))
        self.assertEqual(settings.brain_host, "")
        self.assertEqual(settings.brain_enabled, "false")

    def test_apply_to_hashcat_sets_attributes(self):
        settings = hashcatnode.NodeSettings(
            bind_address="0.0.0.0",
            bind_port=9999,
            username="user",
            password_hash="hash",
            binary="/bin/true",
            hashes_dir="/tmp/hashes",
            rules_dir="/tmp/rules",
            mask_dir="/tmp/masks",
            wordlist_dir="/tmp/wordlists",
            workload_profile="2",
            cert_file="/tmp/cert",
            key_file="/tmp/key",
            brain_enabled="true",
            brain_host="host",
            brain_port="1234",
            brain_password="pw",
        )

        settings.apply_to_hashcat()
        self.assertEqual(hashcatnode.Hashcat.binary, "/bin/true")
        self.assertEqual(hashcatnode.Hashcat.rules_dir, "/tmp/rules")
        self.assertEqual(hashcatnode.Hashcat.brain["host"], "host")
