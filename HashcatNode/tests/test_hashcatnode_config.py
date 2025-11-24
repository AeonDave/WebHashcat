import configparser
import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from HashcatNode import secrets as node_secrets
from HashcatNode.hashcat import Hashcat, HashcatExecutionError, Session


class SecretHelperTests(unittest.TestCase):
    def setUp(self):
        self.config = configparser.ConfigParser()
        self.config.read_dict(
            {
                "Server": {
                    "bind": "0.0.0.0",
                    "port": "9999",
                    "username": "cfg-user",
                    "sha256hash": "",
                }
            }
        )

    def test_secret_file_overrides_inline_value(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("file-secret\n")
            secret_path = handle.name

        self.addCleanup(lambda: os.unlink(secret_path))

        with mock.patch.dict(
                os.environ,
                {
                    "HASHCATNODE_PASSWORD": "env-secret",
                    "HASHCATNODE_PASSWORD_FILE": secret_path,
                },
                clear=False,
        ):
            self.assertEqual(node_secrets.read_secret("HASHCATNODE_PASSWORD"), "file-secret")

    def test_resolve_credentials_prefers_env_username_and_password(self):
        with mock.patch.dict(
                os.environ,
                {
                    "HASHCATNODE_USERNAME": "env-user",
                    "HASHCATNODE_PASSWORD": "new-secret",
                },
                clear=False,
        ):
            username, password_hash = node_secrets.resolve_credentials(self.config["Server"])

        self.assertEqual(username, "env-user")
        self.assertEqual(password_hash, node_secrets.hash_password("new-secret"))

    def test_resolve_credentials_requires_some_secret(self):
        config = configparser.ConfigParser()
        config.read_dict({"Server": {"bind": "0.0.0.0", "port": "9999", "username": "", "sha256hash": ""}})

        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                node_secrets.resolve_credentials(config["Server"])

    def test_resolve_credentials_rejects_conflicting_env(self):
        with mock.patch.dict(
                os.environ,
                {
                    "HASHCATNODE_PASSWORD": "secret",
                    "HASHCATNODE_HASH": "abcd",
                },
                clear=False,
        ):
            with self.assertRaises(RuntimeError):
                node_secrets.resolve_credentials(self.config["Server"])

    def test_hash_password_helper(self):
        self.assertEqual(node_secrets.hash_password("abc"),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


class SessionCrackedTests(unittest.TestCase):
    def setUp(self):
        self.hash_file = tempfile.NamedTemporaryFile("w", delete=False)
        self.hash_file.write("hash\n")
        self.hash_file.flush()
        self.hash_file.close()
        self.result_file = tempfile.NamedTemporaryFile("w", delete=False)
        self.result_file.write("hash:password\n")
        self.result_file.flush()
        self.result_file.close()
        self.addCleanup(lambda: os.unlink(self.hash_file.name))
        self.addCleanup(lambda: os.unlink(self.result_file.name))

    @mock.patch("HashcatNode.hashcat.Hashcat.run_hashcat")
    def test_cracked_uses_wrapper_and_returns_output(self, mock_run):
        Hashcat.binary = "/opt/hashcat/hashcat"
        mock_run.return_value = subprocess.CompletedProcess(
            [Hashcat.binary, "--show"], 0, stdout="", stderr=""
        )

        session = Session(
            hash_mode_id=0,
            hash_file=self.hash_file.name,
            username_included=False,
            pot_file="/tmp/potfile",
            result_file=self.result_file.name,
        )

        output = session.cracked()

        self.assertIn("password", output)
        self.assertTrue(mock_run.called)
        called_cmd = mock_run.call_args[0][0]
        self.assertEqual(called_cmd[0], Hashcat.binary)


class Md5HelperTests(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile("w", delete=False)
        self.temp_file.write("hashcat\n")
        self.temp_file.flush()
        self.temp_file.close()
        self.addCleanup(lambda: os.unlink(self.temp_file.name))

    def test_md5_for_file_uses_run_hashcat_on_posix(self):
        with mock.patch("HashcatNode.hashcat.os.name", "posix"):
            with mock.patch(
                    "HashcatNode.hashcat.Hashcat.run_hashcat",
                    return_value=subprocess.CompletedProcess(["md5sum"], 0, stdout="abcd  file\n", stderr=""),
            ) as mock_run:
                digest = Hashcat._md5_for_file(self.temp_file.name)

        self.assertEqual(digest, "abcd")
        mock_run.assert_called_once_with(["md5sum", self.temp_file.name])

    def test_md5_for_file_falls_back_on_error(self):
        with mock.patch("HashcatNode.hashcat.os.name", "posix"):
            with mock.patch(
                    "HashcatNode.hashcat.Hashcat.run_hashcat",
                    side_effect=HashcatExecutionError(["md5sum"], 1, "", "boom"),
            ):
                digest = Hashcat._md5_for_file(self.temp_file.name)

        with open(self.temp_file.name, "rb") as handle:
            expected = hashlib.md5(handle.read()).hexdigest()
        self.assertEqual(digest, expected)


class AssetLoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

    @mock.patch("HashcatNode.hashcat.Hashcat._md5_for_file", return_value="deadbeef")
    def test_parse_rules_uses_shared_loader(self, mock_md5):
        rule_path = Path(self.temp_dir.name) / "test.rule"
        rule_path.write_text("rule", encoding="utf-8")
        Hashcat.rules_dir = self.temp_dir.name

        Hashcat.parse_rules()

        self.assertIn("test.rule", Hashcat.rules)
        self.assertEqual(Hashcat.rules["test.rule"]["md5"], "deadbeef")
        mock_md5.assert_called_once_with(str(rule_path))

    @mock.patch("HashcatNode.hashcat.Hashcat._md5_for_file", return_value="feedface")
    def test_parse_masks_filters_extension(self, mock_md5):
        mask_path = Path(self.temp_dir.name) / "mask.hcmask"
        mask_path.write_text("?u?l", encoding="utf-8")
        other_path = Path(self.temp_dir.name) / "ignore.txt"
        other_path.write_text("skip", encoding="utf-8")
        Hashcat.mask_dir = self.temp_dir.name

        Hashcat.parse_masks()

        self.assertIn("mask.hcmask", Hashcat.masks)
        self.assertNotIn("ignore.txt", Hashcat.masks)
        mock_md5.assert_called_once_with(str(mask_path))

    @mock.patch("HashcatNode.hashcat.Hashcat._md5_for_file", return_value="c0ffee")
    def test_parse_wordlists_accepts_any_extension(self, mock_md5):
        wordlist_path = Path(self.temp_dir.name) / "list.txt"
        wordlist_path.write_text("pass", encoding="utf-8")
        Hashcat.wordlist_dir = self.temp_dir.name

        Hashcat.parse_wordlists()

        self.assertIn("list.txt", Hashcat.wordlists)
        mock_md5.assert_called_once_with(str(wordlist_path))


class SessionCommandTests(unittest.TestCase):
    def setUp(self):
        # minimal session setup
        self.session = Session.__new__(Session)
        self.session.name = "sess"
        self.session.crack_type = "dictionary"
        self.session.hash_mode_id = -2  # autodetect
        self.session.hash_file = "/tmp/hashes"
        self.session.wordlist_file = "/tmp/wl"
        self.session.mask_file = "/tmp/mask"
        self.session.rule_file = None
        self.session.username_included = False
        self.session.device_type = None
        self.session.brain_mode = 0
        self.session.pot_file = "/tmp/pot"
        self.session.hashcat_output_file = tempfile.NamedTemporaryFile(delete=False).name
        self.session.mask = "mask"
        self.session.mask_file = "/tmp/mask"
        self.session.session_status = ""
        self.session.thread = None
        self.session.save = mock.Mock()
        self.session.update_session = mock.Mock()
        self.session._finalize_process_result = mock.Mock()

    @mock.patch("HashcatNode.hashcat.subprocess.Popen")
    def test_autodetect_omits_hash_mode_flag(self, mock_popen):
        popen_inst = mock.Mock()
        popen_inst.stdout = []
        popen_inst.stderr = mock.Mock()
        popen_inst.wait.return_value = 0
        mock_popen.return_value = popen_inst

        self.session._start_thread = Session.__dict__['start']  # type: ignore[attr-defined]
        # Trigger session_thread via start()
        self.session.start()

        args = mock_popen.call_args[0][0]
        self.assertNotIn("-m", args)

    @mock.patch("HashcatNode.hashcat.subprocess.Popen")
    def test_mask_includes_mask_file(self, mock_popen):
        popen_inst = mock.Mock()
        popen_inst.stdout = []
        popen_inst.stderr = mock.Mock()
        popen_inst.wait.return_value = 0
        mock_popen.return_value = popen_inst

        self.session.crack_type = "mask"
        self.session._start_thread = Session.__dict__['start']  # type: ignore[attr-defined]
        self.session.start()

        args = mock_popen.call_args[0][0]
        self.assertIn(self.session.mask_file, args)
