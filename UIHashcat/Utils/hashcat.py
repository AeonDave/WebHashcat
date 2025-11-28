#!/usr/bin/python3
import hashlib
import io
import logging
import os
import random
import re
import shlex
import string
import subprocess
import tempfile
import time
import traceback
from hashlib import sha1
from operator import itemgetter
from os import listdir
from os.path import isfile, join
from shutil import copyfile
from typing import Any, Callable, Dict, List, Optional, Union

import humanize
from django.db import connection
from django.db import transaction
from django.db.utils import OperationalError

from Hashcat.models import Hash, Session, Hashfile
from Utils import file_metadata
from Utils.hashcatAPI import HashcatAPIError, HashcatAPI
from Utils.models import Lock
from Utils.utils import del_hashfile_locks

LOGGER = logging.getLogger(__name__)


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


class HashcatExecutionError(RuntimeError):
    """Raised when a hashcat subprocess fails."""

    def __init__(self, cmd, returncode, stdout=None, stderr=None):
        super().__init__(f"Hashcat command failed with exit code {returncode}: {shlex.join(cmd)}")
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class ClassProperty(property):
    def __get__(self, cls, owner):
        return self.fget.__get__(None, owner)()


class PotfileManager:
    """Helper to backup, restore and optimize the global potfile."""

    def __init__(self, potfile_path: str, *, runner=None):
        self.potfile_path = potfile_path
        self.backup_path = potfile_path + ".bkp"
        self._run_cmd = runner or Hashcat.run_hashcat

    def _line_count(self, path: str) -> int:
        if not os.path.exists(path):
            return 0
        return sum(1 for _ in open(path, errors="backslashreplace"))

    def backup(self) -> Dict[str, int]:
        current_count = self._line_count(self.potfile_path)
        backup_count = self._line_count(self.backup_path)
        if current_count > backup_count:
            copyfile(self.potfile_path, self.backup_path)
        elif current_count < backup_count:
            LOGGER.error("Potfile appears to be corrupted")
        return {"current": current_count, "backup": backup_count}

    def restore_if_corrupt(self) -> bool:
        current_count = self._line_count(self.potfile_path)
        backup_count = self._line_count(self.backup_path)
        if backup_count > current_count and backup_count > 0:
            copyfile(self.backup_path, self.potfile_path)
            return True
        return False

    def optimize(self) -> None:
        self.backup()
        optimized = False
        while not optimized:
            with transaction.atomic():
                try:
                    potfile_locks = list(Lock.objects.select_for_update().filter(lock_ressource="potfile"))

                    try:
                        sorted_unique = self._run_cmd(["sort", "-u", self.potfile_path]).stdout or ""
                    except HashcatExecutionError as exc:
                        LOGGER.error("Unable to optimize potfile with sort -u: %s", exc)
                        raise

                    tmp_file = tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8")
                    try:
                        tmp_file.write(sorted_unique)
                        tmp_file.flush()
                        tmp_file.close()
                        os.replace(tmp_file.name, self.potfile_path)
                    finally:
                        try:
                            os.unlink(tmp_file.name)
                        except FileNotFoundError:
                            pass

                    del potfile_locks
                    optimized = True
                except OperationalError:
                    pass


class Hashcat(object):
    _hash_types = {}
    _version = None

    @classmethod
    def run_hashcat(
            cls,
            cmd: List[str],
            *,
            check: bool = True,
            capture_output: bool = True,
            text: bool = True,
            env: Optional[Dict[str, str]] = None,
            cwd: Optional[str] = None,
            input_data: Optional[Union[str, bytes]] = None,
            timeout: Optional[float] = None,
            stdout: Optional[int] = None,
            stderr: Optional[int] = None,
    ) -> subprocess.CompletedProcess:
        if not cmd:
            raise ValueError("Command list must not be empty")

        binary_dir = os.path.dirname(cls.get_binary())
        exec_cwd = cwd or binary_dir
        log_cmd = shlex.join(cmd)
        LOGGER.debug("Executing hashcat command: %s", log_cmd)

        run_kwargs: Dict[str, Any] = {
            "check": False,
            "text": text,
            "cwd": exec_cwd,
            "env": env,
            "input": input_data,
            "timeout": timeout,
        }
        if capture_output:
            run_kwargs["capture_output"] = True
        else:
            if stdout is not None:
                run_kwargs["stdout"] = stdout
            if stderr is not None:
                run_kwargs["stderr"] = stderr

        try:
            completed = subprocess.run(cmd, **run_kwargs)
        except OSError as exc:
            LOGGER.exception("Failed to run hashcat command: %s", log_cmd)
            raise HashcatExecutionError(cmd, -1, None, str(exc)) from exc

        if check and completed.returncode != 0:
            LOGGER.error(
                "Hashcat command failed (%s): rc=%s stderr=%s",
                log_cmd,
                completed.returncode,
                (completed.stderr or "").strip() if capture_output else None,
            )
            raise HashcatExecutionError(cmd, completed.returncode, completed.stdout, completed.stderr)

        return completed

    @classmethod
    def _hashlisted_files(
            cls,
            base_dir: str,
            suffix,
            *,
            detailed: bool,
            include_lines: bool = False,
            use_metadata: bool = True,
            line_counter: Optional[Callable[[str], Optional[int]]] = None,
            category: str = "wordlists",
            compute_md5: bool = False,
    ):
        os.makedirs(base_dir, exist_ok=True)
        files = [
            join(base_dir, f)
            for f in listdir(base_dir)
            if isfile(join(base_dir, f)) and f.endswith(suffix)
        ]
        if not detailed:
            return [{"name": os.path.basename(f)} for f in files]

        meta_cache: Dict[str, Dict[str, Optional[int]]] = file_metadata.load_metadata(category) if use_metadata else {}
        valid_files = set()
        meta_changed = False

        entries = []
        for file_path in files:
            fname = os.path.basename(file_path)
            cached_entry = meta_cache.get(fname) if use_metadata else None
            info = {
                "name": fname,
                "md5": cached_entry.get("md5") if cached_entry else None,
                "path": file_path,
            }
            if (info["md5"] is None or info["md5"] == "") and compute_md5:
                try:
                    h = hashlib.md5()
                    with open(file_path, "rb") as fh:
                        for chunk in iter(lambda: fh.read(8192), b""):
                            h.update(chunk)
                    info["md5"] = h.hexdigest()
                except Exception:
                    LOGGER.warning("Failed to compute md5 for %s", file_path, exc_info=True)
            valid_files.add(info["name"])
            if include_lines:
                cached_lines = cached_entry.get("lines") if cached_entry else None
                line_count: Optional[int] = None

                if cached_entry and cached_lines is not None:
                    line_count = cached_lines if isinstance(cached_lines, int) else None
                else:
                    try:
                        if line_counter:
                            line_count = line_counter(file_path)
                        else:
                            line_count = sum(1 for _ in open(file_path, errors="backslashreplace"))
                    except UnicodeDecodeError:
                        LOGGER.warning("Unicode decode error in file %s", file_path)
                    except Exception:
                        LOGGER.exception("Failed to count lines for %s", file_path)

                if line_count is not None:
                    info["lines"] = humanize.intcomma(line_count)
                else:
                    info["lines"] = "unknown"

                if use_metadata and (cached_entry is None or cached_entry.get("md5") != info["md5"] or cached_lines != line_count):
                    meta_cache[info["name"]] = {"md5": info["md5"], "lines": line_count}
                    meta_changed = True
            entries.append(info)

        # Prune metadata entries for files that no longer exist
        if include_lines and use_metadata:
            missing = [k for k in meta_cache.keys() if k not in valid_files]
            if missing:
                for key in missing:
                    del meta_cache[key]
                meta_changed = True
            if meta_changed:
                file_metadata.save_metadata(category, meta_cache)
        return sorted(entries, key=itemgetter('name'))

    @classmethod
    def get_binary(self):
        return _env("WEBHASHCAT_HASHCAT_BINARY", _env("HASHCAT_BINARY", "/usr/bin/hashcat"))

    @classmethod
    def get_potfile(self):
        return _env("WEBHASHCAT_POTFILE", "/webhashcat/Files/potfile")

    @classmethod
    def get_hash_types(self):
        if len(self._hash_types) == 0:
            self.parse_help()

        return self._hash_types

    """
        Parse hashcat version
    """

    @classmethod
    def parse_version(self):

        result = self.run_hashcat([self.get_binary(), '-V'])
        self._version = (result.stdout or "").strip()

    @ClassProperty
    @classmethod
    def version(self):
        if not self._version:
            self.parse_version()

        return self._version

    """
        Parse hashcat help
    """

    @classmethod
    def parse_help(self):

        help_section = None
        help_section_regex = re.compile("^- \[ (?P<section_name>.*) \] -$")
        hash_mode_regex = re.compile("^\s*(?P<id>\d+)\s+\|\s+(?P<name>.+)\s+\|\s+(?P<description>.+)\s*$")

        hashcat_help = self.run_hashcat([self.get_binary(), '--help'])
        for raw_line in (hashcat_help.stdout or "").splitlines():
            line = raw_line.rstrip()

            if len(line) == 0:
                continue

            section_match = help_section_regex.match(line)
            if section_match:
                help_section = section_match.group("section_name")
                continue

            if help_section == "Hash modes":
                hash_mode_match = hash_mode_regex.match(line)
                if hash_mode_match:
                    self._hash_types[int(hash_mode_match.group("id"))] = {
                        "id": int(hash_mode_match.group("id")),
                        "name": "%s (%d)" % (hash_mode_match.group("name"), int(hash_mode_match.group("id"))),
                        "description": hash_mode_match.group("description"),
                    }

    @classmethod
    def compare_potfile(self, hashfile, potfile=None):
        if not potfile:
            potfile = self.get_potfile()

        with transaction.atomic():
            locked = False
            while not locked:
                try:
                    # Lock: lock all the potfiles, this way only one instance of hashcat will be running at a time, the --left option eats a lot of RAM...
                    potfile_locks = list(Lock.objects.select_for_update().filter(lock_ressource="potfile"))
                    # Lock: prevent hashes file from being processed
                    hashfile_lock = \
                        Lock.objects.select_for_update().filter(hashfile_id=hashfile.id, lock_ressource="hashfile")[0]

                    locked = True
                except OperationalError as e:
                    continue

        hashfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile.hashfile)

        # trick to allow multiple instances of hashcat
        session_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12))

        cracked_file = tempfile.NamedTemporaryFile(delete=False)

        hashcat_big_version = int(self.version[1:].split('.')[0])

        # is there a way to combine --show and --remove in hashcat ?

        # Get cracked hashes
        cmd_line = [self.get_binary(), '--show', '-m', str(hashfile.hash_type), hashfile_path, '-o', cracked_file.name,
                    '--session', session_name]
        if hashcat_big_version >= 6:
            cmd_line += ['--outfile-format', '1,2']
        else:
            cmd_line += ['--outfile-format', '3']
        if potfile:
            cmd_line += ['--potfile-path', potfile]
        LOGGER.info("%s: Command: %s", hashfile.name, " ".join(cmd_line))
        self.run_hashcat(
            cmd_line,
            capture_output=False,
            text=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )

        # Remove cracked hashes from list
        f = tempfile.NamedTemporaryFile(delete=False)
        f.close()
        cmd_line = [self.get_binary(), '--left', '-m', str(hashfile.hash_type), hashfile_path, '-o', f.name,
                    '--session', session_name]
        cmd_line += ['--outfile-format', '1']
        if potfile:
            cmd_line += ['--potfile-path', potfile]
        LOGGER.info("%s: Command: %s", hashfile.name, " ".join(cmd_line))
        self.run_hashcat(
            cmd_line,
            capture_output=False,
            text=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )

        copyfile(f.name, hashfile_path)
        os.remove(f.name)

        # hashcat over, remove lock on potfile and hashfile
        del potfile_locks
        del hashfile_lock

        if os.path.exists(cracked_file.name):
            start = time.perf_counter()

            cursor = connection.cursor()
            tmp_table_name = "tmp_table_%s" % ''.join(
                random.choice(string.ascii_lowercase + string.digits) for i in range(10))
            try:
                # create temporary table
                cursor.execute("BEGIN;")
                cursor.execute(
                    "CREATE TEMPORARY TABLE " + tmp_table_name + " (hash_hash varchar(190) PRIMARY KEY, hash LONGTEXT, password varchar(190) NOT NULL, pass_len INTEGER, pass_charset varchar(190), pass_mask varchar(190));")
                cursor.execute("SET unique_checks=0;")

                bulk_insert_list = []
                nb_insert = 0
                for index, line in enumerate(open(cracked_file.name, encoding='utf-8')):
                    line = line.strip()
                    password = line.split(":")[-1]
                    password_hash = ":".join(line.split(":")[0:-1])
                    password_hash_hash = sha1(password_hash.encode()).hexdigest()

                    pass_len, pass_charset, _, pass_mask, _ = analyze_password(password)

                    bulk_insert_list += [password_hash_hash, password_hash, password, pass_len, pass_charset, pass_mask]
                    nb_insert += 1

                    if nb_insert >= 1000:
                        cursor.execute("INSERT INTO " + tmp_table_name + " VALUES " + ", ".join(
                            ["(%s, %s, %s, %s, %s, %s)"] * nb_insert) + ";", bulk_insert_list)
                        bulk_insert_list = []
                        nb_insert = 0

                    # insert into table every 100K rows will prevent MySQL from raising "The number of locks exceeds the lock table size"
                    if index % 100000 == 0:
                        cursor.execute(
                            "UPDATE " + tmp_table_name + " b JOIN Hashcat_hash a ON a.hash_hash = b.hash_hash AND a.hash_type=%s SET a.password = b.password, a.password_len = b.pass_len, a.password_charset = b.pass_charset, a.password_mask = b.pass_mask;",
                            [hashfile.hash_type])
                        cursor.execute("DELETE FROM " + tmp_table_name + ";")
                        cursor.execute("COMMIT;")

                if len(bulk_insert_list) != 0:
                    cursor.execute("INSERT INTO " + tmp_table_name + " VALUES " + ", ".join(
                        ["(%s, %s, %s, %s, %s, %s)"] * nb_insert) + ";", bulk_insert_list)

                cursor.execute(
                    "UPDATE " + tmp_table_name + " b JOIN Hashcat_hash a ON a.hash_hash = b.hash_hash AND a.hash_type=%s SET a.password = b.password, a.password_len = b.pass_len, a.password_charset = b.pass_charset, a.password_mask = b.pass_mask;",
                    [hashfile.hash_type])
                cursor.execute("COMMIT;")
            except Exception:
                LOGGER.exception("Failed to update cracked passwords for %s", hashfile.name)
            finally:
                cursor.execute("SET unique_checks=1;")
                cursor.execute("DROP TABLE %s;" % tmp_table_name)
                cursor.execute("COMMIT;")
                cursor.close()

                hashfile.cracked_count = Hash.objects.filter(hashfile_id=hashfile.id, password__isnull=False).count()
                hashfile.save()

            end = time.perf_counter()
            LOGGER.info("Updated passwords in %.2fs", end - start)

            os.remove(cracked_file.name)

    # executed only when file is uploaded
    @classmethod
    def insert_hashes(self, hashfile):

        with transaction.atomic():
            locked = False
            while not locked:
                try:
                    # Lock: prevent cracked file from being processed
                    hashfile_lock = \
                        Lock.objects.select_for_update().filter(hashfile_id=hashfile.id, lock_ressource="hashfile")[0]

                    locked = True
                except OperationalError as e:
                    continue

        hashfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile.hashfile)
        if os.path.exists(hashfile_path):

            try:
                # 0 - Hashcat can change the hash output (upper/lower chars), lets pass them through hashcat first

                f = tempfile.NamedTemporaryFile(delete=False)
                f.close()
                cmd_line = [self.get_binary(), '--left', '-m', str(hashfile.hash_type), hashfile_path, '-o', f.name]
                cmd_line += ['--outfile-format', '1']
                cmd_line += ['--potfile-path', '/dev/null']
                if hashfile.username_included:
                    cmd_line += ['--username']

                LOGGER.info("%s: Command: %s", hashfile.name, " ".join(map(str, cmd_line)))
                self.run_hashcat(
                    cmd_line,
                    capture_output=False,
                    text=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                )

                # 1 - import hashfile to database

                start = time.perf_counter()

                batch_create_list = []
                hash_count = 0
                for index, line in enumerate(open(f.name, encoding='utf-8')):
                    try:
                        line = line.strip()
                        if hashfile.username_included:
                            username = line.split(":")[0]
                            password_hash = ":".join(line.split(":")[1:])
                        else:
                            username = None
                            password_hash = line
                    except IndexError:
                        continue

                    if len(password_hash) == 0:
                        continue

                    # SHA1 of the hash for joins in MySQL
                    password_hash_hash = sha1(password_hash.encode()).hexdigest()

                    h = Hash(
                        hashfile=hashfile,
                        hash_type=hashfile.hash_type,
                        username=username,
                        hash=password_hash,
                        hash_hash=password_hash_hash,
                        password=None,
                        password_len=None,
                        password_charset=None,
                        password_mask=None,
                    )
                    batch_create_list.append(h)

                    if len(batch_create_list) >= 100000:
                        hashfile.line_count += len(batch_create_list)
                        while len(batch_create_list) != 0:
                            Hash.objects.bulk_create(batch_create_list[:1000])
                            batch_create_list = batch_create_list[1000:]
                        hashfile.save()

                os.remove(f.name)

                hashfile.line_count += len(batch_create_list)
                while len(batch_create_list) != 0:
                    Hash.objects.bulk_create(batch_create_list[:1000])
                    batch_create_list = batch_create_list[1000:]
                hashfile.save()

                end = time.perf_counter()
                LOGGER.info("Inserted hashes in %.2fs", end - start)

                # 2 - if username in hashfile, delete file and create one with only the hashes, 
                #     --username takes a lot of RAM with hashcat, this method is better when processing huge hashfiles

                start = time.perf_counter()

                if hashfile.username_included:
                    os.remove(hashfile_path)

                    tmpfile_name = ''.join([random.choice(string.ascii_lowercase) for i in range(16)])
                    tmpfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "tmp", tmpfile_name)

                    f = open(tmpfile_path, "w")

                    cursor = connection.cursor()
                    # cursor.execute("SELECT DISTINCT hash FROM Hashcat_hash WHERE hashfile_id=%s INTO OUTFILE %s", [hashfile.id, tmpfile_path])
                    cursor.execute("SELECT DISTINCT hash FROM Hashcat_hash WHERE hashfile_id=%s", [hashfile.id])
                    for row in cursor.fetchall():
                        f.write("%s\n" % row[0])
                    cursor.close()

                    f.close()

                    copyfile(tmpfile_path, hashfile_path)
                    os.remove(tmpfile_path)

                end = time.perf_counter()
                LOGGER.info("Wrote hashfile on disk in %.2fs", end - start)

            except Exception:
                LOGGER.exception("Failed to insert hashes for %s", hashfile.name)
        else:
            LOGGER.error("Hashfile %s does not exist on disk", hashfile.hashfile)

        # Crackedfile processing if over, remove lock
        del hashfile_lock

    # executed only when file is uploaded
    @classmethod
    def insert_plaintext(self, hashfile):

        with transaction.atomic():
            locked = False
            while not locked:
                try:
                    # Lock: prevent cracked file from being processed
                    hashfile_lock = \
                        Lock.objects.select_for_update().filter(hashfile_id=hashfile.id, lock_ressource="hashfile")[0]

                    locked = True
                except OperationalError as e:
                    continue

        hashfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile.hashfile)
        if os.path.exists(hashfile_path):
            try:
                batch_create_list = []
                for index, line in enumerate(open(hashfile_path, encoding='utf-8')):
                    if index < hashfile.cracked_count:
                        continue

                    line = line.strip()
                    password = line.split(":")[-1]
                    if hashfile.username_included:
                        username = line.split(":")[0]
                        password_hash = ""
                    else:
                        username = None
                        password_hash = ""

                    pass_len, pass_charset, _, pass_mask, _ = analyze_password(password)

                    h = Hash(
                        hashfile=hashfile,
                        hash_type=hashfile.hash_type,
                        username=username,
                        password=password,
                        hash=password_hash,
                        password_len=pass_len,
                        password_charset=pass_charset,
                        password_mask=pass_mask,
                    )
                    batch_create_list.append(h)

                    if len(batch_create_list) >= 100000:
                        hashfile.line_count += len(batch_create_list)
                        hashfile.cracked_count += len(batch_create_list)
                        while len(batch_create_list) != 0:
                            Hash.objects.bulk_create(batch_create_list[:1000])
                            batch_create_list = batch_create_list[1000:]
                        hashfile.save()

                hashfile.line_count += len(batch_create_list)
                hashfile.cracked_count += len(batch_create_list)
                while len(batch_create_list) != 0:
                    Hash.objects.bulk_create(batch_create_list[:1000])
                    batch_create_list = batch_create_list[1000:]
                hashfile.save()

            except Exception as e:
                traceback.print_exc()

            # Crackedfile processing if over, remove lock
            del hashfile_lock

    @classmethod
    def get_rules(self, detailed=True):

        base_dir = os.path.join(os.path.dirname(__file__), "..", "Files", "Rulefiles")
        def _rule_lines(path: str) -> Optional[int]:
            try:
                with open(path, errors="backslashreplace") as fh:
                    return sum(1 for line in fh if line.strip() and not line.lstrip().startswith("#"))
            except Exception:
                LOGGER.warning("Failed to count rule lines for %s", path, exc_info=True)
                return None

        return self._hashlisted_files(
            base_dir,
            ".rule",
            detailed=detailed,
            include_lines=detailed,
            use_metadata=True,
            line_counter=_rule_lines,
            category="rules",
            compute_md5=True,
        )

    @classmethod
    def get_masks(self, detailed=True):

        base_dir = os.path.join(os.path.dirname(__file__), "..", "Files", "Maskfiles")
        return self._hashlisted_files(
            base_dir,
            ".hcmask",
            detailed=detailed,
            include_lines=detailed,
            use_metadata=True,
            category="masks",
            compute_md5=True,
        )

    @classmethod
    def get_wordlists(self, detailed=True):

        base_dir = os.path.join(os.path.dirname(__file__), "..", "Files", "Wordlistfiles")
        suffixes = (
            ".wordlist",
            ".wordlist.gz",
            ".wordlist.zip",
            ".txt",
            ".list",
            ".txt.gz",
            ".list.gz",
            ".txt.zip",
            ".list.zip",
        )
        return self._hashlisted_files(
            base_dir,
            suffixes,
            detailed=detailed,
            include_lines=True,
            use_metadata=True,
            category="wordlists",
            compute_md5=True,
            line_counter=self._count_wordlist_lines,
        )

    @classmethod
    def _count_wordlist_lines(cls, path: str) -> Optional[int]:
        try:
            if path.endswith(".gz"):
                import gzip
                with gzip.open(path, "rt", errors="backslashreplace") as fh:
                    return sum(1 for _ in fh)
            if path.endswith(".zip"):
                import zipfile
                with zipfile.ZipFile(path) as zf:
                    for member in zf.infolist():
                        if member.is_dir():
                            continue
                        with zf.open(member) as fh:
                            return sum(1 for _ in io.TextIOWrapper(fh, errors="backslashreplace"))
                    return None
            if path.endswith(".7z"):
                return None  # without py7zr we cannot stream safely
            return sum(1 for _ in open(path, errors="backslashreplace"))
        except Exception:
            LOGGER.warning("Failed to count wordlist lines for %s", path, exc_info=True)
            return None

    @classmethod
    def upload_rule(self, name, file):
        if not name.endswith(".rule"):
            name = "%s.rule" % name
        name = name.replace(" ", "_")

        path = os.path.join(os.path.dirname(__file__), "..", "Files", "Rulefiles", name)

        with open(path, "wb") as f:
            f.write(file)

        try:
            md5_hash = hashlib.md5(file).hexdigest()
            with open(path, errors="backslashreplace") as fh:
                line_count = sum(1 for line in fh if line.strip() and not line.lstrip().startswith("#"))
        except Exception:
            md5_hash = None
            line_count = None
        file_metadata.update_entry("rules", name, md5_hash, line_count)

    @classmethod
    def upload_mask(self, name, file):
        if not name.endswith(".hcmask"):
            name = "%s.hcmask" % name
        name = name.replace(" ", "_")

        path = os.path.join(os.path.dirname(__file__), "..", "Files", "Maskfiles", name)

        with open(path, "wb") as f:
            f.write(file)
        try:
            md5_hash = hashlib.md5(file).hexdigest()
            with open(path, errors="backslashreplace") as fh:
                line_count = sum(1 for _ in fh)
        except Exception:
            md5_hash = None
            line_count = None
        file_metadata.update_entry("masks", name, md5_hash, line_count)

    @classmethod
    def upload_wordlist(self, name, file):
        name = name.replace(" ", "_")
        base = name
        ext = ""
        if name.endswith(".gz"):
            base = name[:-3]
            ext = ".gz"
        elif name.endswith(".zip"):
            base = name[:-4]
            ext = ".zip"
        else:
            # drop generic extension (e.g., .txt, .lst) before appending .wordlist
            base = os.path.splitext(name)[0]

        if not base.endswith(".wordlist"):
            base = f"{base}.wordlist"

        name = base + ext

        path = os.path.join(os.path.dirname(__file__), "..", "Files", "Wordlistfiles", name)

        # Compute md5 and line count before writing to disk
        md5_hash = hashlib.md5(file).hexdigest()
        line_count: Optional[int] = None

        try:
            if ext == ".gz":
                import gzip
                with gzip.open(io.BytesIO(file), "rt", errors="backslashreplace") as fh:
                    line_count = sum(1 for _ in fh)
            elif ext == ".zip":
                import zipfile
                with zipfile.ZipFile(io.BytesIO(file)) as zf:
                    for member in zf.infolist():
                        if member.is_dir():
                            continue
                        with zf.open(member) as fh:
                            line_count = sum(1 for _ in io.TextIOWrapper(fh, errors="backslashreplace"))
                        break
            elif ext == ".7z":
                # Unsupported for in-memory line counting; keep None
                line_count = None
            else:
                line_count = file.count(b"\n")
        except Exception:
            LOGGER.warning("Unable to precompute line count for %s", name, exc_info=True)

        with open(path, "wb") as f:
            f.write(file)

        file_metadata.update_entry("wordlists", name, md5_hash, line_count)

    @classmethod
    def remove_rule(self, name):
        name = name.split("/")[-1]
        path = os.path.join(os.path.dirname(__file__), "..", "Files", "Rulefiles", name)

        try:
            os.remove(path)
        except Exception as e:
            pass
        file_metadata.remove_entry("rules", name)

    @classmethod
    def remove_mask(self, name):
        name = name.split("/")[-1]
        path = os.path.join(os.path.dirname(__file__), "..", "Files", "Maskfiles", name)

        try:
            os.remove(path)
        except Exception as e:
            pass
        file_metadata.remove_entry("masks", name)

    @classmethod
    def remove_wordlist(self, name):
        name = name.split("/")[-1]
        path = os.path.join(os.path.dirname(__file__), "..", "Files", "Wordlistfiles", name)

        try:
            os.remove(path)
        except Exception as e:
            pass
        file_metadata.remove_entry("wordlists", name)

    @classmethod
    def ensure_hashfile_exists(self, hashfile) -> str:
        """
        Guarantee that the hashfile exists on disk; if missing, rebuild it from DB entries.
        """
        hashfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile.hashfile)
        if os.path.exists(hashfile_path):
            return hashfile_path

        hashes = list(Hash.objects.filter(hashfile=hashfile))
        if not hashes:
            raise FileNotFoundError(f"No backing file or rows found for hashfile {hashfile.id}")

        os.makedirs(os.path.dirname(hashfile_path), exist_ok=True)
        with open(hashfile_path, "w", encoding="utf-8", errors="backslashreplace") as fh:
            for entry in hashes:
                if hashfile.username_included and entry.username:
                    fh.write(f"{entry.username}:{entry.hash}\n")
                else:
                    fh.write(f"{entry.hash}\n")
        return hashfile_path

    @classmethod
    def update_hashfiles(self):

        pot_manager = PotfileManager(self.get_potfile())
        pot_manager.backup()

        updated_hashfile_ids = self.update_potfile()
        LOGGER.debug("Updated hashfile ids: %s", updated_hashfile_ids)

        pot_manager.restore_if_corrupt()

        for hashfile_id in updated_hashfile_ids:
            hashfile = Hashfile.objects.get(id=hashfile_id)
            try:
                self.compare_potfile(hashfile)
            except OperationalError:
                # Probably already being updated, no need to process it again
                pass

    @classmethod
    def update_potfile(self):

        updated_hashfile_ids = []

        with transaction.atomic():
            try:
                # Lock: prevent the potfile from being modified
                list(Lock.objects.select_for_update().filter(lock_ressource="potfile"))

                # update the potfile
                for session in Session.objects.all():
                    try:
                        node = session.node

                        hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)

                        remaining = True
                        while (remaining):
                            potfile_data = hashcat_api.get_potfile(session.name, session.potfile_line_retrieved)
                            if potfile_data != None and potfile_data["response"] == "ok" and potfile_data[
                                "line_count"] > 0:
                                f = open(self.get_potfile(), "a", encoding='utf-8')
                                f.write(potfile_data["potfile_data"])
                                f.close()

                                session.potfile_line_retrieved += potfile_data["line_count"]
                                session.save()

                                remaining = potfile_data["remaining_data"]

                                updated_hashfile_ids.append(session.hashfile.id)
                            else:
                                remaining = False

                    except HashcatAPIError as exc:
                        LOGGER.warning("Unable to update potfile for session %s: %s", session.name, exc)
                    except ConnectionRefusedError:
                        LOGGER.warning("Connection refused when updating potfile for session %s", session.name)
            except OperationalError as e:
                # potfile is locked, no need to be concerned about it, this function is executed regularly
                LOGGER.error("Potfile locked while updating cracked counts")

        return list(set(updated_hashfile_ids))

    @classmethod
    def optimize_potfile(self):

        PotfileManager(Hashcat.get_potfile()).optimize()

    @classmethod
    def backup_potfile(self):
        PotfileManager(self.get_potfile()).backup()

    @classmethod
    def remove_hashfile(self, hashfile):
        # Check if there is a running session
        for session in Session.objects.filter(hashfile_id=hashfile.id):
            node = session.node

            try:
                hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
                hashcat_api.action(session.name, "remove")
            except Exception as e:
                traceback.print_exc()

        hashfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile.hashfile)

        # remove from disk
        try:
            os.remove(hashfile_path)
        except Exception as e:
            pass

        del_hashfile_locks(hashfile)

        start = time.perf_counter()
        # deletion is faster using raw SQL queries
        cursor = connection.cursor()
        cursor.execute("DELETE FROM Hashcat_session WHERE hashfile_id = %s", [hashfile.id])
        cursor.execute("DELETE FROM Hashcat_hash WHERE hashfile_id = %s", [hashfile.id])
        cursor.close()
        hashfile.delete()
        end = time.perf_counter()
        LOGGER.info("Hashfile %s deleted from database in %.2fs", hashfile.name, end - start)


# This function is taken from https://github.com/iphelix/pack

def analyze_password(password):
    # Password length
    if password.startswith("$HEX["):
        pass_length = (len(password) - 6) / 2
        return (pass_length, "unknown", None, None, None)
    else:
        pass_length = len(password)

    # Character-set and policy counters
    digit = 0
    lower = 0
    upper = 0
    special = 0

    simplemask = list()
    advancedmask_string = ""

    # Detect simple and advanced masks
    for letter in password:

        if letter in string.digits:
            digit += 1
            advancedmask_string += "?d"
            if not simplemask or not simplemask[-1] == 'digit': simplemask.append('digit')

        elif letter in string.ascii_lowercase:
            lower += 1
            advancedmask_string += "?l"
            if not simplemask or not simplemask[-1] == 'string': simplemask.append('string')


        elif letter in string.ascii_uppercase:
            upper += 1
            advancedmask_string += "?u"
            if not simplemask or not simplemask[-1] == 'string': simplemask.append('string')

        else:
            special += 1
            advancedmask_string += "?s"
            if not simplemask or not simplemask[-1] == 'special': simplemask.append('special')

    # String representation of masks
    simplemask_string = ''.join(simplemask) if len(simplemask) <= 3 else 'othermask'

    # Policy
    policy = (digit, lower, upper, special)

    # Determine character-set
    if digit and not lower and not upper and not special:
        charset = 'numeric'
    elif not digit and lower and not upper and not special:
        charset = 'loweralpha'
    elif not digit and not lower and upper and not special:
        charset = 'upperalpha'
    elif not digit and not lower and not upper and special:
        charset = 'special'

    elif not digit and lower and upper and not special:
        charset = 'mixedalpha'
    elif digit and lower and not upper and not special:
        charset = 'loweralphanum'
    elif digit and not lower and upper and not special:
        charset = 'upperalphanum'
    elif not digit and lower and not upper and special:
        charset = 'loweralphaspecial'
    elif not digit and not lower and upper and special:
        charset = 'upperalphaspecial'
    elif digit and not lower and not upper and special:
        charset = 'specialnum'

    elif not digit and lower and upper and special:
        charset = 'mixedalphaspecial'
    elif digit and not lower and upper and special:
        charset = 'upperalphaspecialnum'
    elif digit and lower and not upper and special:
        charset = 'loweralphaspecialnum'
    elif digit and lower and upper and not special:
        charset = 'mixedalphanum'
    else:
        charset = 'all'

    return (pass_length, charset, simplemask_string, advancedmask_string, policy)
