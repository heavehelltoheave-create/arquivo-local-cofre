import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import json
import securebox_core as core

from securebox_core import (
    VaultError, atomic_write, decrypt_secret, disguise_as_zip,
    encrypt_secret, generate_password, read_encrypted_file,
)

MASTER = "uma senha mestra longa e unica 2026"


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = "MinhaSenha!abc_123€🔒"
        cls.encrypted = encrypt_secret(cls.password, MASTER, "Conta teste")

    def test_round_trip(self):
        value, label = decrypt_secret(self.encrypted, MASTER)
        self.assertEqual(value, self.password)
        self.assertEqual(label, "Conta teste")

    def test_wrong_password(self):
        with self.assertRaises(VaultError):
            decrypt_secret(self.encrypted, "incorreta_com_mais_de_16_chars")

    def test_tamper_ciphertext(self):
        import json
        data = json.loads(self.encrypted.split(b"\n", 1)[1])
        c = data["ciphertext"]
        data["ciphertext"] = ("A" if c[0] != "A" else "B") + c[1:]
        tampered = b"LVLT1\n" + json.dumps(data).encode("utf-8")
        with self.assertRaises(VaultError):
            decrypt_secret(tampered, MASTER)

    def test_header_tamper(self):
        data = self.encrypted.replace(b"LVLT1", b"LVLT9", 1)
        with self.assertRaises(VaultError):
            decrypt_secret(data, MASTER)

    def test_randomization(self):
        other = encrypt_secret(self.password, MASTER)
        self.assertNotEqual(other, self.encrypted)

    def test_zip_round_trip(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "data.txt"
            z = Path(temp) / "files.zip"
            atomic_write(p, self.encrypted)
            disguise_as_zip(read_encrypted_file(p), z)
            self.assertEqual(read_encrypted_file(z), self.encrypted)
            self.assertEqual(decrypt_secret(read_encrypted_file(z), MASTER)[0], self.password)

    def test_generate_random_password(self):
        self.assertEqual(len(generate_password(32)), 32)
        with self.assertRaises(VaultError):
            generate_password(3)

    def test_old_files_still_decrypt(self):
        with patch.object(core, "KDF", core.LEGACY_KDF):
            old = encrypt_secret(self.password, MASTER, "Backup antigo")
        self.assertEqual(decrypt_secret(old, MASTER), (self.password, "Backup antigo"))
        self.assertEqual(json.loads(old[len(core.MAGIC):])["kdf"]["memory_kib"], 131072)

    def test_new_files_use_stronger_kdf(self):
        self.assertEqual(json.loads(self.encrypted[len(core.MAGIC):])["kdf"]["memory_kib"], 262144)

    def test_reject_untrusted_expensive_kdf(self):
        envelope = json.loads(self.encrypted[len(core.MAGIC):])
        envelope["kdf"]["memory_kib"] = 10**9
        tampered = core.MAGIC + json.dumps(envelope).encode("utf-8")
        with self.assertRaises(VaultError):
            decrypt_secret(tampered, MASTER)

    def test_reject_obvious_new_master(self):
        with self.assertRaises(VaultError):
            encrypt_secret("sample", "1234567890123456")
        with self.assertRaises(VaultError):
            encrypt_secret("sample", "abababababababab")

    def test_invalid_archive_does_not_extract_files(self):
        import zipfile
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "not_our_backup.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("../danger.txt", self.encrypted)
            with self.assertRaises(VaultError):
                read_encrypted_file(path)
            self.assertFalse((Path(folder) / "danger.txt").exists())

    def test_encrypted_file_no_plaintext(self):
        self.assertNotIn(self.password.encode("utf-8"), self.encrypted)
        self.assertNotIn(MASTER.encode("utf-8"), self.encrypted)


if __name__ == "__main__":
    unittest.main()
