"""Windows per-user DPAPI vault. Windows-only; never stores plaintext."""
from __future__ import annotations

import os
import re
import secrets
from datetime import datetime
from pathlib import Path

from securebox_core import VaultError, atomic_write, read_encrypted_file, _validated_data

FILENAME = re.compile(r"^[a-f0-9]{32}\.dat$")


class WindowsVault:
    def __init__(self):
        if os.name != "nt":
            raise VaultError("O cofre DPAPI exige Windows.")
        import win32crypt  # installed on Windows by requirements.txt
        self.win32crypt = win32crypt
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            raise VaultError("Pasta LOCALAPPDATA não encontrada.")
        self.root = Path(base) / "LocalVault" / "records"
        self.root.mkdir(parents=True, exist_ok=True)

    def store(self, encrypted: bytes) -> str:
        _validated_data(encrypted)
        protected = self.win32crypt.CryptProtectData(encrypted, "Local private record", None, None, None, 0)
        filename = f"{secrets.token_hex(16)}.dat"
        atomic_write(self.root / filename, protected)
        return filename[:-4]

    def list_entries(self) -> list[tuple[str, str]]:
        entries = []
        for path in self.root.glob("*.dat"):
            if FILENAME.fullmatch(path.name):
                modified = path.stat().st_mtime
                when = datetime.fromtimestamp(modified).strftime("%d/%m/%Y %H:%M")
                entries.append((path.stem, when, modified))
        return [(identifier, when) for identifier, when, _ in sorted(entries, key=lambda x: x[2], reverse=True)]

    def delete(self, identifier: str) -> None:
        """Remove the vault entry, but do not promise forensic secure erasure."""
        if not re.fullmatch(r"[a-f0-9]{32}", identifier):
            raise VaultError("Identificador do cofre inválido.")
        (self.root / (identifier + ".dat")).unlink()

    def load(self, identifier: str) -> bytes:
        if not re.fullmatch(r"[a-f0-9]{32}", identifier):
            raise VaultError("Identificador do cofre inválido.")
        path = self.root / (identifier + ".dat")
        if path.stat().st_size > 2_000_000:
            raise VaultError("Registro do cofre com tamanho inválido.")
        data = path.read_bytes()
        try:
            _description, encrypted = self.win32crypt.CryptUnprotectData(data, None, None, None, 0)
        except Exception as exc:
            raise VaultError("Não foi possível abrir o registro com a conta atual do Windows.") from exc
        return _validated_data(encrypted)
