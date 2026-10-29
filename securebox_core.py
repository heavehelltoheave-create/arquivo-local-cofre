"""Independent cryptographic engine for the LocalVault Windows application.

All secret material is encrypted by an authenticated cipher. No custom cipher.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import string
import zipfile
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"LVLT1\n"
FORMAT = "LVLT1"
ZIP_ENTRY = "data/001.bin"
LEGACY_KDF = {"algorithm": "argon2id", "memory_kib": 131072, "iterations": 3, "parallelism": 2}
# New exports use more memory; old files remain supported via a strict allowlist.
KDF = {"algorithm": "argon2id", "memory_kib": 262144, "iterations": 3, "parallelism": 2}
ALLOWED_KDF = (LEGACY_KDF, KDF)
MAX_ENCRYPTED = 1_000_000
MAX_ARCHIVE = 2_000_000
MAX_PASSWORD_LENGTH = 4096
FILLER = string.ascii_letters + string.digits + "!@#$%&*_-+=?"


class VaultError(Exception):
    """User-facing storage/crypto error. Do not include plaintext in messages."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _from_b64(value: str, expected_length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise VaultError("Arquivo criptografado inválido.")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise VaultError("Arquivo criptografado inválido.") from exc
    if expected_length is not None and len(raw) != expected_length:
        raise VaultError("Parâmetros de criptografia inválidos.")
    return raw


def _canonical(data: dict) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _derive(master: str, salt: bytes, kdf: dict | None = None) -> bytes:
    # Never accept untrusted memory/time values directly from the file.
    profile = KDF if kdf is None else kdf
    if profile not in ALLOWED_KDF:
        raise VaultError("Parâmetros Argon2id não suportados.")
    try:
        return hash_secret_raw(
            secret=master.encode("utf-8"), salt=salt,
            time_cost=profile["iterations"], memory_cost=profile["memory_kib"],
            parallelism=profile["parallelism"], hash_len=32, type=Type.ID,
        )
    except (MemoryError, RuntimeError) as exc:
        raise VaultError("Memória insuficiente para executar a derivação Argon2id.") from exc


def _check_master(master: str) -> None:
    if not isinstance(master, str) or len(master) < 16 or len(master) > 1024:
        raise VaultError("A senha mestra deve conter de 16 a 1.024 caracteres.")


def check_new_master_strength(master: str) -> None:
    """Conservative filter for easily guessed patterns; not an entropy estimate.

    Existing master passwords are deliberately NOT strength-checked when reading
    old records; they must remain decryptable.
    """
    _check_master(master)
    normalized = master.casefold().strip()
    compact = "".join(ch for ch in normalized if not ch.isspace())
    if not compact or len(set(compact)) <= 3:
        raise VaultError("Senha mestra muito repetitiva. Escolha uma frase longa e única.")
    if compact.isdigit() or compact.isalpha() and len(compact.split()) == 1 and len(set(compact)) < 7:
        raise VaultError("Senha mestra previsível. Use palavras aleatórias ou caracteres gerados.")
    if any(sequence in compact for sequence in ("123456", "654321", "012345", "qwerty", "asdfgh", "password123", "senha123", "admin123")):
        raise VaultError("Senha mestra contém sequência comum. Escolha outra mais imprevisível.")
    if any(ch * 7 in compact for ch in set(compact)):
        raise VaultError("Senha mestra contém repetição excessiva de caracteres.")


def generate_password(length: int = 32) -> str:
    if not isinstance(length, int) or not 16 <= length <= 128:
        raise VaultError("Escolha um tamanho entre 16 e 128 caracteres.")
    groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%&*-_+=?"]
    result = [secrets.choice(group) for group in groups]
    universe = "".join(groups)
    result.extend(secrets.choice(universe) for _ in range(length - len(result)))
    secrets.SystemRandom().shuffle(result)
    return "".join(result)


def _mix(secret: str) -> dict:
    # This is a reversible transformation INSIDE AES-GCM, not a new cipher.
    tokens: list[tuple[str, int | None]] = [(ch, i) for i, ch in enumerate(secret)]
    # Insert additional securely chosen characters (at least 16 filler chars).
    filler_count = min(8192, max(16, 2 * len(secret)))
    tokens.extend((secrets.choice(FILLER), None) for _ in range(filler_count))
    secrets.SystemRandom().shuffle(tokens)
    positions = [None] * len(secret)
    for j, (_, original_idx) in enumerate(tokens):
        if original_idx is not None:
            positions[original_idx] = j
    return {"mixed": "".join(ch for ch, _ in tokens), "positions": positions}


def _unmix(content: dict) -> tuple[str, str]:
    if not isinstance(content, dict) or set(content) != {"version", "label", "mixed", "positions"}:
        raise VaultError("Conteúdo autenticado inesperado.")
    mixed = content["mixed"]
    positions = content["positions"]
    if (content["version"] != 1 or not isinstance(content["label"], str)
            or not isinstance(mixed, str) or not isinstance(positions, list)
            or len(positions) > MAX_PASSWORD_LENGTH or len(mixed) > 3 * MAX_PASSWORD_LENGTH + 16
            or any(type(i) is not int or i < 0 or i >= len(mixed) for i in positions)
            or len(set(positions)) != len(positions)):
        raise VaultError("Conteúdo autenticado inválido.")
    return "".join(mixed[index] for index in positions), content["label"]


def encrypt_secret(secret: str, master: str, label: str = "") -> bytes:
    if not isinstance(secret, str) or not 1 <= len(secret) <= MAX_PASSWORD_LENGTH:
        raise VaultError("Informe uma senha de 1 a 4.096 caracteres.")
    if not isinstance(label, str) or len(label) > 120:
        raise VaultError("O identificador deve ter no máximo 120 caracteres.")
    check_new_master_strength(master)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    header = {"format": FORMAT, "kdf": KDF, "salt": _b64(salt), "nonce": _b64(nonce)}
    inner = {"version": 1, "label": label, **_mix(secret)}
    key = _derive(master, salt)
    ciphertext = AESGCM(key).encrypt(nonce, _canonical(inner), _canonical(header))
    data = MAGIC + _canonical({**header, "ciphertext": _b64(ciphertext)}) + b"\n"
    if len(data) > MAX_ENCRYPTED:
        raise VaultError("O conteúdo criptografado excede o tamanho máximo.")
    return data


def decrypt_secret(data: bytes, master: str) -> tuple[str, str]:
    _check_master(master)
    if not isinstance(data, bytes) or len(data) > MAX_ENCRYPTED or not data.startswith(MAGIC):
        raise VaultError("Formato inválido: escolha um arquivo criado pelo aplicativo.")
    try:
        env = json.loads(data[len(MAGIC):])
        if not isinstance(env, dict) or set(env) != {"format", "kdf", "salt", "nonce", "ciphertext"}:
            raise ValueError("schema")
        if env["format"] != FORMAT or env["kdf"] not in ALLOWED_KDF:
            raise ValueError("version or kdf")
        salt = _from_b64(env["salt"], 16)
        nonce = _from_b64(env["nonce"], 12)
        ct = _from_b64(env["ciphertext"])
        if len(ct) < 16 or len(ct) > MAX_ENCRYPTED:
            raise ValueError("ciphertext length")
        header = {key: env[key] for key in ("format", "kdf", "salt", "nonce")}
        key = _derive(master, salt, env["kdf"])
        try:
            plain = AESGCM(key).decrypt(nonce, ct, _canonical(header))
        except InvalidTag as exc:
            raise VaultError("Senha mestra incorreta ou arquivo alterado/corrompido.") from exc
        payload = json.loads(plain)
        return _unmix(payload)
    except VaultError:
        raise
    except (TypeError, KeyError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise VaultError("Arquivo criptografado inválido ou incompatível.") from exc


def _validated_data(data: bytes) -> bytes:
    if not data.startswith(MAGIC) or len(data) > MAX_ENCRYPTED:
        raise VaultError("O arquivo não contém dados criptografados válidos deste aplicativo.")
    return data


def read_encrypted_file(path: str | Path) -> bytes:
    p = Path(path)
    if p.stat().st_size > MAX_ARCHIVE:
        raise VaultError("O arquivo é grande demais para este cofre.")
    if zipfile.is_zipfile(p):
        try:
            with zipfile.ZipFile(p, "r") as archive:
                members = archive.infolist()
                if len(members) != 1 or members[0].filename != ZIP_ENTRY:
                    raise VaultError("Este ZIP não foi criado pelo aplicativo.")
                info = members[0]
                if info.file_size > MAX_ENCRYPTED or info.file_size < len(MAGIC):
                    raise VaultError("Tamanho interno do ZIP inválido.")
                with archive.open(info, "r") as reader:
                    data = reader.read(MAX_ENCRYPTED + 1)
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            raise VaultError("Falha na leitura do ZIP.") from exc
        return _validated_data(data)
    return _validated_data(p.read_bytes())


def atomic_write(path: str | Path, data: bytes) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{secrets.token_hex(12)}.tmp")
    try:
        with tmp.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, p)
    finally:
        tmp.unlink(missing_ok=True)


def disguise_as_zip(encrypted: bytes, out_path: str | Path) -> None:
    _validated_data(encrypted)
    out = Path(out_path)
    tmp = out.with_name(f".{secrets.token_hex(12)}.tmp")
    try:
        with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            archive.writestr(ZIP_ENTRY, encrypted)
        os.replace(tmp, out)
    finally:
        tmp.unlink(missing_ok=True)
