from __future__ import annotations

import secrets
from abc import ABC, abstractmethod
from typing import Final

from cloud_data_sanitizer.models import SanitizerError

SERVICE_NAME: Final = "motoc-cloud-data-sanitizer"
KEY_USERNAME: Final = "customer-hmac-key"
KEY_BYTES: Final = 32


class KeyStore(ABC):
    """Opaque local key storage. Never logs or returns key material to UI/logs."""

    @abstractmethod
    def generate(self) -> bytes:
        """Create a new 256-bit key and persist it according to the backend."""

    @abstractmethod
    def load(self) -> bytes | None:
        """Load the persisted key, or None if absent."""

    @abstractmethod
    def save(self, key: bytes) -> None:
        """Persist an existing key."""

    @abstractmethod
    def delete(self) -> None:
        """Delete any persisted key."""

    def load_or_generate(self, *, persist: bool = True) -> bytes:
        existing = self.load()
        if existing is not None:
            return existing
        key = secrets.token_bytes(KEY_BYTES)
        if persist:
            self.save(key)
        return key


class MemoryKeyStore(KeyStore):
    """Session-only key store. Future runs will not correlate."""

    def __init__(self) -> None:
        self._key: bytes | None = None

    def generate(self) -> bytes:
        self._key = secrets.token_bytes(KEY_BYTES)
        return self._key

    def load(self) -> bytes | None:
        return self._key

    def save(self, key: bytes) -> None:
        _validate_key(key)
        self._key = key

    def delete(self) -> None:
        self._key = None


class OSKeyStore(KeyStore):
    """macOS Keychain / Windows Credential Manager via keyring."""

    def generate(self) -> bytes:
        key = secrets.token_bytes(KEY_BYTES)
        self.save(key)
        return key

    def load(self) -> bytes | None:
        try:
            import keyring
        except ImportError as exc:
            raise SanitizerError(
                "keystore_unavailable",
                "OS key store backend is not available.",
            ) from exc
        raw = keyring.get_password(SERVICE_NAME, KEY_USERNAME)
        if raw is None:
            return None
        try:
            key = bytes.fromhex(raw)
        except ValueError as exc:
            raise SanitizerError(
                "keystore_corrupt",
                "Stored key material is unreadable.",
            ) from exc
        _validate_key(key)
        return key

    def save(self, key: bytes) -> None:
        _validate_key(key)
        try:
            import keyring
        except ImportError as exc:
            raise SanitizerError(
                "keystore_unavailable",
                "OS key store backend is not available.",
            ) from exc
        keyring.set_password(SERVICE_NAME, KEY_USERNAME, key.hex())

    def delete(self) -> None:
        try:
            import keyring
            from keyring.errors import PasswordDeleteError
        except ImportError as exc:
            raise SanitizerError(
                "keystore_unavailable",
                "OS key store backend is not available.",
            ) from exc
        try:
            keyring.delete_password(SERVICE_NAME, KEY_USERNAME)
        except PasswordDeleteError:
            return


def _validate_key(key: bytes) -> None:
    if len(key) < KEY_BYTES:
        raise SanitizerError(
            "key_too_short",
            "Customer key must provide at least 256 bits of entropy.",
        )


def create_default_keystore(*, persist: bool = True) -> KeyStore:
    if persist:
        return OSKeyStore()
    return MemoryKeyStore()
