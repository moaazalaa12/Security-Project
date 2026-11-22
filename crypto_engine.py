"""
crypto_engine.py
================
Pure AES cryptographic engine for image encryption & decryption.
Supports ECB, CBC, and CTR modes with selectable key sizes (128, 192, 256 bits).
No UI or PIL dependencies.
"""

from typing import Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

SUPPORTED_MODES = ("ECB", "CBC", "CTR")
SUPPORTED_KEY_SIZES = (16, 24, 32)  # In bytes: 128-bit, 192-bit, 256-bit
BLOCK_SIZE = AES.block_size         # 16 bytes
IV_SIZE_CBC = 16                    # 16 bytes for CBC
NONCE_SIZE_CTR = 8                  # 8 bytes for CTR


def generate_key(key_size_bytes: int = 32) -> bytes:
    """
    Generate a cryptographically secure random AES key.
    
    :param key_size_bytes: Key size in bytes (16 for 128-bit, 24 for 192-bit, 32 for 256-bit).
    :return: Random key bytes.
    :raises ValueError: If key_size_bytes is not 16, 24, or 32.
    """
    if key_size_bytes not in SUPPORTED_KEY_SIZES:
        raise ValueError(
            f"Invalid key size: {key_size_bytes} bytes. Supported sizes are 16 (128-bit), 24 (192-bit), or 32 (256-bit)."
        )
    return get_random_bytes(key_size_bytes)


def generate_iv_or_nonce(mode: str) -> bytes:
    """
    Generate a cryptographically secure random IV or Nonce based on mode.
    
    :param mode: AES mode ('ECB', 'CBC', or 'CTR').
    :return: 16 bytes for CBC, 8 bytes for CTR, or empty bytes for ECB.
    """
    normalized_mode = mode.upper().strip()
    if normalized_mode == "CBC":
        return get_random_bytes(IV_SIZE_CBC)
    elif normalized_mode == "CTR":
        return get_random_bytes(NONCE_SIZE_CTR)
    elif normalized_mode == "ECB":
        return b""
    else:
        raise ValueError(f"Unsupported AES mode: {mode}. Must be one of {SUPPORTED_MODES}.")


def validate_key_hex(key_hex: str) -> bytes:
    """
    Strictly validate and decode a hexadecimal AES key string.
    
    :param key_hex: Hexadecimal string representing the key.
    :return: Key bytes.
    :raises ValueError: If hex is malformed or not 16, 24, or 32 bytes long.
    """
    cleaned = key_hex.strip().replace(" ", "").replace("-", "").replace("0x", "")
    if not cleaned:
        raise ValueError("Key cannot be empty.")
    try:
        key_bytes = bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(f"Invalid hexadecimal key string: {e}") from e

    if len(key_bytes) not in SUPPORTED_KEY_SIZES:
        raise ValueError(
            f"Invalid key length: {len(key_bytes)} bytes ({len(key_bytes) * 8} bits). "
            f"Must be 16 bytes (128-bit / 32 hex chars), 24 bytes (192-bit / 48 hex chars), "
            f"or 32 bytes (256-bit / 64 hex chars)."
        )
    return key_bytes


def validate_iv_or_nonce_hex(mode: str, iv_or_nonce_hex: str) -> bytes:
    """
    Validate and decode a hexadecimal IV or Nonce string.
    
    :param mode: AES mode ('ECB', 'CBC', 'CTR').
    :param iv_or_nonce_hex: Hexadecimal string.
    :return: Decoded bytes (empty for ECB, 16 bytes for CBC, 8 bytes for CTR).
    :raises ValueError: If hex is invalid or has wrong length for the mode.
    """
    normalized_mode = mode.upper().strip()
    cleaned = iv_or_nonce_hex.strip().replace(" ", "").replace("-", "").replace("0x", "")

    if normalized_mode == "ECB":
        return b""

    if not cleaned:
        raise ValueError(f"{normalized_mode} mode requires an IV/Nonce.")

    try:
        iv_bytes = bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(f"Invalid hexadecimal IV/Nonce string: {e}") from e

    if normalized_mode == "CBC":
        if len(iv_bytes) != IV_SIZE_CBC:
            raise ValueError(
                f"CBC mode requires a 16-byte (32 hex characters) IV. Got {len(iv_bytes)} bytes ({len(cleaned)} hex chars)."
            )
        return iv_bytes
    elif normalized_mode == "CTR":
        if len(iv_bytes) != NONCE_SIZE_CTR:
            raise ValueError(
                f"CTR mode requires an 8-byte (16 hex characters) Nonce. Got {len(iv_bytes)} bytes ({len(cleaned)} hex chars)."
            )
        return iv_bytes
    else:
        raise ValueError(f"Unsupported AES mode: {mode}")


def encrypt_bytes(
    plaintext: bytes,
    key: bytes,
    mode: str,
    iv_or_nonce: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext bytes using AES in the specified mode.
    
    :param plaintext: Raw input bytes.
    :param key: AES key bytes (16, 24, or 32 bytes).
    :param mode: AES mode ('ECB', 'CBC', 'CTR').
    :param iv_or_nonce: Optional explicit IV/Nonce. If not provided, a random one is generated.
    :return: Tuple of (ciphertext, actual_iv_or_nonce_bytes).
    :raises ValueError: On invalid parameters or encryption failure.
    """
    if len(key) not in SUPPORTED_KEY_SIZES:
        raise ValueError(f"Invalid key size ({len(key)} bytes). Must be 16, 24, or 32 bytes.")

    normalized_mode = mode.upper().strip()
    if normalized_mode not in SUPPORTED_MODES:
        raise ValueError(f"Unsupported AES mode: '{mode}'. Must be one of {SUPPORTED_MODES}.")

    try:
        if normalized_mode == "ECB":
            # ECB mode uses PKCS7 padding
            padded_data = pad(plaintext, BLOCK_SIZE, style="pkcs7")
            cipher = AES.new(key, AES.MODE_ECB)
            ciphertext = cipher.encrypt(padded_data)
            return ciphertext, b""

        elif normalized_mode == "CBC":
            # CBC mode uses 16-byte IV and PKCS7 padding
            if iv_or_nonce is None or len(iv_or_nonce) == 0:
                iv = get_random_bytes(IV_SIZE_CBC)
            else:
                if len(iv_or_nonce) != IV_SIZE_CBC:
                    raise ValueError(f"CBC mode IV must be exactly {IV_SIZE_CBC} bytes, got {len(iv_or_nonce)} bytes.")
                iv = iv_or_nonce
            padded_data = pad(plaintext, BLOCK_SIZE, style="pkcs7")
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            ciphertext = cipher.encrypt(padded_data)
            return ciphertext, iv

        elif normalized_mode == "CTR":
            # CTR stream mode: NO padding, 8-byte Nonce
            if iv_or_nonce is None or len(iv_or_nonce) == 0:
                nonce = get_random_bytes(NONCE_SIZE_CTR)
            else:
                if len(iv_or_nonce) != NONCE_SIZE_CTR:
                    raise ValueError(f"CTR mode Nonce must be exactly {NONCE_SIZE_CTR} bytes, got {len(iv_or_nonce)} bytes.")
                nonce = iv_or_nonce
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            ciphertext = cipher.encrypt(plaintext)
            return ciphertext, nonce

        else:
            raise ValueError(f"Unsupported AES mode: {normalized_mode}")

    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"Encryption failed: {e}") from e


def decrypt_bytes(
    ciphertext: bytes,
    key: bytes,
    mode: str,
    iv_or_nonce: Optional[bytes] = None
) -> bytes:
    """
    Decrypt ciphertext bytes using AES in the specified mode.
    
    :param ciphertext: Ciphertext bytes to decrypt.
    :param key: AES key bytes (16, 24, or 32 bytes).
    :param mode: AES mode ('ECB', 'CBC', 'CTR').
    :param iv_or_nonce: IV for CBC (16 bytes) or Nonce for CTR (8 bytes). Ignored for ECB.
    :return: Decrypted plaintext bytes.
    :raises ValueError: On invalid parameters, incorrect padding, or decryption failure.
    """
    if len(key) not in SUPPORTED_KEY_SIZES:
        raise ValueError(f"Invalid key size ({len(key)} bytes). Must be 16, 24, or 32 bytes.")

    normalized_mode = mode.upper().strip()
    if normalized_mode not in SUPPORTED_MODES:
        raise ValueError(f"Unsupported AES mode: '{mode}'. Must be one of {SUPPORTED_MODES}.")

    if not ciphertext:
        return b""

    try:
        if normalized_mode == "ECB":
            if len(ciphertext) % BLOCK_SIZE != 0:
                raise ValueError(
                    f"ECB ciphertext length ({len(ciphertext)} bytes) is not a multiple of AES block size ({BLOCK_SIZE})."
                )
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted_padded = cipher.decrypt(ciphertext)
            try:
                plaintext = unpad(decrypted_padded, BLOCK_SIZE, style="pkcs7")
            except ValueError as e:
                raise ValueError(
                    "Decryption failed: Incorrect PKCS#7 padding. The key, mode, or ciphertext is incorrect."
                ) from e
            return plaintext

        elif normalized_mode == "CBC":
            if iv_or_nonce is None or len(iv_or_nonce) != IV_SIZE_CBC:
                raise ValueError(
                    f"CBC mode requires a valid 16-byte IV. Got {len(iv_or_nonce) if iv_or_nonce else 0} bytes."
                )
            if len(ciphertext) % BLOCK_SIZE != 0:
                raise ValueError(
                    f"CBC ciphertext length ({len(ciphertext)} bytes) is not a multiple of AES block size ({BLOCK_SIZE})."
                )
            cipher = AES.new(key, AES.MODE_CBC, iv=iv_or_nonce)
            decrypted_padded = cipher.decrypt(ciphertext)
            try:
                plaintext = unpad(decrypted_padded, BLOCK_SIZE, style="pkcs7")
            except ValueError as e:
                raise ValueError(
                    "Decryption failed: Incorrect PKCS#7 padding. The key, IV, mode, or ciphertext is incorrect."
                ) from e
            return plaintext

        elif normalized_mode == "CTR":
            if iv_or_nonce is None or len(iv_or_nonce) != NONCE_SIZE_CTR:
                raise ValueError(
                    f"CTR mode requires a valid 8-byte Nonce. Got {len(iv_or_nonce) if iv_or_nonce else 0} bytes."
                )
            cipher = AES.new(key, AES.MODE_CTR, nonce=iv_or_nonce)
            plaintext = cipher.decrypt(ciphertext)
            return plaintext

        else:
            raise ValueError(f"Unsupported AES mode: {normalized_mode}")

    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"Decryption failed: {e}") from e
