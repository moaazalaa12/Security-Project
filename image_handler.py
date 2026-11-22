"""
image_handler.py
================
Lossless image processing, normalization, and PNG metadata handling for AES Image Cipher.
Preserves viewable image structures while storing encryption metadata in PNG text chunks.
"""

from typing import Tuple, Optional, Dict, Any
from PIL import Image
from PIL.PngImagePlugin import PngInfo

import crypto_engine


def normalize_image_to_rgb(img: Image.Image) -> Image.Image:
    """
    Safely normalize any PIL Image to RGB format.
    Transparent images (RGBA, LA, or palette with transparency) are composited
    cleanly onto a solid white background. Grayscale and 1-bit images are converted to RGB.
    
    :param img: Input PIL Image.
    :return: A normalized RGB PIL Image.
    """
    if img.mode == "RGB":
        return img.copy()

    # Check for transparency in RGBA, LA, or Palette modes
    has_transparency = (
        img.mode in ("RGBA", "LA")
        or (img.mode == "P" and "transparency" in img.info)
    )

    if has_transparency:
        rgba = img.convert("RGBA")
        background = Image.new("RGB", rgba.size, (255, 255, 255))
        # Paste using the alpha channel as mask
        background.paste(rgba, mask=rgba.split()[3])
        return background
    else:
        # Handles '1', 'L', 'P' (without transparency), 'CMYK', etc.
        return img.convert("RGB")


def open_and_normalize_image(file_path: str) -> Image.Image:
    """
    Open an image file from disk and normalize it to RGB.
    
    :param file_path: Path to the image file.
    :return: Normalized RGB PIL Image.
    """
    with Image.open(file_path) as img:
        return normalize_image_to_rgb(img)


def build_png_info(
    mode: str,
    iv_or_nonce: bytes,
    padding_overflow: bytes,
    width: int,
    height: int
) -> PngInfo:
    """
    Construct a PngInfo object with non-secret cryptographic metadata.
    NEVER includes the secret encryption key.
    
    :param mode: AES mode ('ECB', 'CBC', 'CTR').
    :param iv_or_nonce: IV for CBC or Nonce for CTR in bytes.
    :param padding_overflow: Extra padded bytes beyond width*height*3.
    :param width: Image width.
    :param height: Image height.
    :return: PngInfo object.
    """
    png_info = PngInfo()
    png_info.add_text("aes_mode", mode.upper().strip())
    png_info.add_text("iv_or_nonce", iv_or_nonce.hex() if iv_or_nonce else "")
    png_info.add_text("padding_overflow", padding_overflow.hex() if padding_overflow else "")
    png_info.add_text("orig_width", str(width))
    png_info.add_text("orig_height", str(height))
    return png_info


def extract_metadata_from_info(info: Dict[str, Any]) -> Dict[str, str]:
    """
    Extract standard AES Image Cipher metadata from an image's info dict.
    
    :param info: Dictionary, usually img.info.
    :return: Dictionary containing extracted metadata strings.
    """
    return {
        "aes_mode": str(info.get("aes_mode", "")).strip().upper(),
        "iv_or_nonce": str(info.get("iv_or_nonce", "")).strip(),
        "padding_overflow": str(info.get("padding_overflow", "")).strip(),
        "orig_width": str(info.get("orig_width", "")).strip(),
        "orig_height": str(info.get("orig_height", "")).strip(),
    }


def load_image_with_metadata(file_path: str) -> Tuple[Image.Image, Dict[str, str]]:
    """
    Load an image from disk and extract its embedded PNG metadata if present.
    
    :param file_path: Path to the PNG file.
    :return: Tuple of (PIL.Image, metadata_dict).
    """
    img = Image.open(file_path)
    # Ensure pixel data is loaded into memory so file can be closed safely
    img.load()
    metadata = extract_metadata_from_info(img.info)
    return img, metadata


def encrypt_image(
    image: Image.Image,
    key: bytes,
    mode: str,
    iv_or_nonce: Optional[bytes] = None
) -> Tuple[Image.Image, PngInfo, Dict[str, str]]:
    """
    Encrypt an image's raw RGB pixel bytes using AES.
    Returns a viewable RGB image of the exact original dimensions,
    along with PngInfo containing non-secret metadata for lossless round-trip recovery.
    
    :param image: Input PIL Image.
    :param key: AES Key bytes (16, 24, or 32 bytes).
    :param mode: AES mode ('ECB', 'CBC', 'CTR').
    :param iv_or_nonce: Optional explicit IV or Nonce bytes.
    :return: Tuple of (viewable_encrypted_image, png_info, metadata_dict).
    """
    norm_img = normalize_image_to_rgb(image)
    width, height = norm_img.size
    raw_pixels = norm_img.tobytes()
    n_bytes = width * height * 3

    ciphertext, actual_iv_or_nonce = crypto_engine.encrypt_bytes(
        raw_pixels, key, mode, iv_or_nonce
    )

    viewable_bytes = ciphertext[:n_bytes]
    padding_overflow = ciphertext[n_bytes:]

    encrypted_img = Image.frombytes("RGB", (width, height), viewable_bytes)

    # Attach metadata to img.info for immediate in-memory round-trip operations
    metadata = {
        "aes_mode": mode.upper().strip(),
        "iv_or_nonce": actual_iv_or_nonce.hex() if actual_iv_or_nonce else "",
        "padding_overflow": padding_overflow.hex() if padding_overflow else "",
        "orig_width": str(width),
        "orig_height": str(height),
    }
    encrypted_img.info.update(metadata)

    png_info = build_png_info(
        mode=mode,
        iv_or_nonce=actual_iv_or_nonce,
        padding_overflow=padding_overflow,
        width=width,
        height=height
    )

    return encrypted_img, png_info, metadata


def save_image_lossless_png(
    image: Image.Image,
    output_path: str,
    png_info: Optional[PngInfo] = None
) -> None:
    """
    Save an image strictly in lossless PNG format, embedding metadata if provided.
    
    :param image: PIL Image to save.
    :param output_path: Destination file path.
    :param png_info: Optional PngInfo containing text chunks.
    """
    if not output_path.lower().endswith(".png"):
        output_path += ".png"

    if png_info is None:
        # Build png_info from image.info if available
        meta = extract_metadata_from_info(image.info)
        if meta.get("aes_mode"):
            iv_bytes = bytes.fromhex(meta["iv_or_nonce"]) if meta["iv_or_nonce"] else b""
            overflow_bytes = bytes.fromhex(meta["padding_overflow"]) if meta["padding_overflow"] else b""
            w = int(meta["orig_width"]) if meta["orig_width"] else image.width
            h = int(meta["orig_height"]) if meta["orig_height"] else image.height
            png_info = build_png_info(meta["aes_mode"], iv_bytes, overflow_bytes, w, h)

    if png_info is not None:
        image.save(output_path, format="PNG", pnginfo=png_info)
    else:
        image.save(output_path, format="PNG")


def decrypt_image(
    encrypted_image: Image.Image,
    key: bytes,
    mode: str,
    iv_or_nonce: Optional[bytes] = None,
    padding_overflow: Optional[bytes] = None
) -> Image.Image:
    """
    Decrypt an encrypted image to recover the exact original RGB image.
    
    :param encrypted_image: Encrypted PIL Image (viewable RGB).
    :param key: AES Key bytes.
    :param mode: AES mode ('ECB', 'CBC', 'CTR').
    :param iv_or_nonce: IV for CBC (16 bytes) or Nonce for CTR (8 bytes).
                        If None, attempts to extract from encrypted_image.info.
    :param padding_overflow: Overflow padding bytes from encryption.
                             If None, attempts to extract from encrypted_image.info.
    :return: Decrypted original RGB PIL Image.
    :raises ValueError: On decryption failure, wrong key/mode, or invalid dimensions.
    """
    # Normalize to RGB in case loaded in another mode
    rgb_img = encrypted_image.convert("RGB")
    width, height = rgb_img.size
    pixel_bytes = rgb_img.tobytes()

    metadata = extract_metadata_from_info(rgb_img.info)

    # Resolve padding overflow
    if padding_overflow is None:
        overflow_hex = metadata.get("padding_overflow", "")
        if overflow_hex:
            try:
                padding_overflow = bytes.fromhex(overflow_hex)
            except ValueError:
                padding_overflow = b""
        else:
            padding_overflow = b""

    # Resolve IV or Nonce
    if iv_or_nonce is None:
        iv_hex = metadata.get("iv_or_nonce", "")
        if iv_hex:
            try:
                iv_or_nonce = bytes.fromhex(iv_hex)
            except ValueError:
                iv_or_nonce = None

    # Reconstruct full ciphertext
    full_ciphertext = pixel_bytes + padding_overflow

    # Perform decryption via crypto_engine
    decrypted_bytes = crypto_engine.decrypt_bytes(
        ciphertext=full_ciphertext,
        key=key,
        mode=mode,
        iv_or_nonce=iv_or_nonce
    )

    # Determine original dimensions
    orig_w_str = metadata.get("orig_width", "")
    orig_h_str = metadata.get("orig_height", "")
    if orig_w_str.isdigit() and orig_h_str.isdigit():
        orig_width = int(orig_w_str)
        orig_height = int(orig_h_str)
    else:
        orig_width = width
        orig_height = height

    expected_len = orig_width * orig_height * 3
    if len(decrypted_bytes) != expected_len:
        raise ValueError(
            f"Decrypted data size ({len(decrypted_bytes)} bytes) does not match expected "
            f"image dimensions {orig_width}x{orig_height} ({expected_len} bytes)."
        )

    decrypted_image = Image.frombytes("RGB", (orig_width, orig_height), decrypted_bytes)
    return decrypted_image
