"""
tests/test_app.py
=================
Comprehensive automated test suite for AES Image Encryption & Decryption.
Verifies cryptographic correctness, edge cases, lossless image recovery,
and security properties across ECB, CBC, and CTR modes.
"""

import os
import sys
import tempfile
import pytest
from PIL import Image, ImageDraw

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import crypto_engine
import image_handler


# ============================================================================
# 1. Cryptographic Engine Unit Tests
# ============================================================================

@pytest.mark.parametrize("key_size", [16, 24, 32])
def test_key_generation(key_size):
    """Verify that random key generation produces valid bytes of exact length."""
    key = crypto_engine.generate_key(key_size)
    assert len(key) == key_size
    assert isinstance(key, bytes)


def test_invalid_key_generation():
    """Verify error when requesting unsupported key size."""
    with pytest.raises(ValueError, match="Invalid key size"):
        crypto_engine.generate_key(20)


@pytest.mark.parametrize("mode, expected_len", [
    ("ECB", 0),
    ("CBC", 16),
    ("CTR", 8),
])
def test_iv_nonce_generation(mode, expected_len):
    """Verify IV/Nonce generation lengths according to mode."""
    iv_or_nonce = crypto_engine.generate_iv_or_nonce(mode)
    assert len(iv_or_nonce) == expected_len


def test_key_validation_valid():
    """Verify hex key validation for 128, 192, and 256 bits."""
    for size in (16, 24, 32):
        raw_key = b"\xaa" * size
        hex_key = raw_key.hex()
        validated = crypto_engine.validate_key_hex(hex_key)
        assert validated == raw_key

        # With spaces and 0x prefix
        formatted = f" 0x{hex_key[:10]} {hex_key[10:]} "
        assert crypto_engine.validate_key_hex(formatted) == raw_key


def test_key_validation_invalid():
    """Verify errors for invalid key hex or unsupported lengths."""
    # Invalid characters
    with pytest.raises(ValueError, match="Invalid hexadecimal"):
        crypto_engine.validate_key_hex("not_a_valid_hex_string_1234567890")

    # Empty string
    with pytest.raises(ValueError, match="Key cannot be empty"):
        crypto_engine.validate_key_hex("   ")

    # Wrong length (e.g. 10 bytes = 20 hex chars)
    with pytest.raises(ValueError, match="Invalid key length"):
        crypto_engine.validate_key_hex("aa" * 10)


def test_iv_nonce_validation():
    """Verify strict IV/Nonce hex validation."""
    # ECB ignores IV
    assert crypto_engine.validate_iv_or_nonce_hex("ECB", "") == b""
    assert crypto_engine.validate_iv_or_nonce_hex("ECB", "1234") == b""

    # CBC requires exactly 16 bytes (32 hex)
    valid_cbc_iv = "00" * 16
    assert crypto_engine.validate_iv_or_nonce_hex("CBC", valid_cbc_iv) == b"\x00" * 16
    with pytest.raises(ValueError, match="CBC mode requires a 16-byte"):
        crypto_engine.validate_iv_or_nonce_hex("CBC", "00" * 8)

    # CTR requires exactly 8 bytes (16 hex)
    valid_ctr_nonce = "ff" * 8
    assert crypto_engine.validate_iv_or_nonce_hex("CTR", valid_ctr_nonce) == b"\xff" * 8
    with pytest.raises(ValueError, match="CTR mode requires an 8-byte"):
        crypto_engine.validate_iv_or_nonce_hex("CTR", "ff" * 16)


# ============================================================================
# 2. Raw Byte Encryption & Decryption Round-Trips
# ============================================================================

@pytest.mark.parametrize("mode", ["ECB", "CBC", "CTR"])
@pytest.mark.parametrize("key_size", [16, 24, 32])
@pytest.mark.parametrize("payload_len", [0, 15, 16, 17, 100, 1024])
def test_raw_bytes_round_trip(mode, key_size, payload_len):
    """Verify round-trip decryption for various payload lengths across all modes and key sizes."""
    key = crypto_engine.generate_key(key_size)
    plaintext = os.urandom(payload_len)

    ciphertext, iv_or_nonce = crypto_engine.encrypt_bytes(plaintext, key, mode)
    decrypted = crypto_engine.decrypt_bytes(ciphertext, key, mode, iv_or_nonce)

    assert decrypted == plaintext


def test_decryption_failure_wrong_key():
    """Verify graceful failure when decrypting with an incorrect key."""
    key1 = crypto_engine.generate_key(32)
    key2 = crypto_engine.generate_key(32)
    data = b"Sensitive university project data" * 10

    # ECB: should fail unpadding
    ct_ecb, _ = crypto_engine.encrypt_bytes(data, key1, "ECB")
    with pytest.raises(ValueError, match="Incorrect PKCS#7 padding"):
        crypto_engine.decrypt_bytes(ct_ecb, key2, "ECB")

    # CBC: should fail unpadding
    ct_cbc, iv = crypto_engine.encrypt_bytes(data, key1, "CBC")
    with pytest.raises(ValueError, match="Incorrect PKCS#7 padding"):
        crypto_engine.decrypt_bytes(ct_cbc, key2, "CBC", iv)


def test_cbc_ctr_fresh_iv_difference():
    """Verify that encrypting the same data twice in CBC and CTR yields distinct ciphertexts."""
    key = crypto_engine.generate_key(32)
    data = b"Deterministic payload to encrypt" * 5

    # CBC
    ct1, iv1 = crypto_engine.encrypt_bytes(data, key, "CBC")
    ct2, iv2 = crypto_engine.encrypt_bytes(data, key, "CBC")
    assert iv1 != iv2
    assert ct1 != ct2

    # CTR
    ct_ctr1, nonce1 = crypto_engine.encrypt_bytes(data, key, "CTR")
    ct_ctr2, nonce2 = crypto_engine.encrypt_bytes(data, key, "CTR")
    assert nonce1 != nonce2
    assert ct_ctr1 != ct_ctr2


# ============================================================================
# 3. Image Handling & Lossless Round-Trip Tests
# ============================================================================

def create_synthetic_image(mode: str, size: tuple, color=None) -> Image.Image:
    """Helper to create test images with various modes and patterns."""
    if mode == "RGB":
        img = Image.new("RGB", size, color or (120, 50, 200))
        d = ImageDraw.Draw(img)
        d.rectangle([2, 2, size[0] // 2, size[1] // 2], fill=(255, 0, 0))
        d.line([0, 0, size[0], size[1]], fill=(0, 255, 0), width=2)
        return img
    elif mode == "RGBA":
        img = Image.new("RGBA", size, (0, 0, 0, 0))  # Transparent background
        d = ImageDraw.Draw(img)
        d.ellipse([5, 5, size[0] - 5, size[1] - 5], fill=(255, 100, 50, 180))
        return img
    elif mode == "L":
        img = Image.new("L", size, 128)
        d = ImageDraw.Draw(img)
        d.rectangle([5, 5, size[0] - 5, size[1] - 5], fill=255)
        return img
    elif mode == "1":
        img = Image.new("1", size, 0)
        d = ImageDraw.Draw(img)
        d.rectangle([3, 3, size[0] - 3, size[1] - 3], fill=1)
        return img
    else:
        raise ValueError(f"Unsupported synthetic mode: {mode}")


@pytest.mark.parametrize("aes_mode", ["ECB", "CBC", "CTR"])
@pytest.mark.parametrize("key_size", [16, 24, 32])
def test_lossless_roundtrip_disk_io(aes_mode, key_size):
    """
    Critical requirement: Full round-trip test:
    Original Image -> Encrypt -> Save PNG to disk -> Load from disk -> Decrypt == Original normalized RGB.
    """
    key = crypto_engine.generate_key(key_size)
    orig_img = create_synthetic_image("RGB", (64, 48))
    norm_orig = image_handler.normalize_image_to_rgb(orig_img)

    with tempfile.TemporaryDirectory() as tmpdir:
        encrypted_png_path = os.path.join(tmpdir, "encrypted.png")

        # Encrypt and save to disk
        enc_img, png_info, meta = image_handler.encrypt_image(norm_orig, key, aes_mode)
        image_handler.save_image_lossless_png(enc_img, encrypted_png_path, png_info)

        # File exists and is a valid PNG
        assert os.path.exists(encrypted_png_path)

        # Load from disk with metadata
        loaded_img, loaded_meta = image_handler.load_image_with_metadata(encrypted_png_path)
        assert loaded_meta["aes_mode"] == aes_mode
        assert int(loaded_meta["orig_width"]) == 64
        assert int(loaded_meta["orig_height"]) == 48

        # Decrypt
        dec_img = image_handler.decrypt_image(
            loaded_img,
            key=key,
            mode=loaded_meta["aes_mode"]
        )

        # Verify exact pixel-for-pixel match
        assert dec_img.size == norm_orig.size
        assert dec_img.mode == "RGB"
        assert dec_img.tobytes() == norm_orig.tobytes()


@pytest.mark.parametrize("aes_mode", ["ECB", "CBC", "CTR"])
def test_tricky_odd_dimensions(aes_mode):
    """
    Test odd dimensions where width * height * 3 is NOT divisible by 16.
    Example: 101 x 73 * 3 = 22,119 bytes (22119 % 16 = 7).
    Ensures padding_overflow metadata handles trailing bytes without loss.
    """
    key = crypto_engine.generate_key(32)
    odd_img = create_synthetic_image("RGB", (101, 73))
    norm_orig = image_handler.normalize_image_to_rgb(odd_img)

    with tempfile.TemporaryDirectory() as tmpdir:
        save_path = os.path.join(tmpdir, "odd_enc.png")

        enc_img, png_info, meta = image_handler.encrypt_image(norm_orig, key, aes_mode)
        image_handler.save_image_lossless_png(enc_img, save_path, png_info)

        loaded_img, loaded_meta = image_handler.load_image_with_metadata(save_path)
        dec_img = image_handler.decrypt_image(loaded_img, key, loaded_meta["aes_mode"])

        assert dec_img.size == (101, 73)
        assert dec_img.tobytes() == norm_orig.tobytes()


def test_rgba_with_transparency_normalization():
    """Verify RGBA image with transparency is composited onto white and round-trips cleanly."""
    key = crypto_engine.generate_key(32)
    rgba_img = create_synthetic_image("RGBA", (50, 50))
    norm_orig = image_handler.normalize_image_to_rgb(rgba_img)

    assert norm_orig.mode == "RGB"

    enc_img, png_info, _ = image_handler.encrypt_image(norm_orig, key, "CBC")
    dec_img = image_handler.decrypt_image(enc_img, key, "CBC")

    assert dec_img.size == (50, 50)
    assert dec_img.mode == "RGB"
    assert dec_img.tobytes() == norm_orig.tobytes()


@pytest.mark.parametrize("src_mode", ["L", "1"])
def test_grayscale_and_1bit_normalization(src_mode):
    """Verify 1-bit and grayscale images normalize cleanly and round-trip."""
    key = crypto_engine.generate_key(16)
    img = create_synthetic_image(src_mode, (40, 30))
    norm_orig = image_handler.normalize_image_to_rgb(img)

    assert norm_orig.mode == "RGB"
    assert norm_orig.size == (40, 30)

    enc_img, _, _ = image_handler.encrypt_image(norm_orig, key, "CTR")
    dec_img = image_handler.decrypt_image(enc_img, key, "CTR")

    assert dec_img.tobytes() == norm_orig.tobytes()


def test_ecb_pattern_exposure_vs_cbc_ctr_randomness():
    """
    Verify the fundamental visual property of ECB:
    Identical plaintext blocks produce identical ciphertext blocks,
    preserving geometric patterns, whereas CBC and CTR produce pseudo-random noise.
    """
    key = crypto_engine.generate_key(32)
    # 64x64 solid white square with a solid black square inside
    img = Image.new("RGB", (64, 64), (255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.rectangle([16, 16, 47, 47], fill=(0, 0, 0))

    enc_ecb, _, _ = image_handler.encrypt_image(img, key, "ECB")
    enc_cbc, _, _ = image_handler.encrypt_image(img, key, "CBC")
    enc_ctr, _, _ = image_handler.encrypt_image(img, key, "CTR")

    bytes_ecb = enc_ecb.tobytes()
    bytes_cbc = enc_cbc.tobytes()
    bytes_ctr = enc_ctr.tobytes()

    # In ECB, all 16-byte blocks of pure white will produce the exact same 16-byte ciphertext
    # Check that in ECB there are repeated 16-byte blocks
    ecb_blocks = [bytes_ecb[i:i+16] for i in range(0, len(bytes_ecb) - 16, 16)]
    unique_ecb_blocks = len(set(ecb_blocks))

    cbc_blocks = [bytes_cbc[i:i+16] for i in range(0, len(bytes_cbc) - 16, 16)]
    unique_cbc_blocks = len(set(cbc_blocks))

    ctr_blocks = [bytes_ctr[i:i+16] for i in range(0, len(bytes_ctr) - 16, 16)]
    unique_ctr_blocks = len(set(ctr_blocks))

    # ECB has far fewer unique blocks because identical white blocks map to identical cipher blocks
    assert unique_ecb_blocks < len(ecb_blocks) * 0.5
    # CBC and CTR produce virtually all unique blocks
    assert unique_cbc_blocks == len(cbc_blocks)
    assert unique_ctr_blocks == len(ctr_blocks)


def test_decryption_with_wrong_mode():
    """Verify that decrypting with the wrong mode fails or produces invalid unpadding."""
    key = crypto_engine.generate_key(32)
    img = create_synthetic_image("RGB", (32, 32))

    # Encrypt with CBC
    enc_cbc, _, _ = image_handler.encrypt_image(img, key, "CBC")

    # Attempt to decrypt with ECB (will fail PKCS7 padding or fail to reproduce image)
    with pytest.raises(ValueError):
        image_handler.decrypt_image(enc_cbc, key, "ECB")


def test_decryption_with_corrupted_ciphertext():
    """Verify that tampering with ciphertext triggers ValueError upon decryption."""
    key = crypto_engine.generate_key(32)
    img = create_synthetic_image("RGB", (32, 32))
    enc_cbc, _, _ = image_handler.encrypt_image(img, key, "CBC")

    # Corrupt raw pixels
    raw = bytearray(enc_cbc.tobytes())
    raw[-5] ^= 0xFF  # Corrupt near the end (affects padding block)
    corrupted_img = Image.frombytes("RGB", enc_cbc.size, bytes(raw))
    corrupted_img.info.update(enc_cbc.info)

    with pytest.raises(ValueError):
        image_handler.decrypt_image(corrupted_img, key, "CBC")


def test_jpeg_and_bmp_normalization_and_roundtrip():
    """Verify loading and normalizing genuine JPEG and BMP files from disk."""
    key = crypto_engine.generate_key(32)
    orig_img = create_synthetic_image("RGB", (55, 45))

    with tempfile.TemporaryDirectory() as tmpdir:
        jpg_path = os.path.join(tmpdir, "test.jpg")
        bmp_path = os.path.join(tmpdir, "test.bmp")

        orig_img.save(jpg_path, format="JPEG")
        orig_img.save(bmp_path, format="BMP")

        for p in (jpg_path, bmp_path):
            norm = image_handler.open_and_normalize_image(p)
            assert norm.mode == "RGB"
            assert norm.size == (55, 45)

            enc_img, png_info, meta = image_handler.encrypt_image(norm, key, "CTR")
            dec_img = image_handler.decrypt_image(enc_img, key, "CTR")
            assert dec_img.tobytes() == norm.tobytes()


def test_gui_app_initialization_and_helpers():
    """Verify that GUI initializes properly and helper methods function as expected."""
    from gui import AESImageCipherApp

    app = AESImageCipherApp()
    try:
        app.withdraw()  # Keep window hidden during test
        assert app.operation_mode == "Encrypt"
        assert app.active_aes_mode == "CBC"

        # Test key entry validation
        valid_key = app._validate_key_entry()
        assert valid_key is not None
        assert len(valid_key) == 32

        # Test switching AES modes
        app._on_aes_mode_changed("ECB")
        assert app.active_aes_mode == "ECB"
        assert app.iv_entry.cget("state") == "disabled"

        app._on_aes_mode_changed("CTR")
        assert app.active_aes_mode == "CTR"
        assert app.iv_entry.cget("state") == "normal"
        assert len(app.iv_entry.get().strip()) == 16  # 8 bytes nonce

        app._on_aes_mode_changed("CBC")
        assert app.active_aes_mode == "CBC"
        assert len(app.iv_entry.get().strip()) == 32  # 16 bytes IV

        # Test switching operations
        app._on_operation_changed("Decrypt")
        assert app.operation_mode == "Decrypt"

        app._on_operation_changed("Encrypt")
        assert app.operation_mode == "Encrypt"
    finally:
        app.destroy()


def test_gui_responsive_layout_and_inspector():
    """Verify preview layout switching (Side-by-Side vs Stacked) and ImageInspectorModal."""
    from gui import AESImageCipherApp, ImageInspectorModal

    app = AESImageCipherApp()
    try:
        app.withdraw()

        # Verify initial layout
        assert app.view_layout_mode == "Side-by-Side"
        assert app.side_by_side_container.winfo_manager() == "grid"

        # Switch to Stacked layout
        app._on_view_layout_changed("Stacked (Scrollable)")
        assert app.view_layout_mode == "Stacked (Scrollable)"
        assert app.side_by_side_container.winfo_manager() == ""

        # Switch back to Side-by-Side
        app._on_view_layout_changed("Side-by-Side")
        assert app.view_layout_mode == "Side-by-Side"
        assert app.side_by_side_container.winfo_manager() == "grid"

        # Test ImageInspectorModal
        test_img = Image.new("RGB", (320, 240), (100, 150, 200))
        modal = ImageInspectorModal(app, test_img, "Test Inspector")
        try:
            modal.withdraw()
            assert modal.orig_image == test_img
            assert modal.zoom_level > 0

            # Test zoom controls
            modal._set_zoom(1.5)
            assert modal.zoom_level == 1.5

            modal._zoom_step(1.2)
            assert modal.zoom_level == pytest.approx(1.8)

            modal._on_zoom_fit_clicked()
            assert modal.is_fit_mode is True
        finally:
            modal.destroy()
    finally:
        app.destroy()


def test_drag_and_drop_validation_and_parsing():
    """Verify Drag & Drop Windows path parsing and mode-specific extension validation."""
    from gui import AESImageCipherApp

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create valid test images
        png_path = os.path.join(tmpdir, "sample image (1).png")
        jpg_path = os.path.join(tmpdir, "photo with spaces.jpg")
        txt_path = os.path.join(tmpdir, "document.txt")
        sub_dir = os.path.join(tmpdir, "folder")

        create_synthetic_image("RGB", (24, 24)).save(png_path)
        create_synthetic_image("RGB", (24, 24)).save(jpg_path, format="JPEG")
        with open(txt_path, "w") as f:
            f.write("text content")
        os.makedirs(sub_dir, exist_ok=True)

        # 1. Single valid file in Encrypt mode
        chosen, warning, err = AESImageCipherApp.validate_dropped_files([png_path], "Encrypt")
        assert chosen == png_path
        assert warning is None
        assert err is None

        # 2. JPG in Encrypt mode (supported)
        chosen, warning, err = AESImageCipherApp.validate_dropped_files([jpg_path], "Encrypt")
        assert chosen == jpg_path
        assert err is None

        # 3. JPG in Decrypt mode (rejected - Decrypt requires PNG)
        chosen, warning, err = AESImageCipherApp.validate_dropped_files([jpg_path], "Decrypt")
        assert chosen is None
        assert "requires a lossless PNG" in err

        # 4. TXT in Encrypt mode (unsupported)
        chosen, warning, err = AESImageCipherApp.validate_dropped_files([txt_path], "Encrypt")
        assert chosen is None
        assert "Unsupported file format" in err

        # 5. Dropping a directory
        chosen, warning, err = AESImageCipherApp.validate_dropped_files([sub_dir], "Encrypt")
        assert chosen is None
        assert "is a directory" in err

        # 6. Multiple files dropped (picks first valid image, produces warning note)
        chosen, warning, err = AESImageCipherApp.validate_dropped_files([txt_path, png_path, jpg_path], "Encrypt")
        assert chosen == png_path
        assert "Multiple items dropped" in warning
        assert err is None

        # 7. Test Windows curly-braced path splitlist parsing
        app = AESImageCipherApp()
        try:
            app.withdraw()
            # 7. Test Windows curly-braced path splitlist parsing
            raw_event_data = f'{{{png_path}}} {{{jpg_path}}}'
            normalized = raw_event_data.replace("\\", "/")
            parsed = [os.path.normpath(p.strip("{}'\"")) for p in app.tk.splitlist(normalized)]
            assert len(parsed) == 2
            assert parsed[0] == os.path.normpath(png_path)
            assert parsed[1] == os.path.normpath(jpg_path)

            # 8. Test _on_file_dropped integration
            class FakeEvent:
                def __init__(self, data):
                    self.data = data
            app._on_file_dropped(FakeEvent(png_path))
            assert app.input_image is not None
            assert app.input_image_path == png_path

            # Check DnD availability on this system
            assert hasattr(app, "_dnd_available")
            if app._dnd_available:
                assert app.TkdndVersion is not None
        finally:
            app.destroy()



