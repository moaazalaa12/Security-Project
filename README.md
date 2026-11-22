# AES Image Cipher • Visual Cryptography Suite
**Course Project: SCE 422e (Security Engineering)**

A production-quality Python desktop application that implements and visualizes **Advanced Encryption Standard (AES)** encryption and decryption directly on image pixel data across **ECB**, **CBC**, and **CTR** modes.

---

## 🌟 Key Features

1. **Strict Cryptographic Implementation**:
   - **ECB (`AES.MODE_ECB`)**: Block mode with PKCS7 padding. Demonstrates the classic cryptographic flaw where identical plaintext blocks produce identical ciphertext blocks, visually exposing image shapes (e.g., the Tux penguin).
   - **CBC (`AES.MODE_CBC`)**: Block mode with PKCS7 padding and a 16-byte cryptographically secure random Initialization Vector (IV). Completely eliminates repeated block patterns, yielding pseudo-random static noise.
   - **CTR (`AES.MODE_CTR`)**: Stream cipher mode with an 8-byte random Nonce counter. Encrypts pixel bytes with zero padding overhead, producing pure random static and guaranteeing lossless stream recovery.
2. **Key Management**:
   - Supported key sizes: **128-bit (16 B)**, **192-bit (24 B)**, and **256-bit (32 B, default)**.
   - Cryptographically secure pseudo-random generation via `Crypto.Random.get_random_bytes`.
   - Real-time hexadecimal validation and character count badge.
   - **Generate**, **Copy**, **Save (`.key`)**, and **Load (`.key`)** functionality.
   - **Zero Key Leakage Rule**: The secret key is **never** embedded into the image or PNG metadata.
3. **Lossless Round-Trip & Viewable Ciphertexts**:
   - **No Header Corruption**: Encrypts raw RGB pixel bytes (`width * height * 3`) while preserving standard image headers so the encrypted image can be opened and viewed in any image viewer.
   - **Intelligent Normalization**: Safely converts PNG, JPEG, BMP, GIF, and WebP images (`RGB`, `RGBA`, `LA`, `L`, `1`, `P`) into clean RGB, automatically compositing transparent regions onto a solid white background.
   - **Lossless Handling of Odd Dimensions**: Stores trailing PKCS7 padding bytes (`padding_overflow`) in non-secret PNG `PngInfo` text chunks. Guarantees 100% pixel-for-pixel fidelity even for irregular dimensions (e.g. `101 × 73`).
4. **Modern, Responsive Desktop GUI**:
   - Built with **`customtkinter`** with dark and light appearance modes.
   - **Equal-Width 50/50 Responsive Layout**: Uniform column constraints and DPI-aware container scaling guarantee preview cards never squash or clip, regardless of display resolution or Windows scaling.
   - **Dual View Layout Switch**:
     - **Side-by-Side (50/50)**: Ideal for square and standard images.
     - **Stacked (Scrollable)**: Full-width stacked view inside a scrollable viewport, perfect for wide 16:9 images.
   - **Click-to-Zoom & Pan Image Inspector**: Click on any preview image or the `🔍 Inspect` button to open a full-resolution inspection modal featuring mouse-wheel zoom, drag-to-pan, and nearest-neighbor resampling for pixel-crisp cryptographic block analysis.
   - **Responsive Background Execution (`threading.Thread`)**: Prevents interface freezing on large image processing.
   - **Quick-Workflow Button (`Send Output to Decrypt`)**: Instantly transfers ciphertext to the decrypt tab for single-click round-trip demonstrations.

---

## 📁 Project Architecture

```
aes_image_cipher/
├── crypto_engine.py      # Pure AES logic (ECB, CBC, CTR, key/IV validation)
├── image_handler.py      # Normalization, pixel extraction, PngInfo metadata
├── gui.py                # Modern CustomTkinter desktop interface & Image Inspector
├── main.py               # Clean application entry point
├── requirements.txt      # Project dependencies
├── sample_images/        # High-contrast test images (Tux, transparent logo, odd dim)
│   ├── tux_demo.png
│   ├── transparent_logo.png
│   └── odd_dimension_101x73.png
├── tests/
│   └── test_app.py       # Comprehensive pytest suite (87 test cases)
└── README.md             # Documentation and usage guide
```

---

## 🚀 Setup & Installation

### 1. Prerequisites
- Python 3.10 or higher.

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

*(Dependencies: `pycryptodome`, `Pillow`, `customtkinter`, `pytest`)*

### 3. Run the Desktop Application
```bash
python main.py
```

### 4. Run Automated Verification Tests
```bash
pytest -v
```

All 87 automated test cases will execute and verify:
- Exact pixel-for-pixel round-trip recovery across all modes (ECB, CBC, CTR).
- Key sizes (128, 192, 256 bits).
- Irregular/odd image dimensions (`101 × 73`).
- RGBA transparency compositing, 1-bit, and grayscale images.
- ECB pattern leakage vs. CBC/CTR randomness.
- Graceful error handling for incorrect keys, wrong cipher modes, or corrupted files.

---

## 🔬 Academic Evaluation & Demonstration Guide

### Demonstration 1: The ECB Mode Flaw
1. Run `python main.py`.
2. Keep **Operation** set to **Encrypt**.
3. Select `sample_images/tux_demo.png`.
4. Choose **ECB** mode and click **Encrypt Image**.
5. Observe the output image: The penguin's outline remains clearly distinguishable because identical 16-byte blocks of white/black pixels encrypt to identical ciphertext blocks!

### Demonstration 2: Semantic Security with CBC & CTR
1. Switch mode to **CBC** or **CTR**.
2. Click **Encrypt Image**.
3. Observe the output: The ciphertext is indistinguishable from random visual static.
4. Click **Encrypt Image** a second time: A completely new static pattern is generated due to the fresh random IV/Nonce.

### Demonstration 3: Lossless Round-Trip Verification
1. Click **Send Output to Decrypt ➔** on the sidebar.
2. The UI switches to Decrypt mode, automatically loads the ciphertext, and fills the IV from metadata.
3. Click **Decrypt Image**.
4. The exact original image is restored with 100% pixel-for-pixel accuracy!

---

## 🛡️ Security Notes
- **PNG Text Chunks**: Non-secret metadata (`aes_mode`, `iv_or_nonce`, `padding_overflow`, `orig_width`, `orig_height`) is embedded for convenience.
- **Key Security**: The secret AES key is **never** written to file metadata. The recipient must possess the secret key to decrypt.
