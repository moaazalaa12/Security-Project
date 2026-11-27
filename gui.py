"""
gui.py
======
Modern CustomTkinter desktop interface for AES Image Encryption & Decryption.
Provides interactive ECB, CBC, and CTR visual analysis, key management,
lossless round-trip verification, background worker responsiveness,
responsive 50/50 and stacked preview layouts, full-featured zoom inspector,
and smooth Drag & Drop file loading with TkinterDnD integration.
"""

import os
import time
import threading
from typing import Optional, Dict, Tuple, List
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk

import customtkinter as ctk

# Safe TkinterDnD integration with graceful fallback
try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    HAS_TKDND = True
except ImportError:
    TkinterDnD = None
    DND_FILES = None
    HAS_TKDND = False

import crypto_engine
import image_handler


class ImageInspectorModal(ctk.CTkToplevel):
    """
    High-resolution zoomable and pannable image inspection window.
    Supports mouse-wheel zooming, click-and-drag panning, quick zoom presets,
    and sharp nearest-neighbor interpolation for analyzing AES pixel block patterns.
    """

    def __init__(self, parent, image: Image.Image, title_text: str):
        super().__init__(parent)

        self.orig_image = image
        self.zoom_level = 1.0
        self.is_fit_mode = True
        self._photo_ref = None

        self.title(f"Image Inspector • {title_text} ({image.width} × {image.height} px)")
        self.minsize(860, 600)

        # Center relative to parent
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        px = parent.winfo_x()
        py = parent.winfo_y()
        win_w = min(1080, max(860, pw - 80))
        win_h = min(760, max(600, ph - 60))
        x = max(0, px + (pw - win_w) // 2)
        y = max(0, py + (ph - win_h) // 2)
        self.geometry(f"{win_w}x{win_h}+{x}+{y}")

        # Top Toolbar
        self._init_toolbar(title_text)

        # Canvas & Scrollbars
        self._init_canvas()

        # Keyboard shortcuts
        self.bind("<Escape>", lambda e: self.destroy())
        self.bind("<Control-plus>", lambda e: self._zoom_step(1.25))
        self.bind("<Control-equal>", lambda e: self._zoom_step(1.25))
        self.bind("<Control-minus>", lambda e: self._zoom_step(0.8))
        self.bind("<Control-0>", lambda e: self._set_zoom(1.0))

        # Initial render after geometry settlement
        self.after(100, self._initial_fit)

    def _init_toolbar(self, title_text: str):
        """Build the top controls toolbar with zoom presets and telemetry."""
        toolbar = ctk.CTkFrame(self, height=44, corner_radius=0, fg_color=("gray85", "gray14"))
        toolbar.pack(fill="x", side="top", padx=0, pady=0)
        toolbar.pack_propagate(False)

        # Left Info
        info_lbl = ctk.CTkLabel(
            toolbar,
            text=f"{title_text} • {self.orig_image.width} × {self.orig_image.height} px ({self.orig_image.mode})",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold")
        )
        info_lbl.pack(side="left", padx=14)

        # Center/Right Zoom Presets
        controls_frame = ctk.CTkFrame(toolbar, fg_color="transparent")
        controls_frame.pack(side="right", padx=12)

        # Quick zoom buttons
        btn_fit = ctk.CTkButton(
            controls_frame, text="Fit", width=48, height=26,
            command=self._on_zoom_fit_clicked, font=ctk.CTkFont(size=11, weight="bold")
        )
        btn_fit.pack(side="left", padx=2)

        for pct in (50, 100, 150, 200):
            btn = ctk.CTkButton(
                controls_frame, text=f"{pct}%", width=46, height=26,
                command=lambda p=pct: self._set_zoom(p / 100.0),
                fg_color=("gray75", "gray25"), hover_color=("gray65", "gray35"),
                font=ctk.CTkFont(size=11)
            )
            btn.pack(side="left", padx=2)

        # Step buttons
        btn_minus = ctk.CTkButton(
            controls_frame, text="-", width=32, height=26,
            command=lambda: self._zoom_step(0.8),
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold")
        )
        btn_minus.pack(side="left", padx=(6, 2))

        self.zoom_label = ctk.CTkLabel(
            controls_frame, text="100%", width=50,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold")
        )
        self.zoom_label.pack(side="left", padx=2)

        btn_plus = ctk.CTkButton(
            controls_frame, text="+", width=32, height=26,
            command=lambda: self._zoom_step(1.25),
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold")
        )
        btn_plus.pack(side="left", padx=2)

        # Interaction hint
        hint_lbl = ctk.CTkLabel(
            controls_frame,
            text="🖱 Drag to pan • Scroll to zoom",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=("gray45", "gray65")
        )
        hint_lbl.pack(side="left", padx=(12, 4))

    def _init_canvas(self):
        """Build the canvas container paired with CTk scrollbars."""
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=8, pady=8)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        is_dark = (ctk.get_appearance_mode() == "Dark")
        canvas_bg = "#121214" if is_dark else "#f4f4f5"

        self.canvas = tk.Canvas(
            container,
            bg=canvas_bg,
            highlightthickness=0,
            cursor="hand2"
        )
        self.canvas.grid(row=0, column=0, sticky="nsew")

        self.v_scrollbar = ctk.CTkScrollbar(
            container, orientation="vertical", command=self.canvas.yview
        )
        self.v_scrollbar.grid(row=0, column=1, sticky="ns")

        self.h_scrollbar = ctk.CTkScrollbar(
            container, orientation="horizontal", command=self.canvas.xview
        )
        self.h_scrollbar.grid(row=1, column=0, sticky="ew")

        self.canvas.configure(
            xscrollcommand=self.h_scrollbar.set,
            yscrollcommand=self.v_scrollbar.set
        )

        # Mouse panning bindings
        self.canvas.bind("<ButtonPress-1>", self._on_start_pan)
        self.canvas.bind("<B1-Motion>", self._on_drag_pan)
        self.canvas.bind("<ButtonRelease-1>", self._on_end_pan)

        # Mouse wheel zoom bindings
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

    def _initial_fit(self):
        """Fit image to canvas on initial window launch."""
        self._zoom_fit()
        self.lift()
        self.focus_force()

    def _on_start_pan(self, event):
        """Begin canvas pan gesture."""
        self.canvas.scan_mark(event.x, event.y)
        self.canvas.configure(cursor="fleur")

    def _on_drag_pan(self, event):
        """Execute canvas pan gesture."""
        self.canvas.scan_dragto(event.x, event.y, gain=1)

    def _on_end_pan(self, event):
        """End canvas pan gesture."""
        self.canvas.configure(cursor="hand2")

    def _on_mousewheel(self, event):
        """Handle mouse wheel zooming."""
        if event.delta > 0:
            self._zoom_step(1.15)
        elif event.delta < 0:
            self._zoom_step(1.0 / 1.15)

    def _on_zoom_fit_clicked(self):
        """Handle Fit button click."""
        self.is_fit_mode = True
        self._zoom_fit()

    def _zoom_step(self, factor: float):
        """Step zoom level by multiplication factor."""
        self.is_fit_mode = False
        new_level = self.zoom_level * factor
        self._set_zoom(new_level)

    def _set_zoom(self, level: float):
        """Set zoom to explicit level and re-render."""
        self.zoom_level = max(0.05, min(16.0, level))
        self._render_image()

    def _zoom_fit(self):
        """Calculate zoom factor to fit entire image in canvas viewport."""
        cw = max(50, self.canvas.winfo_width() - 24)
        ch = max(50, self.canvas.winfo_height() - 24)
        iw = self.orig_image.width
        ih = self.orig_image.height
        if iw <= 0 or ih <= 0:
            return
        scale = min(cw / iw, ch / ih)
        self.zoom_level = max(0.05, min(10.0, scale))
        self._render_image()

    def _on_canvas_configure(self, event):
        """Re-fit image if window is resized while in Fit mode."""
        if self.is_fit_mode:
            self._zoom_fit()

    def _render_image(self):
        """Render resized image onto canvas with nearest-neighbor when enlarged."""
        w = max(1, int(self.orig_image.width * self.zoom_level))
        h = max(1, int(self.orig_image.height * self.zoom_level))

        # Use NEAREST when >= 100% so individual pixel blocks stay sharp
        if self.zoom_level >= 1.0:
            resample = Image.Resampling.NEAREST
        else:
            resample = Image.Resampling.LANCZOS

        resized = self.orig_image.resize((w, h), resample)
        self._photo_ref = ImageTk.PhotoImage(resized)

        self.canvas.delete("all")

        cw = self.canvas.winfo_width()
        ch = self.canvas.winfo_height()
        pos_x = max(cw // 2, w // 2)
        pos_y = max(ch // 2, h // 2)

        self.canvas.create_image(pos_x, pos_y, anchor="center", image=self._photo_ref)

        scroll_w = max(cw, w)
        scroll_h = max(ch, h)
        self.canvas.configure(scrollregion=(0, 0, scroll_w, scroll_h))

        self.zoom_label.configure(text=f"{int(round(self.zoom_level * 100))}%")


# Dynamic base class ensuring TkinterDnD mixin works cleanly when available
if HAS_TKDND and TkinterDnD is not None:
    class _BaseApp(ctk.CTk, TkinterDnD.DnDWrapper):
        pass
else:
    class _BaseApp(ctk.CTk):
        pass


class AESImageCipherApp(_BaseApp):
    """Main Application Window for AES Image Encryption & Decryption."""

    APP_TITLE = "AES Image Cipher • Visual Cryptography (SCE 422e)"
    MIN_WIDTH = 1150
    MIN_HEIGHT = 740
    SIDEBAR_WIDTH = 330

    SUPPORTED_ENCRYPT_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}
    SUPPORTED_DECRYPT_EXTENSIONS = {".png"}

    MODE_DESCRIPTIONS = {
        "ECB": "ECB: Identical blocks produce identical ciphertext (visual patterns visible)",
        "CBC": "CBC: Chained blocks with random IV (unbreakable pseudo-random noise)",
        "CTR": "CTR: Stream mode with Nonce counter (lossless stream, random noise)"
    }

    def __init__(self):
        super().__init__()

        # Drag and Drop initialization
        self._dnd_available = False
        if HAS_TKDND and TkinterDnD is not None:
            try:
                self.TkdndVersion = TkinterDnD._require(self)
                self._dnd_available = True
            except Exception:
                self.TkdndVersion = None
                self._dnd_available = False
        else:
            self.TkdndVersion = None
            self._dnd_available = False

        # Appearance setup
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.title(self.APP_TITLE)
        self.minsize(self.MIN_WIDTH, self.MIN_HEIGHT)

        # Center on screen
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        win_w = min(1240, max(self.MIN_WIDTH, screen_w - 60))
        win_h = min(820, max(self.MIN_HEIGHT, screen_h - 80))
        pos_x = max(0, (screen_w - win_w) // 2)
        pos_y = max(0, (screen_h - win_h) // 2)
        self.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")

        # Application state
        self.operation_mode = "Encrypt"  # "Encrypt" or "Decrypt"
        self.active_aes_mode = "CBC"
        self.current_key_size = 32       # 32 bytes = 256 bits
        self.view_layout_mode = "Side-by-Side"

        self.input_image: Optional[Image.Image] = None
        self.input_image_path: Optional[str] = None
        self.input_metadata: Dict[str, str] = {}

        self.output_image: Optional[Image.Image] = None
        self.output_png_info = None
        self.output_metadata: Dict[str, str] = {}

        self._resize_timer = None
        self._is_processing = False

        # Build UI layout
        self._init_layout()
        self._init_sidebar()
        self._init_workspace()
        self._init_statusbar()
        self._init_dnd_targets()

        # Generate initial key and IV
        self._generate_new_key()
        self._generate_new_iv_nonce()
        self._update_operation_ui_state()

        # Handle window resizing for image preview cards
        self.bind("<Configure>", self._on_window_configure)

    # =========================================================================
    # UI Initialization
    # =========================================================================

    def _init_layout(self):
        """Configure main window grid layout."""
        self.grid_columnconfigure(0, weight=0, minsize=self.SIDEBAR_WIDTH)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)

    def _init_sidebar(self):
        """Build the left sidebar with all cryptographic controls."""
        self.sidebar_frame = ctk.CTkScrollableFrame(
            self,
            width=self.SIDEBAR_WIDTH,
            corner_radius=0,
            fg_color=("gray92", "gray14")
        )
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        self.sidebar_frame.grid_columnconfigure(0, weight=1)

        # 1. Header & Branding
        header_card = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        header_card.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6))
        header_card.grid_columnconfigure(0, weight=1)

        title_lbl = ctk.CTkLabel(
            header_card,
            text="AES Image Cipher",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold")
        )
        title_lbl.grid(row=0, column=0, sticky="w")

        subtitle_lbl = ctk.CTkLabel(
            header_card,
            text="ECB • CBC • CTR Mode Visualizer",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=("gray40", "gray70")
        )
        subtitle_lbl.grid(row=1, column=0, sticky="w")

        badge_lbl = ctk.CTkLabel(
            header_card,
            text="Academic Cryptography Suite • SCE 422e",
            font=ctk.CTkFont(family="Segoe UI", size=9, slant="italic"),
            text_color=("#1f6aa5", "#38bdf8")
        )
        badge_lbl.grid(row=2, column=0, sticky="w", pady=(2, 0))

        # Divider
        self._add_divider(self.sidebar_frame, row=1)

        # 2. Operation Switcher (Encrypt / Decrypt)
        op_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="OPERATION WORKFLOW",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("gray30", "gray70")
        )
        op_label.grid(row=2, column=0, sticky="w", padx=12, pady=(4, 2))

        self.op_segmented = ctk.CTkSegmentedButton(
            self.sidebar_frame,
            values=["Encrypt", "Decrypt"],
            command=self._on_operation_changed,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            selected_color="#1f6aa5"
        )
        self.op_segmented.set("Encrypt")
        self.op_segmented.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 8))

        # 3. Image Selection Card
        img_card = ctk.CTkFrame(self.sidebar_frame, fg_color=("gray85", "gray18"), corner_radius=8)
        img_card.grid(row=4, column=0, sticky="ew", padx=10, pady=5)
        img_card.grid_columnconfigure(0, weight=1)

        self.img_card_title = ctk.CTkLabel(
            img_card,
            text="INPUT IMAGE SOURCE",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("gray30", "gray70")
        )
        self.img_card_title.grid(row=0, column=0, sticky="w", padx=10, pady=(6, 2))

        self.browse_btn = ctk.CTkButton(
            img_card,
            text="Select Plaintext Image...",
            command=self._on_browse_image,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=("#2b7a4b", "#15803d"),
            hover_color=("#205e3a", "#166534")
        )
        self.browse_btn.grid(row=1, column=0, sticky="ew", padx=10, pady=4)

        self.file_info_lbl = ctk.CTkLabel(
            img_card,
            text="No image loaded yet",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=("gray45", "gray65"),
            wraplength=290,
            justify="left"
        )
        self.file_info_lbl.grid(row=2, column=0, sticky="w", padx=10, pady=(0, 6))

        # 4. AES Cipher Mode Selection
        mode_card = ctk.CTkFrame(self.sidebar_frame, fg_color=("gray85", "gray18"), corner_radius=8)
        mode_card.grid(row=5, column=0, sticky="ew", padx=10, pady=5)
        mode_card.grid_columnconfigure(0, weight=1)

        mode_title = ctk.CTkLabel(
            mode_card,
            text="AES BLOCK CIPHER MODE",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("gray30", "gray70")
        )
        mode_title.grid(row=0, column=0, sticky="w", padx=10, pady=(6, 2))

        self.mode_segmented = ctk.CTkSegmentedButton(
            mode_card,
            values=["ECB", "CBC", "CTR"],
            command=self._on_aes_mode_changed,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold")
        )
        self.mode_segmented.set("CBC")
        self.mode_segmented.grid(row=1, column=0, sticky="ew", padx=10, pady=4)

        self.mode_desc_lbl = ctk.CTkLabel(
            mode_card,
            text=self.MODE_DESCRIPTIONS["CBC"],
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=("gray35", "gray70"),
            wraplength=290,
            justify="left"
        )
        self.mode_desc_lbl.grid(row=2, column=0, sticky="w", padx=10, pady=(2, 4))

        self.detected_mode_badge = ctk.CTkLabel(
            mode_card,
            text="",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=("#0284c7", "#38bdf8")
        )
        self.detected_mode_badge.grid(row=3, column=0, sticky="w", padx=10, pady=(0, 6))

        # 5. Key Management Card
        key_card = ctk.CTkFrame(self.sidebar_frame, fg_color=("gray85", "gray18"), corner_radius=8)
        key_card.grid(row=6, column=0, sticky="ew", padx=10, pady=5)
        key_card.grid_columnconfigure(0, weight=1)

        key_header_frame = ctk.CTkFrame(key_card, fg_color="transparent")
        key_header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(6, 2))
        key_header_frame.grid_columnconfigure(0, weight=1)

        key_title = ctk.CTkLabel(
            key_header_frame,
            text="SECRET KEY MANAGEMENT",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("gray30", "gray70")
        )
        key_title.grid(row=0, column=0, sticky="w")

        self.key_size_dropdown = ctk.CTkOptionMenu(
            key_header_frame,
            values=["256-bit (32 bytes)", "192-bit (24 bytes)", "128-bit (16 bytes)"],
            command=self._on_key_size_selected,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            width=130,
            height=22
        )
        self.key_size_dropdown.set("256-bit (32 bytes)")
        self.key_size_dropdown.grid(row=0, column=1, sticky="e")

        self.key_entry = ctk.CTkEntry(
            key_card,
            font=ctk.CTkFont(family="Consolas", size=11),
            placeholder_text="Hexadecimal AES key"
        )
        self.key_entry.grid(row=1, column=0, sticky="ew", padx=10, pady=4)
        self.key_entry.bind("<KeyRelease>", self._on_key_entry_changed)

        self.key_validation_lbl = ctk.CTkLabel(
            key_card,
            text="64 hex chars (32 / 32 bytes) ✓",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=("#166534", "#4ade80")
        )
        self.key_validation_lbl.grid(row=2, column=0, sticky="w", padx=10, pady=0)

        # Key action buttons row
        key_btn_frame = ctk.CTkFrame(key_card, fg_color="transparent")
        key_btn_frame.grid(row=3, column=0, sticky="ew", padx=8, pady=(4, 6))
        key_btn_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.gen_key_btn = ctk.CTkButton(
            key_btn_frame,
            text="Generate",
            command=self._generate_new_key,
            height=24,
            font=ctk.CTkFont(family="Segoe UI", size=10)
        )
        self.gen_key_btn.grid(row=0, column=0, padx=2)

        self.copy_key_btn = ctk.CTkButton(
            key_btn_frame,
            text="Copy",
            command=self._on_copy_key,
            height=24,
            fg_color=("gray75", "gray30"),
            hover_color=("gray65", "gray40"),
            font=ctk.CTkFont(family="Segoe UI", size=10)
        )
        self.copy_key_btn.grid(row=0, column=1, padx=2)

        self.save_key_btn = ctk.CTkButton(
            key_btn_frame,
            text="Save",
            command=self._on_save_key,
            height=24,
            fg_color=("gray75", "gray30"),
            hover_color=("gray65", "gray40"),
            font=ctk.CTkFont(family="Segoe UI", size=10)
        )
        self.save_key_btn.grid(row=0, column=2, padx=2)

        self.load_key_btn = ctk.CTkButton(
            key_btn_frame,
            text="Load",
            command=self._on_load_key,
            height=24,
            fg_color=("gray75", "gray30"),
            hover_color=("gray65", "gray40"),
            font=ctk.CTkFont(family="Segoe UI", size=10)
        )
        self.load_key_btn.grid(row=0, column=3, padx=2)

        # 6. IV / Nonce Field Card
        iv_card = ctk.CTkFrame(self.sidebar_frame, fg_color=("gray85", "gray18"), corner_radius=8)
        iv_card.grid(row=7, column=0, sticky="ew", padx=10, pady=5)
        iv_card.grid_columnconfigure(0, weight=1)

        iv_header = ctk.CTkFrame(iv_card, fg_color="transparent")
        iv_header.grid(row=0, column=0, sticky="ew", padx=10, pady=(6, 2))
        iv_header.grid_columnconfigure(0, weight=1)

        self.iv_title = ctk.CTkLabel(
            iv_header,
            text="IV / NONCE (HEX)",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("gray30", "gray70")
        )
        self.iv_title.grid(row=0, column=0, sticky="w")

        self.gen_iv_btn = ctk.CTkButton(
            iv_header,
            text="New IV",
            command=self._generate_new_iv_nonce,
            width=58,
            height=22,
            font=ctk.CTkFont(family="Segoe UI", size=10)
        )
        self.gen_iv_btn.grid(row=0, column=1, sticky="e")

        self.iv_entry = ctk.CTkEntry(
            iv_card,
            font=ctk.CTkFont(family="Consolas", size=11),
            placeholder_text="Hex IV (16B) or Nonce (8B)"
        )
        self.iv_entry.grid(row=1, column=0, sticky="ew", padx=10, pady=4)

        self.iv_helper_lbl = ctk.CTkLabel(
            iv_card,
            text="16 bytes (32 hex) for CBC • 8 bytes (16 hex) for CTR",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=("gray40", "gray65")
        )
        self.iv_helper_lbl.grid(row=2, column=0, sticky="w", padx=10, pady=(0, 6))

        # 7. Primary Action Buttons
        actions_card = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        actions_card.grid(row=8, column=0, sticky="ew", padx=10, pady=8)
        actions_card.grid_columnconfigure(0, weight=1)

        self.primary_action_btn = ctk.CTkButton(
            actions_card,
            text="Encrypt Image",
            command=self._on_run_primary_action,
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            height=42,
            fg_color="#1f6aa5",
            hover_color="#144870"
        )
        self.primary_action_btn.grid(row=0, column=0, sticky="ew", pady=(0, 6))

        self.save_output_btn = ctk.CTkButton(
            actions_card,
            text="Save Output PNG...",
            command=self._on_save_output_image,
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            height=32,
            fg_color=("gray75", "gray30"),
            hover_color=("gray65", "gray40"),
            state="disabled"
        )
        self.save_output_btn.grid(row=1, column=0, sticky="ew", pady=2)

        self.quick_swap_btn = ctk.CTkButton(
            actions_card,
            text="Send Output to Decrypt ➔",
            command=self._on_quick_swap_workflow,
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            height=32,
            fg_color=("#0d9488", "#0f766e"),
            hover_color=("#115e59", "#134e4a"),
            state="disabled"
        )
        self.quick_swap_btn.grid(row=2, column=0, sticky="ew", pady=2)

        # 8. Theme Switcher at bottom
        self._add_divider(self.sidebar_frame, row=9)
        theme_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        theme_frame.grid(row=10, column=0, sticky="ew", padx=12, pady=(4, 12))
        theme_frame.grid_columnconfigure(0, weight=1)

        self.theme_switch = ctk.CTkSwitch(
            theme_frame,
            text="Dark Mode",
            command=self._on_theme_switch_toggled,
            font=ctk.CTkFont(family="Segoe UI", size=11)
        )
        self.theme_switch.select()
        self.theme_switch.grid(row=0, column=0, sticky="w")

    def _init_workspace(self):
        """Build the right preview workspace with layout switcher and preview cards."""
        self.workspace_frame = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        self.workspace_frame.grid(row=0, column=1, sticky="nsew", padx=12, pady=(10, 4))
        self.workspace_frame.grid_rowconfigure(0, weight=0)  # Top Toolbar
        self.workspace_frame.grid_rowconfigure(1, weight=1)  # Card Container
        self.workspace_frame.grid_columnconfigure(0, weight=1)

        # Top Toolbar inside Right Workspace
        workspace_toolbar = ctk.CTkFrame(self.workspace_frame, height=36, fg_color="transparent")
        workspace_toolbar.grid(row=0, column=0, sticky="ew", padx=2, pady=(0, 6))
        workspace_toolbar.grid_columnconfigure(0, weight=1)
        workspace_toolbar.grid_columnconfigure(1, weight=0)

        ws_title = ctk.CTkLabel(
            workspace_toolbar,
            text="WORKSPACE • VISUAL CRYPTOGRAPHY ANALYSIS",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("gray35", "gray65")
        )
        ws_title.grid(row=0, column=0, sticky="w")

        # View Layout Switcher (Side-by-Side vs Stacked)
        self.layout_segmented = ctk.CTkSegmentedButton(
            workspace_toolbar,
            values=["Side-by-Side", "Stacked (Scrollable)"],
            command=self._on_view_layout_changed,
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            height=26
        )
        self.layout_segmented.set("Side-by-Side")
        self.layout_segmented.grid(row=0, column=1, sticky="e")

        # Container 1: Strict 50/50 Side-by-Side Container
        self.side_by_side_container = ctk.CTkFrame(self.workspace_frame, fg_color="transparent")
        self.side_by_side_container.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)
        self.side_by_side_container.grid_columnconfigure((0, 1), weight=1, uniform="preview_cols")
        self.side_by_side_container.grid_rowconfigure(0, weight=1)

        # Container 2: Stacked Scrollable Container (for wide 16:9 images)
        self.stacked_scroll_container = ctk.CTkScrollableFrame(self.workspace_frame, fg_color="transparent")
        self.stacked_scroll_container.grid_columnconfigure(0, weight=1)

        # Build Card 1: Input Preview Card
        self.input_card = ctk.CTkFrame(self.workspace_frame, corner_radius=10, fg_color=("gray88", "gray17"))
        self.input_card.grid_columnconfigure(0, weight=1)
        self.input_card.grid_rowconfigure(1, weight=1)

        input_header = ctk.CTkFrame(self.input_card, fg_color="transparent")
        input_header.grid(row=0, column=0, sticky="ew", padx=12, pady=(8, 4))
        input_header.grid_columnconfigure(0, weight=1)
        input_header.grid_columnconfigure(1, weight=0)
        input_header.grid_columnconfigure(2, weight=0)

        self.input_card_title = ctk.CTkLabel(
            input_header,
            text="Plaintext Input Image",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold")
        )
        self.input_card_title.grid(row=0, column=0, sticky="w")

        self.input_dims_lbl = ctk.CTkLabel(
            input_header,
            text="No Image Loaded",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=("gray40", "gray65")
        )
        self.input_dims_lbl.grid(row=0, column=1, sticky="e", padx=(4, 8))

        self.input_inspect_btn = ctk.CTkButton(
            input_header,
            text="🔍 Inspect",
            width=70,
            height=22,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            command=self._on_inspect_input_image,
            state="disabled"
        )
        self.input_inspect_btn.grid(row=0, column=2, sticky="e")

        self.input_display_frame = ctk.CTkFrame(self.input_card, fg_color=("gray80", "gray12"), corner_radius=8)
        self.input_display_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.input_display_frame.grid_propagate(False)
        self.input_display_frame.grid_columnconfigure(0, weight=1)
        self.input_display_frame.grid_rowconfigure(0, weight=1)

        self.input_img_label = ctk.CTkLabel(
            self.input_display_frame,
            text=self._get_input_placeholder_text(),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=("gray50", "gray60")
        )
        self.input_img_label.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        self.input_img_label.bind("<Button-1>", lambda e: self._on_inspect_input_image())

        # Build Card 2: Output Preview Card
        self.output_card = ctk.CTkFrame(self.workspace_frame, corner_radius=10, fg_color=("gray88", "gray17"))
        self.output_card.grid_columnconfigure(0, weight=1)
        self.output_card.grid_rowconfigure(1, weight=1)

        output_header = ctk.CTkFrame(self.output_card, fg_color="transparent")
        output_header.grid(row=0, column=0, sticky="ew", padx=12, pady=(8, 4))
        output_header.grid_columnconfigure(0, weight=1)
        output_header.grid_columnconfigure(1, weight=0)
        output_header.grid_columnconfigure(2, weight=0)

        self.output_card_title = ctk.CTkLabel(
            output_header,
            text="Encrypted Ciphertext (Viewable)",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold")
        )
        self.output_card_title.grid(row=0, column=0, sticky="w")

        self.output_dims_lbl = ctk.CTkLabel(
            output_header,
            text="Awaiting Execution",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=("gray40", "gray65")
        )
        self.output_dims_lbl.grid(row=0, column=1, sticky="e", padx=(4, 8))

        self.output_inspect_btn = ctk.CTkButton(
            output_header,
            text="🔍 Inspect",
            width=70,
            height=22,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            command=self._on_inspect_output_image,
            state="disabled"
        )
        self.output_inspect_btn.grid(row=0, column=2, sticky="e")

        self.output_display_frame = ctk.CTkFrame(self.output_card, fg_color=("gray80", "gray12"), corner_radius=8)
        self.output_display_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.output_display_frame.grid_propagate(False)
        self.output_display_frame.grid_columnconfigure(0, weight=1)
        self.output_display_frame.grid_rowconfigure(0, weight=1)

        self.output_img_label = ctk.CTkLabel(
            self.output_display_frame,
            text="No Output Generated\n\nClick 'Encrypt Image' to run AES encryption\non the input image pixels.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=("gray50", "gray60")
        )
        self.output_img_label.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        self.output_img_label.bind("<Button-1>", lambda e: self._on_inspect_output_image())

        # Bind configure on display containers for dynamic scaling
        self.input_display_frame.bind("<Configure>", self._on_container_configure)
        self.output_display_frame.bind("<Configure>", self._on_container_configure)

        # Place cards into default Side-by-Side view
        self._apply_layout_mode("Side-by-Side")

    def _init_statusbar(self):
        """Build the bottom status bar showing execution telemetry and diagnostics."""
        self.statusbar_frame = ctk.CTkFrame(self, height=34, corner_radius=0, fg_color=("gray85", "gray13"))
        self.statusbar_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=0, pady=0)
        self.statusbar_frame.grid_columnconfigure(1, weight=1)

        self.status_lbl = ctk.CTkLabel(
            self.statusbar_frame,
            text="● Ready",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("#16a34a", "#4ade80")
        )
        self.status_lbl.grid(row=0, column=0, sticky="w", padx=14, pady=3)

        self.diagnostic_lbl = ctk.CTkLabel(
            self.statusbar_frame,
            text="Header preserved • Pixel bytes encrypted • Secret key never stored in file metadata",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=("gray45", "gray60")
        )
        self.diagnostic_lbl.grid(row=0, column=1, sticky="w", padx=8, pady=3)

        self.telemetry_lbl = ctk.CTkLabel(
            self.statusbar_frame,
            text="Mode: AES-256-CBC | Time: 0 ms",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=("gray40", "gray65")
        )
        self.telemetry_lbl.grid(row=0, column=2, sticky="e", padx=14, pady=3)

    def _add_divider(self, parent, row: int):
        """Add a subtle horizontal divider line."""
        div = ctk.CTkFrame(parent, height=1, fg_color=("gray80", "gray25"))
        div.grid(row=row, column=0, sticky="ew", padx=12, pady=5)

    # =========================================================================
    # Drag & Drop File Support (TkinterDnD)
    # =========================================================================

    def _init_dnd_targets(self):
        """Register widgets as Drag & Drop targets if tkinterdnd2 is available."""
        if not self._dnd_available or DND_FILES is None:
            return

        drop_targets = [
            self,
            self.input_card,
            self.input_display_frame,
            self.input_img_label,
            self.browse_btn
        ]

        for target in drop_targets:
            try:
                target.drop_target_register(DND_FILES)
                target.dnd_bind("<<Drop>>", self._on_file_dropped)
            except Exception:
                pass

        # Visual feedback bindings on input card area
        for feedback_widget in [self.input_card, self.input_display_frame, self.input_img_label]:
            try:
                feedback_widget.dnd_bind("<<DropEnter>>", self._on_drop_enter)
                feedback_widget.dnd_bind("<<DropLeave>>", self._on_drop_leave)
            except Exception:
                pass

    def _on_drop_enter(self, event=None):
        """Highlight input card border with accent color when dragging over."""
        try:
            self.input_card.configure(border_width=2, border_color=("#1f6aa5", "#38bdf8"))
            self.input_display_frame.configure(border_width=2, border_color=("#1f6aa5", "#38bdf8"))
        except Exception:
            pass

    def _on_drop_leave(self, event=None):
        """Restore default input card border styling when drag leaves."""
        try:
            self.input_card.configure(border_width=0)
            self.input_display_frame.configure(border_width=0)
        except Exception:
            pass

    
    def _on_file_dropped(self, event):
        """Handle dropped files with robust path parsing."""
        self._on_drop_leave()

        if not event or not event.data:
            return

        raw_data = str(event.data).strip()
        normalized = raw_data.replace("\\", "/")

        # Handle a single existing path, including spaces
        single_path = os.path.normpath(
            normalized.strip("{}'\"")
        )

        if os.path.exists(single_path):
            paths = [single_path]
        else:
            try:
                raw_paths = list(self.tk.splitlist(normalized))
                paths = [
                    os.path.normpath(p.strip("{}'\""))
                    for p in raw_paths if p.strip()
                ]
            except Exception:
                paths = [single_path]

        valid_file, warning_note, error_msg = (
            self.validate_dropped_files(
                paths, self.operation_mode
            )
        )

        if error_msg:
            self._set_status("Error", error_msg)
            messagebox.showwarning(
                "Drop Failed", error_msg, parent=self
            )
            return

        if valid_file:
            if warning_note:
                self._set_status("Ready", warning_note)

            self._load_image_from_path(valid_file)

    @classmethod
    def validate_dropped_files(
        cls,
        paths: List[str],
        operation_mode: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Validate dropped paths for the given operation mode.
        Returns: (chosen_filepath, warning_or_info_note, error_message)
        """
        if not paths:
            return None, None, "No files detected in drop action."

        cleaned_paths = [p.strip() for p in paths if p and p.strip()]
        if not cleaned_paths:
            return None, None, "No valid file paths found."

        # Check if first dropped item is a directory
        if os.path.isdir(cleaned_paths[0]):
            folder_name = os.path.basename(os.path.normpath(cleaned_paths[0])) or cleaned_paths[0]
            return None, None, f"'{folder_name}' is a directory. Please drop an image file."

        allowed_exts = cls.SUPPORTED_ENCRYPT_EXTENSIONS if operation_mode == "Encrypt" else cls.SUPPORTED_DECRYPT_EXTENSIONS
        chosen_path = None

        for path in cleaned_paths:
            if os.path.isfile(path):
                _, ext = os.path.splitext(path.lower())
                if ext in allowed_exts:
                    chosen_path = path
                    break

        if not chosen_path:
            first_ext = os.path.splitext(cleaned_paths[0].lower())[1]
            first_name = os.path.basename(cleaned_paths[0])
            if operation_mode == "Decrypt":
                return (
                    None,
                    None,
                    f"Decrypt mode requires a lossless PNG image file. Dropped file '{first_name}' has extension '{first_ext or 'none'}'."
                )
            else:
                return (
                    None,
                    None,
                    f"Unsupported file format '{first_ext or 'unknown'}' for '{first_name}'. Supported formats: PNG, JPG, JPEG, BMP, GIF, WebP."
                )

        warning_note = None
        if len(cleaned_paths) > 1:
            warning_note = f"Multiple items dropped ({len(cleaned_paths)}); loaded '{os.path.basename(chosen_path)}'"

        return chosen_path, warning_note, None

    def _get_input_placeholder_text(self) -> str:
        """Return dynamic placeholder text based on operation mode and DnD availability."""
        dnd_prefix = "Drag & Drop an image here\nor click" if self._dnd_available else "Click"
        if self.operation_mode == "Encrypt":
            return (
                f"{dnd_prefix} 'Select Plaintext Image'\nto load an image (PNG, JPG, BMP, WebP)."
            )
        else:
            return (
                f"{dnd_prefix} 'Select Ciphertext PNG'\nto load an encrypted PNG file."
            )

    # =========================================================================
    # Layout Switching & Dynamic Sizing
    # =========================================================================

    def _on_view_layout_changed(self, mode: str):
        """Switch between Side-by-Side 50/50 view and Stacked Scrollable view."""
        self.view_layout_mode = mode
        self._apply_layout_mode(mode)
        self.after(50, self._handle_delayed_resize)

    def _apply_layout_mode(self, mode: str):
        """Re-grid preview cards according to active view layout."""
        self.input_card.grid_forget()
        self.output_card.grid_forget()

        if mode == "Side-by-Side":
            self.stacked_scroll_container.grid_forget()
            self.side_by_side_container.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)

            # In side-by-side, let cards flex with window height
            self.input_card.configure(height=100)
            self.output_card.configure(height=100)
            self.input_display_frame.configure(height=100)
            self.output_display_frame.configure(height=100)

            self.input_card.grid(in_=self.side_by_side_container, row=0, column=0, sticky="nsew", padx=(0, 5), pady=0)
            self.output_card.grid(in_=self.side_by_side_container, row=0, column=1, sticky="nsew", padx=(5, 0), pady=0)
        else:
            self.side_by_side_container.grid_forget()
            self.stacked_scroll_container.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)

            # In stacked mode, provide ample card height for wide 16:9 images
            self.input_card.configure(height=470)
            self.output_card.configure(height=470)
            self.input_display_frame.configure(height=410)
            self.output_display_frame.configure(height=410)

            self.input_card.grid(in_=self.stacked_scroll_container._parent_frame, row=0, column=0, sticky="ew", padx=2, pady=(0, 12))
            self.output_card.grid(in_=self.stacked_scroll_container._parent_frame, row=1, column=0, sticky="ew", padx=2, pady=(0, 12))

    # =========================================================================
    # Operation & Mode Handlers
    # =========================================================================

    def _on_operation_changed(self, value: str):
        """Handle switching between Encrypt and Decrypt operation workflows."""
        self.operation_mode = value
        self._update_operation_ui_state()

    def _update_operation_ui_state(self):
        """Update buttons, titles, and placeholders based on the active workflow."""
        is_encrypt = (self.operation_mode == "Encrypt")

        if is_encrypt:
            self.browse_btn.configure(text="Select Plaintext Image...")
            self.primary_action_btn.configure(
                text="Encrypt Image",
                fg_color="#1f6aa5",
                hover_color="#144870"
            )
            self.input_card_title.configure(text="Plaintext Input Image")
            self.output_card_title.configure(text="Encrypted Ciphertext (Viewable)")
            self.quick_swap_btn.configure(text="Send Output to Decrypt ➔")
            self.detected_mode_badge.configure(text="")
        else:
            self.browse_btn.configure(text="Select Ciphertext PNG...")
            self.primary_action_btn.configure(
                text="Decrypt Image",
                fg_color=("#15803d", "#16a34a"),
                hover_color=("#166534", "#15803d")
            )
            self.input_card_title.configure(text="Ciphertext Input PNG")
            self.output_card_title.configure(text="Decrypted Plaintext Image")
            self.quick_swap_btn.configure(text="Send Output to Encrypt ➔")

        if self.input_image is None:
            self.input_img_label.configure(image=None, text=self._get_input_placeholder_text())

        self._update_iv_ui_state()
        self._update_telemetry()

    def _on_aes_mode_changed(self, mode: str):
        """Handle AES mode selection change (ECB, CBC, CTR)."""
        self.active_aes_mode = mode
        self.mode_desc_lbl.configure(text=self.MODE_DESCRIPTIONS.get(mode, ""))
        self._update_iv_ui_state()
        self._update_telemetry()

    def _update_iv_ui_state(self):
        """Update IV/Nonce field state based on current AES mode."""
        mode = self.active_aes_mode

        if mode == "ECB":
            self.iv_entry.delete(0, "end")
            self.iv_entry.insert(0, "")
            self.iv_entry.configure(state="disabled", placeholder_text="Not required for ECB mode")
            self.gen_iv_btn.configure(state="disabled")
            self.iv_helper_lbl.configure(text="ECB mode does not use an IV or Nonce.")
        else:
            self.iv_entry.configure(state="normal")
            self.gen_iv_btn.configure(state="normal")
            if mode == "CBC":
                self.iv_entry.configure(placeholder_text="16-byte (32 hex) IV")
                self.iv_helper_lbl.configure(text="16 bytes (32 hex chars) IV for CBC chaining.")
                current_iv = self.iv_entry.get().strip()
                if not current_iv or len(current_iv) != 32:
                    self._generate_new_iv_nonce()
            elif mode == "CTR":
                self.iv_entry.configure(placeholder_text="8-byte (16 hex) Nonce")
                self.iv_helper_lbl.configure(text="8 bytes (16 hex chars) Nonce for CTR counter.")
                current_iv = self.iv_entry.get().strip()
                if not current_iv or len(current_iv) != 16:
                    self._generate_new_iv_nonce()

    def _on_key_size_selected(self, choice: str):
        """Handle key size dropdown change (128, 192, 256 bits)."""
        if "128" in choice:
            self.current_key_size = 16
        elif "192" in choice:
            self.current_key_size = 24
        else:
            self.current_key_size = 32
        self._generate_new_key()

    def _generate_new_key(self):
        """Generate a cryptographically secure key of selected size and populate entry."""
        key_bytes = crypto_engine.generate_key(self.current_key_size)
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, key_bytes.hex())
        self._validate_key_entry()

    def _generate_new_iv_nonce(self):
        """Generate a random IV for CBC or Nonce for CTR."""
        mode = self.active_aes_mode
        if mode == "ECB":
            return
        iv_bytes = crypto_engine.generate_iv_or_nonce(mode)
        self.iv_entry.configure(state="normal")
        self.iv_entry.delete(0, "end")
        self.iv_entry.insert(0, iv_bytes.hex())

    def _on_key_entry_changed(self, event=None):
        """Trigger key validation on user keystrokes."""
        self._validate_key_entry()

    def _validate_key_entry(self) -> Optional[bytes]:
        """Validate current key entry and update visual badge."""
        key_str = self.key_entry.get().strip()
        try:
            key_bytes = crypto_engine.validate_key_hex(key_str)
            hex_len = len(key_bytes) * 2
            byte_len = len(key_bytes)
            bit_len = byte_len * 8

            if byte_len != self.current_key_size:
                self.current_key_size = byte_len
                self.key_size_dropdown.set(f"{bit_len}-bit ({byte_len} bytes)")

            self.key_validation_lbl.configure(
                text=f"{hex_len} hex chars ({byte_len} / {byte_len} bytes) ✓",
                text_color=("#166534", "#4ade80")
            )
            return key_bytes
        except ValueError as e:
            self.key_validation_lbl.configure(
                text=f"Invalid key: {e}",
                text_color=("#b91c1c", "#f87171")
            )
            return None

    def _on_copy_key(self):
        """Copy key hex to clipboard."""
        key_str = self.key_entry.get().strip()
        if key_str:
            self.clipboard_clear()
            self.clipboard_append(key_str)
            original_text = self.copy_key_btn.cget("text")
            self.copy_key_btn.configure(text="Copied!")
            self.after(1500, lambda: self.copy_key_btn.configure(text=original_text))

    def _on_save_key(self):
        """Save current key hex to a file."""
        key_str = self.key_entry.get().strip()
        if not key_str:
            messagebox.showwarning("Empty Key", "No key available to save.", parent=self)
            return
        file_path = filedialog.asksaveasfilename(
            parent=self,
            title="Save AES Key",
            defaultextension=".key",
            filetypes=[("AES Key File", "*.key"), ("Text File", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(key_str)
                self._set_status("Success", f"Key saved to {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save key file: {e}", parent=self)

    def _on_load_key(self):
        """Load key hex from a file."""
        file_path = filedialog.askopenfilename(
            parent=self,
            title="Load AES Key",
            filetypes=[("AES Key File", "*.key"), ("Text File", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                key_bytes = crypto_engine.validate_key_hex(content)
                self.key_entry.delete(0, "end")
                self.key_entry.insert(0, key_bytes.hex())
                self._validate_key_entry()
                self._set_status("Success", f"Key loaded from {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Load Error", f"Failed to load key: {e}", parent=self)

    def _on_theme_switch_toggled(self):
        """Toggle dark / light appearance mode."""
        if self.theme_switch.get() == 1:
            ctk.set_appearance_mode("Dark")
        else:
            ctk.set_appearance_mode("Light")

    # =========================================================================
    # Image Loading & Browsing
    # =========================================================================

    def _on_browse_image(self):
        """Open file dialog to browse for input image."""
        is_encrypt = (self.operation_mode == "Encrypt")

        if is_encrypt:
            file_types = [
                ("All Supported Images", "*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.webp"),
                ("PNG Image", "*.png"),
                ("JPEG Image", "*.jpg;*.jpeg"),
                ("Bitmap", "*.bmp"),
                ("All Files", "*.*")
            ]
            title = "Select Plaintext Image"
        else:
            file_types = [
                ("PNG Image", "*.png"),
                ("All Files", "*.*")
            ]
            title = "Select Encrypted Ciphertext PNG"

        path = filedialog.askopenfilename(parent=self, title=title, filetypes=file_types)
        if not path:
            return

        self._load_image_from_path(path)

    def _load_image_from_path(self, path: str):
        """Load and normalize image from disk, extracting metadata if present."""
        try:
            filename = os.path.basename(path)

            if self.operation_mode == "Encrypt":
                img = image_handler.open_and_normalize_image(path)
                meta = {}

                # Bonus UX: Check if this PNG has embedded AES metadata while in Encrypt mode
                try:
                    with Image.open(path) as raw_img:
                        enc_meta = image_handler.extract_metadata_from_info(raw_img.info or {})
                        detected = enc_meta.get("aes_mode")
                        if detected in crypto_engine.SUPPORTED_MODES:
                            self.after(50, lambda d=detected, fn=filename: self._set_status(
                                "Ready",
                                f"Tip: '{fn}' contains AES-{d} metadata — switch to Decrypt mode to decrypt it."
                            ))
                except Exception:
                    pass
            else:
                img, meta = image_handler.load_image_with_metadata(path)

            self.input_image = img
            self.input_image_path = path
            self.input_metadata = meta

            filesize_kb = os.path.getsize(path) / 1024
            self.file_info_lbl.configure(
                text=f"File: {filename}\nResolution: {img.width} × {img.height} px | Size: {filesize_kb:.1f} KB"
            )
            self.input_dims_lbl.configure(text=f"{img.width} × {img.height} px")
            self.input_inspect_btn.configure(state="normal")

            if self.operation_mode == "Decrypt":
                detected_mode = meta.get("aes_mode", "")
                if detected_mode in crypto_engine.SUPPORTED_MODES:
                    self.active_aes_mode = detected_mode
                    self.mode_segmented.set(detected_mode)
                    self.mode_desc_lbl.configure(text=self.MODE_DESCRIPTIONS.get(detected_mode, ""))
                    self.detected_mode_badge.configure(
                        text=f"Detected Mode: {detected_mode} (from PNG info)"
                    )
                else:
                    self.detected_mode_badge.configure(text="No AES mode found in PNG info")

                iv_hex = meta.get("iv_or_nonce", "")
                if iv_hex and self.active_aes_mode != "ECB":
                    self.iv_entry.configure(state="normal")
                    self.iv_entry.delete(0, "end")
                    self.iv_entry.insert(0, iv_hex)

                self._update_iv_ui_state()

            # Render input preview
            self._render_input_preview()

            # Clear previous output
            self.output_image = None
            self.output_png_info = None
            self.output_metadata = {}
            self.save_output_btn.configure(state="disabled")
            self.quick_swap_btn.configure(state="disabled")
            self.output_inspect_btn.configure(state="disabled")
            self.output_dims_lbl.configure(text="Awaiting Execution")
            self.output_img_label.configure(
                image=None,
                text=f"Ready to {self.operation_mode.lower()}.\nClick '{self.primary_action_btn.cget('text')}' to start."
            )

            self._set_status("Ready", f"Loaded {filename}")
            self._update_telemetry()

        except Exception as e:
            messagebox.showerror(
                "Image Load Failed",
                f"Could not load image:\n{e}\n\nPlease select a valid image file.",
                parent=self
            )

    # =========================================================================
    # Primary Execution (Worker Thread)
    # =========================================================================

    def _on_run_primary_action(self):
        """Start encryption or decryption on a background thread to prevent UI freezing."""
        if self._is_processing:
            return

        if self.input_image is None:
            messagebox.showwarning(
                "No Image Loaded",
                f"Please select an image before running {self.operation_mode.lower()}.",
                parent=self
            )
            return

        key_bytes = self._validate_key_entry()
        if key_bytes is None:
            messagebox.showerror(
                "Invalid Key",
                "Please provide a valid 128-bit, 192-bit, or 256-bit hexadecimal AES key.",
                parent=self
            )
            return

        mode = self.active_aes_mode
        iv_hex = self.iv_entry.get().strip()
        iv_bytes = None
        if mode in ("CBC", "CTR"):
            try:
                iv_bytes = crypto_engine.validate_iv_or_nonce_hex(mode, iv_hex)
            except ValueError as e:
                messagebox.showerror(
                    "Invalid IV / Nonce",
                    f"{e}\n\nPlease click 'New IV' or provide a valid hex value.",
                    parent=self
                )
                return

        self._set_processing_state(True)
        self._set_status("Processing", f"Running {mode} {self.operation_mode.lower()}...")

        thread = threading.Thread(
            target=self._worker_execute,
            args=(self.operation_mode, self.input_image, key_bytes, mode, iv_bytes, self.input_metadata),
            daemon=True
        )
        thread.start()

    def _worker_execute(
        self,
        op_mode: str,
        image: Image.Image,
        key: bytes,
        aes_mode: str,
        iv_or_nonce: Optional[bytes],
        metadata: Dict[str, str]
    ):
        """Background thread worker performing cryptographic operations."""
        start_time = time.perf_counter()
        try:
            if op_mode == "Encrypt":
                enc_img, png_info, out_meta = image_handler.encrypt_image(
                    image=image,
                    key=key,
                    mode=aes_mode,
                    iv_or_nonce=iv_or_nonce
                )
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                self.after(0, lambda: self._on_worker_success(enc_img, png_info, out_meta, elapsed_ms, op_mode))
            else:
                dec_img = image_handler.decrypt_image(
                    encrypted_image=image,
                    key=key,
                    mode=aes_mode,
                    iv_or_nonce=iv_or_nonce
                )
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                self.after(0, lambda: self._on_worker_success(dec_img, None, {}, elapsed_ms, op_mode))

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            error_msg = str(e)
            self.after(0, lambda: self._on_worker_failure(error_msg, op_mode))

    def _on_worker_success(
        self,
        result_img: Image.Image,
        png_info,
        metadata: Dict[str, str],
        elapsed_ms: float,
        op_mode: str
    ):
        """Called on main thread when background worker completes successfully."""
        self.output_image = result_img
        self.output_png_info = png_info
        self.output_metadata = metadata

        self._set_processing_state(False)
        self.save_output_btn.configure(state="normal")
        self.quick_swap_btn.configure(state="normal")
        self.output_inspect_btn.configure(state="normal")

        self.telemetry_lbl.configure(
            text=f"Mode: AES-{len(self._validate_key_entry() or b'') * 8}-{self.active_aes_mode} | Time: {elapsed_ms:.1f} ms"
        )
        self.output_dims_lbl.configure(text=f"{result_img.width} × {result_img.height} px")

        self._render_output_preview()

        if op_mode == "Encrypt":
            self._set_status(
                "Success",
                f"Encryption successful! Viewable ciphertext generated ({elapsed_ms:.1f} ms)."
            )
        else:
            self._set_status(
                "Success",
                f"Decryption successful! Exact RGB image recovered ({elapsed_ms:.1f} ms)."
            )

    def _on_worker_failure(self, error_message: str, op_mode: str):
        """Called on main thread when background worker fails."""
        self._set_processing_state(False)
        self._set_status("Error", f"{op_mode} failed: {error_message}")

        friendly_message = (
            f"{op_mode} failed with error:\n\n{error_message}\n\n"
            "Common causes:\n"
            "• Incorrect decryption key (ensure exact hex key matches encryption).\n"
            "• Wrong AES mode selected (e.g. CBC selected for ECB ciphertext).\n"
            "• Mismatched or corrupted IV/Nonce.\n"
            "• Image was not encrypted with AES Image Cipher or was converted to JPEG."
        )
        messagebox.showerror(f"{op_mode} Error", friendly_message, parent=self)

    def _set_processing_state(self, is_processing: bool):
        """Enable or disable interactive widgets during cryptographic processing."""
        self._is_processing = is_processing
        state = "disabled" if is_processing else "normal"
        self.primary_action_btn.configure(state=state)
        self.browse_btn.configure(state=state)
        self.op_segmented.configure(state=state)
        self.mode_segmented.configure(state=state)
        self.gen_key_btn.configure(state=state)
        self.gen_iv_btn.configure(state=state if self.active_aes_mode != "ECB" else "disabled")

    # =========================================================================
    # Output Saving & Quick-Workflow Swapping
    # =========================================================================

    def _on_save_output_image(self):
        """Save the output image strictly as lossless PNG with metadata."""
        if self.output_image is None:
            return

        is_encrypt = (self.operation_mode == "Encrypt")
        default_name = "encrypted_image.png" if is_encrypt else "decrypted_image.png"

        file_path = filedialog.asksaveasfilename(
            parent=self,
            title="Save Image (Lossless PNG)",
            initialfile=default_name,
            defaultextension=".png",
            filetypes=[("Lossless PNG Image", "*.png"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        try:
            image_handler.save_image_lossless_png(
                image=self.output_image,
                output_path=file_path,
                png_info=self.output_png_info
            )
            self._set_status("Success", f"Saved lossless PNG to {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("Save Failed", f"Could not save PNG:\n{e}", parent=self)

    def _on_quick_swap_workflow(self):
        """
        Streamlined round-trip workflow:
        Transfers the current output image to the input image,
        toggles the operation mode (Encrypt <-> Decrypt),
        and populates corresponding parameters for instant testing.
        """
        if self.output_image is None:
            return

        swapped_image = self.output_image.copy()

        if self.operation_mode == "Encrypt":
            self.operation_mode = "Decrypt"
            self.op_segmented.set("Decrypt")
            self._update_operation_ui_state()

            self.input_image = swapped_image
            self.input_image_path = "<In-Memory Encrypted PNG>"
            self.input_metadata = dict(self.output_metadata)

            self.file_info_lbl.configure(
                text=f"In-Memory Ciphertext\nResolution: {swapped_image.width} × {swapped_image.height} px"
            )
            self.input_dims_lbl.configure(text=f"{swapped_image.width} × {swapped_image.height} px")
            self.input_inspect_btn.configure(state="normal")

            if self.output_metadata.get("iv_or_nonce") and self.active_aes_mode != "ECB":
                self.iv_entry.configure(state="normal")
                self.iv_entry.delete(0, "end")
                self.iv_entry.insert(0, self.output_metadata["iv_or_nonce"])

            self._set_status("Ready", "Ciphertext transferred to Decrypt input. Click 'Decrypt Image' to test.")
        else:
            self.operation_mode = "Encrypt"
            self.op_segmented.set("Encrypt")
            self._update_operation_ui_state()

            self.input_image = swapped_image
            self.input_image_path = "<In-Memory Decrypted Image>"
            self.input_metadata = {}

            self.file_info_lbl.configure(
                text=f"In-Memory Plaintext\nResolution: {swapped_image.width} × {swapped_image.height} px"
            )
            self.input_dims_lbl.configure(text=f"{swapped_image.width} × {swapped_image.height} px")
            self.input_inspect_btn.configure(state="normal")
            self._set_status("Ready", "Decrypted image transferred to Encrypt input.")

        self._render_input_preview()

        self.output_image = None
        self.output_png_info = None
        self.output_metadata = {}
        self.save_output_btn.configure(state="disabled")
        self.quick_swap_btn.configure(state="disabled")
        self.output_inspect_btn.configure(state="disabled")
        self.output_dims_lbl.configure(text="Awaiting Execution")
        self.output_img_label.configure(
            image=None,
            text=f"Ready to {self.operation_mode.lower()}.\nClick '{self.primary_action_btn.cget('text')}' to start."
        )

    # =========================================================================
    # Full-Size Image Inspection
    # =========================================================================

    def _on_inspect_input_image(self):
        """Open high-resolution Image Inspector modal for input image."""
        if self.input_image is not None:
            title = "Input Plaintext" if self.operation_mode == "Encrypt" else "Input Ciphertext PNG"
            ImageInspectorModal(self, self.input_image, title)

    def _on_inspect_output_image(self):
        """Open high-resolution Image Inspector modal for output image."""
        if self.output_image is not None:
            title = "Encrypted Ciphertext" if self.operation_mode == "Encrypt" else "Decrypted Plaintext"
            ImageInspectorModal(self, self.output_image, title)

    # =========================================================================
    # Image Preview Rendering (Aspect-Ratio Preservation & DPI Awareness)
    # =========================================================================

    def _render_input_preview(self):
        """Render the input image into the input preview frame preserving aspect ratio."""
        if self.input_image is None:
            return
        self._render_image_to_label(
            self.input_image,
            self.input_display_frame,
            self.input_img_label
        )

    def _render_output_preview(self):
        """Render the output image into the output preview frame preserving aspect ratio."""
        if self.output_image is None:
            return
        self._render_image_to_label(
            self.output_image,
            self.output_display_frame,
            self.output_img_label
        )

    def _render_image_to_label(
        self,
        img: Image.Image,
        container: ctk.CTkFrame,
        target_label: ctk.CTkLabel
    ):
        """Scale and render a PIL Image inside a CTkLabel with exact aspect ratio and DPI scaling."""
        try:
            scaling = ctk.ScalingTracker.get_widget_scaling(container)
        except Exception:
            scaling = 1.0

        raw_w = container.winfo_width()
        raw_h = container.winfo_height()

        if raw_w <= 1 or raw_h <= 1:
            raw_w = container.cget("width") if container.cget("width") > 1 else 380
            raw_h = container.cget("height") if container.cget("height") > 1 else 300

        # Divide physical pixels by widget scaling to obtain logical points, subtracting padding
        logical_w = max(40, int(raw_w / scaling) - 16)
        logical_h = max(40, int(raw_h / scaling) - 16)

        img_w, img_h = img.size
        scale = min(logical_w / img_w, logical_h / img_h)
        disp_w = max(1, int(img_w * scale))
        disp_h = max(1, int(img_h * scale))

        ctk_img = ctk.CTkImage(
            light_image=img,
            dark_image=img,
            size=(disp_w, disp_h)
        )
        target_label.configure(image=ctk_img, text="", cursor="hand2")
        target_label._current_image = ctk_img

    def _on_container_configure(self, event=None):
        """Debounce preview container configure events to re-render images smoothly."""
        self._trigger_delayed_resize()

    def _on_window_configure(self, event=None):
        """Debounce window resize events to re-render preview images smoothly without flicker."""
        self._trigger_delayed_resize()

    def _trigger_delayed_resize(self):
        """Set or reset debounce timer for rendering preview images."""
        if self._resize_timer is not None:
            self.after_cancel(self._resize_timer)
        self._resize_timer = self.after(90, self._handle_delayed_resize)

    def _handle_delayed_resize(self):
        """Re-render visible images after resizing settles."""
        self._resize_timer = None
        if self.input_image is not None:
            self._render_input_preview()
        if self.output_image is not None:
            self._render_output_preview()

    # =========================================================================
    # Status & Telemetry
    # =========================================================================

    def _set_status(self, status_type: str, message: str):
        """Update status bar badge and message with semantic color coding."""
        if status_type == "Success":
            color = ("#16a34a", "#4ade80")
            badge = "● Success"
        elif status_type == "Error":
            color = ("#dc2626", "#f87171")
            badge = "● Error"
        elif status_type == "Processing":
            color = ("#ca8a04", "#facc15")
            badge = "● Processing..."
        else:
            color = ("#2563eb", "#60a5fa")
            badge = "● Ready"

        self.status_lbl.configure(text=badge, text_color=color)
        self.diagnostic_lbl.configure(text=message)

    def _update_telemetry(self):
        """Update telemetry string with current mode and dimensions."""
        key_bits = len(self._validate_key_entry() or b"") * 8
        if self.input_image:
            dim_str = f"{self.input_image.width} × {self.input_image.height} px"
        else:
            dim_str = "None"
        self.telemetry_lbl.configure(
            text=f"Mode: AES-{key_bits}-{self.active_aes_mode} | Dim: {dim_str}"
        )
