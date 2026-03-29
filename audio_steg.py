"""
Advanced Audio Steganography using LSB Technique
=================================================
Author  : Senior Developer
Version : 2.0 (Enhanced Edition)
"""

# ── Always run from the script's own directory ────────────────────────────────
import os as _os
_os.chdir(_os.path.dirname(_os.path.abspath(__file__)))

# ──────────────────────────────────────────────────────────────────────────────
#  AUTO-INSTALL REQUIRED PACKAGES
# ──────────────────────────────────────────────────────────────────────────────
import subprocess
import sys
from importlib.metadata import distributions as _imeta_dists

REQUIRED = ["cryptography", "Pillow"]
_installed = {d.metadata["Name"].lower() for d in _imeta_dists()}
for pkg in REQUIRED:
    if pkg.lower() not in _installed:
        print(f"[setup] Installing {pkg} …")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

# ──────────────────────────────────────────────────────────────────────────────
#  STANDARD IMPORTS
# ──────────────────────────────────────────────────────────────────────────────
import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext, ttk
import os
import wave
import hashlib
import datetime
import threading
import smtplib
import re
import tempfile
import webbrowser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.audio import MIMEAudio
from cryptography.fernet import Fernet, InvalidToken  # type: ignore

# ──────────────────────────────────────────────────────────────────────────────
#  COLOUR PALETTE  (dark cyberpunk theme)
# ──────────────────────────────────────────────────────────────────────────────
BG_DARK    = "#0d1117"
BG_PANEL   = "#161b22"
BG_CARD    = "#1e2633"
BG_INPUT   = "#0d1117"
ACCENT     = "#00d4ff"          # cyan
ACCENT2    = "#7c3aed"          # purple
SUCCESS    = "#22c55e"          # green
WARNING    = "#f59e0b"          # amber
ERROR      = "#ef4444"          # red
TEXT_MAIN  = "#e6edf3"
TEXT_SUB   = "#8b949e"
BORDER     = "#30363d"

FONT_TITLE  = ("Consolas", 22, "bold")
FONT_HEADER = ("Consolas", 13, "bold")
FONT_BODY   = ("Consolas", 10)
FONT_CODE   = ("Courier New", 9)
FONT_BTN    = ("Consolas", 10, "bold")
FONT_SMALL  = ("Consolas", 8)

# ──────────────────────────────────────────────────────────────────────────────
#  LOGGING HELPER
# ──────────────────────────────────────────────────────────────────────────────
LOG_DIR  = "logs"
LOG_FILE = os.path.join(LOG_DIR, "activity.log")

def ensure_dirs():
    os.makedirs("Output", exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)

ensure_dirs()

def write_log(entry: str):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}]  {entry}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(line)

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

# ──────────────────────────────────────────────────────────────────────────────
#  CORE LSB ENCODE / DECODE
# ──────────────────────────────────────────────────────────────────────────────

def estimate_capacity(wav_path: str) -> int:
    """Return max bytes that can be hidden (excluding 32-byte header)."""
    try:
        with wave.open(wav_path, "rb") as aw:
            n = aw.getnframes()
        return max(0, (n - 32) // 8)
    except Exception:
        return 0

def lsb_encode(audio_path: str, output_path: str, secret: str) -> None:
    """Embed *secret* string into WAV file via LSB and write to *output_path*."""
    aw = wave.open(audio_path, mode="rb")
    params = aw.getparams()
    frames = bytearray(aw.readframes(aw.getnframes()))
    aw.close()

    # Each byte of the message uses 8 frame-bytes (1 bit each).
    # Header = 32 frame-bytes (4 bytes * 8 bits) for message length.
    capacity = (len(frames) - 32) // 8
    if len(secret) > capacity:
        raise ValueError(
            f"Message too long: {len(secret)} chars, capacity {capacity} chars."
        )

    # Encode 32-bit length header (one bit per frame byte, 32 frame bytes)
    msg_len = len(secret)
    for i in range(32):
        bit = (msg_len >> (31 - i)) & 0x01
        frames[i] = (frames[i] & 0xFE) | bit

    # Encode each character bit by bit, starting at frame byte 32
    for i, ch in enumerate(secret):
        byte = ord(ch)
        for j in range(8):
            idx = 32 + i * 8 + j
            frames[idx] = (frames[idx] & 0xFE) | ((byte >> (7 - j)) & 0x01)

    out_aw = wave.open(output_path, mode="wb")
    out_aw.setparams(params)
    out_aw.writeframes(bytes(frames))
    out_aw.close()

def lsb_decode(audio_path: str) -> str:
    """Extract and return the hidden string from *audio_path*."""
    aw = wave.open(audio_path, mode="rb")
    frames = bytearray(aw.readframes(aw.getnframes()))
    aw.close()

    if len(frames) < 32:
        raise ValueError("Audio file too short to contain a hidden message.")

    # Read 32-bit length header (one LSB per frame byte)
    msg_len = 0
    for i in range(32):
        msg_len = (msg_len << 1) | (frames[i] & 0x01)

    max_capacity = (len(frames) - 32) // 8
    if msg_len <= 0 or msg_len > max_capacity:
        raise ValueError(
            f"No valid hidden message found (decoded length={msg_len}, "
            f"max capacity={max_capacity}). File may not be encoded."
        )

    # Extract message bits, starting at frame byte 32
    msg_chars = []
    for i in range(msg_len):
        byte = 0
        for j in range(8):
            idx = 32 + i * 8 + j
            byte = (byte << 1) | (frames[idx] & 0x01)
        # Guard against non-ASCII values (handles corrupt/wrong files)
        msg_chars.append(chr(byte) if byte < 128 else '?')

    return "".join(msg_chars)

# ──────────────────────────────────────────────────────────────────────────────
#  EMAIL HELPER
# ──────────────────────────────────────────────────────────────────────────────
SMTP_SERVER   = "smtp.gmail.com"
SMTP_PORT     = 587
SMTP_USER     = "contact2mr.krishna@gmail.com"
SMTP_PASSWORD = "kwkiackifcfftfpp"

def send_email(receiver: str, key: str, wav_path: str) -> None:
    msg = MIMEMultipart()
    msg["From"]    = SMTP_USER
    msg["To"]      = receiver
    msg["Subject"] = "[AudioSteg] Encoded Audio File & Decryption Key"

    body = (
        "Hello,\n\n"
        "Attached is the encoded audio file containing a hidden encrypted message.\n\n"
        f"Decryption Key:\n{key}\n\n"
        "Use the Advanced Audio Steganography tool to decode it.\n\n"
        "- Sent via Advanced Audio Steganography System"
    )
    msg.attach(MIMEText(body, "plain"))

    # Read WAV bytes and attach correctly
    with open(wav_path, "rb") as fh:
        wav_bytes = fh.read()
    audio_part = MIMEAudio(wav_bytes, _subtype="wav")
    audio_part.add_header(
        "Content-Disposition", "attachment",
        filename=os.path.basename(wav_path)
    )
    msg.attach(audio_part)

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    try:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
    finally:
        server.quit()

# ──────────────────────────────────────────────────────────────────────────────
#  REUSABLE UI WIDGETS
# ──────────────────────────────────────────────────────────────────────────────

def _styled_frame(parent, bg=BG_CARD, **kw):
    return tk.Frame(parent, bg=bg, **kw)

def _label(parent, text, font=FONT_BODY, fg=TEXT_MAIN, bg=BG_CARD, **kw):
    return tk.Label(parent, text=text, font=font, fg=fg, bg=bg, **kw)

def _entry(parent, textvariable=None, show=None, width=40):
    e = tk.Entry(
        parent, textvariable=textvariable, show=show, width=width,
        bg=BG_INPUT, fg=TEXT_MAIN, insertbackground=ACCENT,
        relief="flat", bd=0, highlightthickness=1,
        highlightcolor=ACCENT, highlightbackground=BORDER,
        font=FONT_BODY
    )
    return e

def _btn(parent, text, command, color=ACCENT, width=18):
    b = tk.Button(
        parent, text=text, command=command,
        bg=color, fg=BG_DARK, font=FONT_BTN,
        activebackground=TEXT_MAIN, activeforeground=BG_DARK,
        relief="flat", bd=0, cursor="hand2",
        padx=12, pady=6, width=width
    )
    def on_enter(e): b.config(bg=TEXT_MAIN)
    def on_leave(e): b.config(bg=color)
    b.bind("<Enter>", on_enter)
    b.bind("<Leave>", on_leave)
    return b

def _sep(parent, bg=BORDER):
    return tk.Frame(parent, bg=bg, height=1)

def _scrolled_text(parent, height=8, state="normal"):
    st = scrolledtext.ScrolledText(
        parent, height=height, bg=BG_INPUT, fg=TEXT_MAIN,
        insertbackground=ACCENT, font=FONT_CODE,
        relief="flat", bd=0, highlightthickness=1,
        highlightcolor=ACCENT, highlightbackground=BORDER,
        wrap="word", state=state
    )
    return st

def open_html_demo():
    html_code = """<!DOCTYPE html>
<html>
<head>
<title>Project Information - Audio Steganography</title>
<style>
    body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #ffffff; color: #333333; padding: 40px; margin: 0; }
    .container { max-width: 900px; margin: auto; padding: 20px; }
    .header-logo { text-align: right; margin-bottom: 20px; font-weight: bold; color: #ff3333; font-size: 24px; }
    .logo-sub { font-size: 12px; color: #777777; letter-spacing: 2px; }
    h1 { color: #000000; border-bottom: 0px; margin-bottom: 15px; font-size: 32px; }
    h2 { color: #000000; margin-top: 35px; border-bottom: 0px; font-size: 24px; }
    p.intro { line-height: 1.6; font-size: 16px; margin-bottom: 30px; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 15px; }
    th, td { border: 1px solid #dddddd; padding: 12px 16px; text-align: left; }
    th { background-color: #f5f5f5; font-weight: bold; color: #000000; }
    td { background-color: #ffffff; color: #333333; }
</style>
</head>
<body>
<div class="container">
    <div class="header-logo">SUPRAJA<br><span class="logo-sub">TECHNOLOGIES</span></div>
    
    <h1>Project Information</h1>
    <p class="intro">This project was developed by <b>Anonymous</b> as part of a <b>Cyber Security Intership</b>. This project is designed to <b>Secure the Organizations in Real-World from Cyber Frauds performed by Hackers</b>.</p>
    
    <table>
        <tr>
            <th style="width: 35%;">Project Details</th>
            <th>Value</th>
        </tr>
        <tr><td>Project Name</td><td>Audio Steganoraghy using LSB</td></tr>
        <tr><td>Project Description</td><td>Hiding Message with Encryption in Audio using LSB Algorithm</td></tr>
        <tr><td>Project Start Date</td><td>01-March-2026</td></tr>
        <tr><td>Project End Date</td><td>01-March-2026</td></tr>
        <tr><td>Project Status</td><td><b>Completed</b></td></tr>
    </table>

    <h2>Developer Details</h2>
    <table>
        <tr>
            <th style="width: 30%;">Name</th>
            <th style="width: 30%;">Employee ID</th>
            <th>Email</th>
        </tr>
        <tr>
            <td>B.Shashi Raju</td>
            <td>ST#IS#9041</td>
            <td>boorashashiraju@gmail.com</td>
        </tr>
    </table>

    <h2>Company Details</h2>
    <table>
        <tr>
            <th style="width: 35%;">Company</th>
            <th>Value</th>
        </tr>
        <tr>
            <td style="color: #bcbcbc;">Name</td>
            <td style="color: #bcbcbc;">Supraja Technologies</td>
        </tr>
        <tr>
            <td style="color: #bcbcbc;">Email</td>
            <td style="color: #bcbcbc;">contact@suprajatechnologies.com</td>
        </tr>
    </table>
</div>
</body>
</html>"""
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.html') as temp_file:
            temp_file.write(html_code)
            temp_file_path = temp_file.name
        webbrowser.open('file://' + os.path.realpath(temp_file_path))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open HTML file: {e}")

# ──────────────────────────────────────────────────────────────────────────────
#  MAIN APPLICATION
# ──────────────────────────────────────────────────────────────────────────────

class AudioStegApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("🔐  Advanced Audio Steganography")
        self.root.geometry("1100x700")
        self.root.minsize(950, 620)
        self.root.configure(bg=BG_DARK)
        self.root.resizable(True, True)

        # State vars - pre-declared to fix IDE warnings
        self.encode_output_path = tk.StringVar()
        self.encode_key         = tk.StringVar()
        self.last_hash          = tk.StringVar()
        self.enc_filepath       = tk.StringVar()
        self.enc_capacity_var   = tk.StringVar(value="Capacity: — (select a file)")
        self.enc_char_count     = tk.StringVar(value="Characters: 0")
        self.dec_filepath       = tk.StringVar()
        self.dec_hash_var       = tk.StringVar(value="SHA-256: —")
        self.dec_key_var        = tk.StringVar()
        self.email_sender       = tk.StringVar(value=SMTP_USER)
        self.email_smtp         = tk.StringVar(value=f"{SMTP_SERVER}:{SMTP_PORT}")
        self.email_receiver     = tk.StringVar()
        self.email_wav_path     = tk.StringVar()
        self.email_key_var      = tk.StringVar()
        self.email_status_var   = tk.StringVar(value="")
        self.log_status         = tk.StringVar(value="")
        
        from typing import Any
        self.sidebar: Any = None
        self._nav_buttons: dict = {}
        self.content: Any = None
        self._pages: dict = {}
        self.enc_msg_box: Any = None
        self.enc_status: Any = None
        self.dec_result: Any = None
        self.log_box: Any = None
        self.padlock_img: Any = None

        self._build_ui()
        self._nav_click("home")
        write_log("Application started.")

    # ──────────────────────────────────────────────────────────
    #  LAYOUT
    # ──────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Sidebar ──────────────────────────────────────────
        self.sidebar = tk.Frame(self.root, bg=BG_PANEL, width=200)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        tk.Label(
            self.sidebar, text="🔐 AudioSteg",
            font=("Consolas", 14, "bold"), fg=ACCENT, bg=BG_PANEL
        ).pack(pady=(20, 4))
        tk.Label(
            self.sidebar, text="LSB Steganography",
            font=FONT_SMALL, fg=TEXT_SUB, bg=BG_PANEL
        ).pack(pady=(0, 20))

        _sep(self.sidebar, bg=BORDER).pack(fill="x", padx=12, pady=4)

        self._nav_buttons = {}
        nav_items = [
            ("🏠", "home",   "Home"),
            ("🔒", "encode", "Encode"),
            ("🔓", "decode", "Decode"),
            ("📧", "email",  "Email"),
            ("📋", "logs",   "Logs"),
        ]
        for icon, key, label in nav_items:
            btn = tk.Button(
                self.sidebar, text=f" {icon}  {label}",
                font=FONT_BODY, fg=TEXT_MAIN, bg=BG_PANEL,
                activebackground=BG_CARD, activeforeground=ACCENT,
                relief="flat", bd=0, anchor="w", padx=18, pady=10,
                cursor="hand2",
                command=lambda k=key: self._nav_click(k)  # type: ignore
            )
            btn.pack(fill="x", pady=1)
            self._nav_buttons[key] = btn

        # Bottom info
        tk.Label(
            self.sidebar, text="v2.0 Enhanced",
            font=FONT_SMALL, fg=TEXT_SUB, bg=BG_PANEL
        ).pack(side="bottom", pady=10)

        # ── Main content area ────────────────────────────────
        self.content = tk.Frame(self.root, bg=BG_DARK)
        self.content.pack(side="left", fill="both", expand=True)

        # Build all pages (hidden by default)
        self._pages = {}
        self._build_home()
        self._build_encode()
        self._build_decode()
        self._build_email()
        self._build_logs()

    def _nav_click(self, key: str):
        for k, b in self._nav_buttons.items():
            if k == key:
                b.config(fg=ACCENT, bg=BG_CARD)
            else:
                b.config(fg=TEXT_MAIN, bg=BG_PANEL)

        for k, page in self._pages.items():
            page.pack_forget()
        self._pages[key].pack(fill="both", expand=True, padx=24, pady=20)

        if key == "logs":
            self._refresh_logs()

    # ──────────────────────────────────────────────────────────
    #  PAGE: HOME
    # ──────────────────────────────────────────────────────────
    def _build_home(self):
        p = _styled_frame(self.content, bg=BG_DARK)
        self._pages["home"] = p

        # Header Frame
        header_f = tk.Frame(p, bg=BG_DARK)
        header_f.pack(fill="x", anchor="w", pady=(0, 4))
        
        tk.Label(
            header_f, text="Advanced Audio Steganography",
            font=FONT_TITLE, fg=ACCENT, bg=BG_DARK
        ).pack(side="left")
        
        # ADDED HTML DEMO BUTTON HERE
        tk.Button(
            header_f, text="📋 Project Info", font=("Arial", 11, "bold"),
            bg="#ef4444", fg="#ffffff", relief="flat", cursor="hand2",
            padx=12, pady=4, command=open_html_demo
        ).pack(side="right")

        tk.Label(
            p, text="Hide encrypted secret messages inside WAV audio files using LSB technique.",
            font=FONT_BODY, fg=TEXT_SUB, bg=BG_DARK
        ).pack(anchor="w", pady=(0, 18))

        _sep(p, bg=BORDER).pack(fill="x", pady=(0, 18))

        # Workflow card
        flow_card = _styled_frame(p, bg=BG_CARD)
        flow_card.pack(fill="x", pady=(0, 16), ipady=16, ipadx=16)

        _label(flow_card, "  📊  Processing Workflow", font=FONT_HEADER,
               fg=ACCENT, bg=BG_CARD).pack(anchor="w", padx=16, pady=(12, 8))

        flow_steps = [
            ("1", "Convert Message to Binary",    "Text → ASCII bytes → bit stream"),
            ("2", "Encrypt with Fernet (AES-128)", "Symmetric key generated automatically"),
            ("3", "Embed into Audio Samples",      "Modify LSB of each audio frame byte"),
            ("4", "Generate Encoded WAV File",     "Saved to Output/ folder"),
            ("5", "Receiver Extracts LSB Bits",    "Reads embedded bit stream"),
            ("6", "Decrypt with Key",              "Fernet decryption restores plaintext"),
        ]
        for num, title, desc in flow_steps:
            row = _styled_frame(flow_card, bg=BG_CARD)
            row.pack(fill="x", padx=20, pady=3)

            tk.Label(row, text=f" ◈ {num}  ", font=("Consolas", 10, "bold"),
                     fg=ACCENT2, bg=BG_CARD).pack(side="left")
            tk.Label(row, text=f"{title:<35}", font=("Consolas", 10, "bold"),
                     fg=TEXT_MAIN, bg=BG_CARD).pack(side="left")
            tk.Label(row, text=desc, font=FONT_SMALL,
                     fg=TEXT_SUB, bg=BG_CARD).pack(side="left")

        # Feature badges
        badges_frame = _styled_frame(p, bg=BG_DARK)
        badges_frame.pack(fill="x", pady=6)
        _label(badges_frame, "  ✦  Key Features", font=FONT_HEADER,
               fg=ACCENT, bg=BG_DARK).pack(anchor="w", pady=(0, 10))

        badges = [
            ("🔐", "AES-128 Fernet\nEncryption",   ACCENT),
            ("🎵", "WAV LSB\nSteganography",         ACCENT2),
            ("📧", "Secure Gmail\nDelivery",          SUCCESS),
            ("🛡️", "SHA-256 File\nIntegrity",         WARNING),
            ("📋", "Activity\nLogging",               "#64748b"),
            ("📄", "Automated\nReports",              "#ec4899"),
        ]
        row = _styled_frame(badges_frame, bg=BG_DARK)
        row.pack(fill="x")
        for icon, text, color in badges:
            card = tk.Frame(row, bg=BG_CARD, relief="flat",
                            highlightthickness=1, highlightbackground=color)
            card.pack(side="left", padx=6, pady=4, ipadx=10, ipady=8)
            tk.Label(card, text=icon, font=("Consolas", 20), bg=BG_CARD).pack()
            tk.Label(card, text=text, font=FONT_SMALL, fg=TEXT_MAIN, bg=BG_CARD,
                     justify="center").pack()

    # ──────────────────────────────────────────────────────────
    #  PAGE: ENCODE
    # ──────────────────────────────────────────────────────────
    def _build_encode(self):
        p = _styled_frame(self.content, bg=BG_DARK)
        self._pages["encode"] = p

        tk.Label(p, text="🔒  Encode Message into Audio",
                 font=FONT_TITLE, fg=ACCENT, bg=BG_DARK).pack(anchor="w", pady=(0, 4))
        tk.Label(p, text="Select a WAV file, type your secret message, and generate an encoded output.",
                 font=FONT_BODY, fg=TEXT_SUB, bg=BG_DARK).pack(anchor="w", pady=(0, 14))
        _sep(p, bg=BORDER).pack(fill="x", pady=(0, 16))

        # Two-column layout
        cols = _styled_frame(p, bg=BG_DARK)
        cols.pack(fill="both", expand=True)

        left  = _styled_frame(cols, bg=BG_CARD)
        right = _styled_frame(cols, bg=BG_CARD)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8), pady=0, ipady=16)
        right.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=0, ipady=16)

        # ── Left: Input controls ──────────────────────────────
        _label(left, "  ① Select Input WAV File", font=FONT_HEADER,
               fg=ACCENT, bg=BG_CARD).pack(anchor="w", padx=16, pady=(12, 6))

        file_row = _styled_frame(left, bg=BG_CARD)
        file_row.pack(fill="x", padx=16)

        enc_entry = _entry(file_row, textvariable=self.enc_filepath, width=32)
        enc_entry.pack(side="left", fill="x", expand=True, ipady=5)
        _btn(file_row, "📂 Browse", self._enc_browse, color=ACCENT2, width=10
             ).pack(side="left", padx=(8, 0))

        # Capacity
        tk.Label(left, textvariable=self.enc_capacity_var,
                 font=FONT_SMALL, fg=SUCCESS, bg=BG_CARD).pack(anchor="w", padx=18, pady=4)

        _sep(left, bg=BORDER).pack(fill="x", padx=16, pady=10)

        _label(left, "  ② Enter Secret Message", font=FONT_HEADER,
               fg=ACCENT, bg=BG_CARD).pack(anchor="w", padx=16, pady=(0, 6))
        self.enc_msg_box = _scrolled_text(left, height=7)
        self.enc_msg_box.pack(fill="x", padx=16)
        self.enc_msg_box.bind("<KeyRelease>", self._enc_update_count)

        tk.Label(left, textvariable=self.enc_char_count,
                 font=FONT_SMALL, fg=TEXT_SUB, bg=BG_CARD).pack(anchor="e", padx=18, pady=2)

        _sep(left, bg=BORDER).pack(fill="x", padx=16, pady=10)

        _btn(left, "🔒  Encode & Save", self._encode_action, color=ACCENT, width=22
             ).pack(padx=16, pady=8, anchor="w")

        # ── Right: Results ────────────────────────────────────
        _label(right, "  ③ Encoding Results", font=FONT_HEADER,
               fg=ACCENT, bg=BG_CARD).pack(anchor="w", padx=16, pady=(12, 8))

        def _result_row(lbl, var, copy_cmd=None):
            row = _styled_frame(right, bg=BG_CARD)
            row.pack(fill="x", padx=16, pady=4)
            tk.Label(row, text=lbl, font=FONT_SMALL, fg=TEXT_SUB,
                     bg=BG_CARD, width=16, anchor="w").pack(side="left")
            e = tk.Entry(row, textvariable=var, font=FONT_CODE,
                         bg=BG_INPUT, fg=ACCENT, relief="flat", bd=0,
                         highlightthickness=1, highlightbackground=BORDER,
                         state="readonly", readonlybackground=BG_INPUT)
            e.pack(side="left", fill="x", expand=True, ipady=4)
            if copy_cmd:
                _btn(row, "📋", copy_cmd, color=BG_CARD, width=2).pack(side="left", padx=4)

        _result_row("Output File:", self.encode_output_path, self._copy_output_path)
        _result_row("Fernet Key:", self.encode_key, self._copy_key)
        _result_row("SHA-256 Hash:", self.last_hash)

        _sep(right, bg=BORDER).pack(fill="x", padx=16, pady=12)

        _label(right, "  ④ Status", font=FONT_HEADER,
               fg=ACCENT, bg=BG_CARD).pack(anchor="w", padx=16, pady=(0, 6))
        self.enc_status = _scrolled_text(right, height=6, state="disabled")
        self.enc_status.pack(fill="both", expand=True, padx=16)

    def _enc_browse(self):
        path = filedialog.askopenfilename(
            title="Select WAV file",
            filetypes=[("WAV Audio", "*.wav"), ("All Files", "*.*")]
        )
        if path:
            self.enc_filepath.set(path)
            cap = estimate_capacity(path)
            self.enc_capacity_var.set(
                f"Capacity: {cap:,} characters  ({cap:,} bytes)"
            )

    def _enc_update_count(self, event=None):
        n = len(self.enc_msg_box.get("1.0", "end-1c"))
        self.enc_char_count.set(f"Characters: {n:,}")

    def _encode_action(self):
        audio_path = self.enc_filepath.get().strip()
        message    = self.enc_msg_box.get("1.0", "end-1c").strip()

        if not audio_path:
            messagebox.showerror("Error", "Please select a WAV file.")
            return
        if not os.path.exists(audio_path):
            messagebox.showerror("Error", "Selected file does not exist.")
            return
        if not message:
            messagebox.showerror("Error", "Please enter a secret message.")
            return

        threading.Thread(target=self._do_encode, args=(audio_path, message), daemon=True).start()

    def _do_encode(self, audio_path: str, message: str):
        self._enc_log("⏳ Starting encode …")
        try:
            # Generate key and encrypt
            key = Fernet.generate_key()
            f   = Fernet(key)
            cipher_text = f.encrypt(message.encode()).decode()

            # Output path
            file_name   = os.path.basename(audio_path)
            output_path = os.path.join("Output", file_name)

            # Embed
            lsb_encode(audio_path, output_path, cipher_text)

            # Hash
            digest = sha256_file(output_path)

            # Update state vars (thread-safe via after)
            self.root.after(0, lambda: self.encode_output_path.set(os.path.abspath(output_path)))  # type: ignore
            self.root.after(0, lambda: self.encode_key.set(key.decode()))  # type: ignore
            short_digest = str(digest)[0:48] + '…'  # type: ignore
            self.root.after(0, lambda m=short_digest: self.last_hash.set(m))  # type: ignore

            digest_16 = str(digest)[0:16]  # type: ignore
            write_log(f"ENCODE | input={audio_path} | output={output_path} | sha256={digest_16}…")

            self._enc_log(f"✅ Encoded successfully!")
            self._enc_log(f"   Output : {output_path}")
            self._enc_log(f"   Key    : {key.decode()[:32]}…")
            digest_32 = str(digest)[0:32]  # type: ignore\n            self._enc_log(f"   SHA-256: {digest_32}…")  # type: ignore
            self.root.after(0, lambda: messagebox.showinfo(
                "Success",
                f"Message encoded and saved to:\n{output_path}\n\n"
                f"🔑 Key has been copied to the results panel.\n"
                f"Share the key and audio file with the receiver."
            ))  # type: ignore
        except Exception as ex:
            err_msg = str(ex)
            self._enc_log(f"❌ Error: {err_msg}")
            self.root.after(0, lambda m=err_msg: messagebox.showerror("Encode Error", m))  # type: ignore

    def _enc_log(self, msg: str):
        def _do():
            self.enc_status.config(state="normal")
            self.enc_status.insert("end", msg + "\n")
            self.enc_status.see("end")
            self.enc_status.config(state="disabled")
        self.root.after(0, _do)  # type: ignore

    def _copy_output_path(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.encode_output_path.get())

    def _copy_key(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.encode_key.get())

    # ──────────────────────────────────────────────────────────
    #  PAGE: DECODE
    # ──────────────────────────────────────────────────────────
    def _build_decode(self):
        p = _styled_frame(self.content, bg=BG_DARK)
        self._pages["decode"] = p

        tk.Label(p, text="🔓  Decode Message from Audio",
                 font=FONT_TITLE, fg=ACCENT, bg=BG_DARK).pack(anchor="w", pady=(0, 4))
        tk.Label(p, text="Select an encoded WAV file and provide the Fernet key to reveal the hidden message.",
                 font=FONT_BODY, fg=TEXT_SUB, bg=BG_DARK).pack(anchor="w", pady=(0, 14))
        _sep(p, bg=BORDER).pack(fill="x", pady=(0, 16))

        card = _styled_frame(p, bg=BG_CARD)
        card.pack(fill="both", expand=True, ipady=16)

        # File picker
        _label(card, "  ① Select Encoded WAV File", font=FONT_HEADER,
               fg=ACCENT, bg=BG_CARD).pack(anchor="w", padx=16, pady=(12, 6))

        fr = _styled_frame(card, bg=BG_CARD)
        fr.pack(fill="x", padx=16)
        _entry(fr, textvariable=self.dec_filepath, width=50).pack(
            side="left", fill="x", expand=True, ipady=5)
        _btn(fr, "📂 Browse", self._dec_browse, color=ACCENT2, width=10
             ).pack(side="left", padx=(8, 0))

        tk.Label(card, textvariable=self.dec_hash_var,
                 font=FONT_SMALL, fg=TEXT_SUB, bg=BG_CARD).pack(anchor="w", padx=18, pady=4)

        _sep(card, bg=BORDER).pack(fill="x", padx=16, pady=10)

        # Key entry
        _label(card, "  ② Paste Fernet Decryption Key", font=FONT_HEADER,
               fg=ACCENT, bg=BG_CARD).pack(anchor="w", padx=16, pady=(0, 6))

        key_row = _styled_frame(card, bg=BG_CARD)
        key_row.pack(fill="x", padx=16)
        _entry(key_row, textvariable=self.dec_key_var, width=58).pack(
            side="left", fill="x", expand=True, ipady=5)

        # Paste from clipboard
        def _paste_key():
            try:
                self.dec_key_var.set(self.root.clipboard_get())
            except Exception:
                pass
        _btn(key_row, "📋 Paste", _paste_key, color=BG_CARD, width=8
             ).pack(side="left", padx=(8, 0))

        _sep(card, bg=BORDER).pack(fill="x", padx=16, pady=10)

        _btn(card, "🔓  Decode & Reveal", self._decode_action, color=SUCCESS, width=22
             ).pack(padx=16, pady=4, anchor="w")

        _sep(card, bg=BORDER).pack(fill="x", padx=16, pady=10)

        # Result
        _label(card, "  ③ Revealed Secret Message", font=FONT_HEADER,
               fg=ACCENT, bg=BG_CARD).pack(anchor="w", padx=16, pady=(0, 6))
        self.dec_result = _scrolled_text(card, height=8, state="disabled")
        self.dec_result.pack(fill="both", expand=True, padx=16, pady=(0, 16))

    def _dec_browse(self):
        path = filedialog.askopenfilename(
            title="Select encoded WAV file",
            filetypes=[("WAV Audio", "*.wav"), ("All Files", "*.*")]
        )
        if path:
            self.dec_filepath.set(path)
            digest = sha256_file(path)
            digest_48 = str(digest)[0:48]  # type: ignore\n            self.dec_hash_var.set(f"SHA-256: {digest_48}…")  # type: ignore

    def _decode_action(self):
        file_path = self.dec_filepath.get().strip()
        key_str   = self.dec_key_var.get().strip()

        if not file_path:
            messagebox.showerror("Error", "Please select a WAV file.")
            return
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File not found.")
            return
        if not key_str:
            messagebox.showerror("Error", "Please enter the Fernet key.")
            return

        threading.Thread(target=self._do_decode, args=(file_path, key_str), daemon=True).start()

    def _do_decode(self, file_path: str, key_str: str):
        try:
            raw  = lsb_decode(file_path)
            key  = key_str.encode()
            f    = Fernet(key)
            msg  = f.decrypt(raw.encode()).decode()
            write_log(f"DECODE | file={file_path} | success=True")
            self.root.after(0, lambda: self._dec_show_result(msg))  # type: ignore
        except InvalidToken:
            write_log(f"DECODE | file={file_path} | success=False | reason=InvalidToken")
            self.root.after(0, lambda: messagebox.showerror(
                "Decode Error",
                "Invalid Key!\nThe provided Fernet key cannot decrypt this message.\n"
                "Make sure you copied the full key from the Encode tab."))  # type: ignore
        except Exception as ex:
            err_msg = str(ex)
            write_log(f"DECODE | file={file_path} | success=False | reason={err_msg}")
            self.root.after(0, lambda m=err_msg: messagebox.showerror("Decode Error", m))  # type: ignore

    def _dec_show_result(self, msg: str):
        self.dec_result.config(state="normal")
        self.dec_result.delete("1.0", "end")
        self.dec_result.insert("end", msg)
        self.dec_result.config(state="disabled")
        messagebox.showinfo("🔓 Decoded!", "Secret message revealed successfully!")

    # ──────────────────────────────────────────────────────────
    #  PAGE: EMAIL
    # ──────────────────────────────────────────────────────────
    def _build_email(self):
        p = _styled_frame(self.content, bg=BG_DARK)
        self._pages["email"] = p

        tk.Label(p, text="📧  Send Encoded Audio via Email",
                 font=FONT_TITLE, fg=ACCENT, bg=BG_DARK).pack(anchor="w", pady=(0, 4))
        tk.Label(p, text="Send the encoded WAV file and Fernet key to the receiver's email securely.",
                 font=FONT_BODY, fg=TEXT_SUB, bg=BG_DARK).pack(anchor="w", pady=(0, 14))
        _sep(p, bg=BORDER).pack(fill="x", pady=(0, 16))

        card = _styled_frame(p, bg=BG_CARD)
        card.pack(fill="both", expand=True, ipady=16)

        def labeled_entry(lbl, var, placeholder="", readonly=False):
            row = _styled_frame(card, bg=BG_CARD)
            row.pack(fill="x", padx=16, pady=5)
            tk.Label(row, text=lbl, font=FONT_SMALL, fg=TEXT_SUB,
                     bg=BG_CARD, width=20, anchor="w").pack(side="left")
            e = _entry(row, textvariable=var, width=50)
            if readonly:
                e.config(state="readonly", readonlybackground=BG_INPUT)
            e.pack(side="left", fill="x", expand=True, ipady=5)

        _label(card, "  SMTP Configuration", font=FONT_HEADER,
               fg=ACCENT, bg=BG_CARD).pack(anchor="w", padx=16, pady=(12, 10))

        labeled_entry("Sender (From):", self.email_sender, readonly=True)
        labeled_entry("SMTP Server:",   self.email_smtp,   readonly=True)

        _sep(card, bg=BORDER).pack(fill="x", padx=16, pady=10)

        _label(card, "  Message Details", font=FONT_HEADER,
               fg=ACCENT, bg=BG_CARD).pack(anchor="w", padx=16, pady=(0, 10))

        labeled_entry("Receiver (To):", self.email_receiver)

        # WAV path (auto-filled from encode)
        wav_row = _styled_frame(card, bg=BG_CARD)
        wav_row.pack(fill="x", padx=16, pady=5)
        tk.Label(wav_row, text="Encoded WAV File:", font=FONT_SMALL, fg=TEXT_SUB,
                 bg=BG_CARD, width=20, anchor="w").pack(side="left")
        _entry(wav_row, textvariable=self.email_wav_path, width=38).pack(
            side="left", fill="x", expand=True, ipady=5)
        _btn(wav_row, "🔗 From Encode", self._email_fill_from_encode,
             color=ACCENT2, width=14).pack(side="left", padx=(8, 0))
        _btn(wav_row, "📂 Browse", self._email_browse_wav,
             color=ACCENT2, width=10).pack(side="left", padx=(4, 0))

        # Key
        key_row = _styled_frame(card, bg=BG_CARD)
        key_row.pack(fill="x", padx=16, pady=5)
        tk.Label(key_row, text="Fernet Key:", font=FONT_SMALL, fg=TEXT_SUB,
                 bg=BG_CARD, width=20, anchor="w").pack(side="left")
        _entry(key_row, textvariable=self.email_key_var, width=38).pack(
            side="left", fill="x", expand=True, ipady=5)
        _btn(key_row, "🔗 From Encode", self._email_fill_key_from_encode,
             color=ACCENT2, width=14).pack(side="left", padx=(8, 0))

        _sep(card, bg=BORDER).pack(fill="x", padx=16, pady=12)

        send_row = _styled_frame(card, bg=BG_CARD)
        send_row.pack(fill="x", padx=16)
        _btn(send_row, "📧  Send Email", self._send_email_action, color=SUCCESS, width=20
             ).pack(side="left")
        tk.Label(send_row, textvariable=self.email_status_var,
                 font=FONT_BODY, fg=TEXT_SUB, bg=BG_CARD).pack(side="left", padx=14)

        _sep(card, bg=BORDER).pack(fill="x", padx=16, pady=12)

        # Info box
        info = _styled_frame(card, bg=BG_INPUT)
        info.pack(fill="x", padx=16, pady=(0, 16))
        lines = [
            "  ℹ️  SMTP Setup Requirements:",
            "  • Gmail account with 2-Step Verification enabled",
            "  • App Password generated from Google Account → Security",
            "  • 16-character App Password saved (shown only once)",
            f"  • Preconfigured sender: {SMTP_USER}",
        ]
        for ln in lines:
            tk.Label(info, text=ln, font=FONT_SMALL, fg=TEXT_SUB,
                     bg=BG_INPUT, anchor="w").pack(fill="x", padx=8, pady=1)

    def _email_fill_from_encode(self):
        self.email_wav_path.set(self.encode_output_path.get())

    def _email_fill_key_from_encode(self):
        self.email_key_var.set(self.encode_key.get())

    def _email_browse_wav(self):
        path = filedialog.askopenfilename(
            title="Select encoded WAV", filetypes=[("WAV Audio", "*.wav")])
        if path:
            self.email_wav_path.set(path)

    def _send_email_action(self):
        receiver = self.email_receiver.get().strip()
        wav_path = self.email_wav_path.get().strip()
        key      = self.email_key_var.get().strip()

        if not re.match(r"[^@]+@[^@]+\.[^@]+", receiver):
            messagebox.showerror("Error", "Invalid receiver email address.")
            return
        if not wav_path or not os.path.exists(wav_path):
            messagebox.showerror("Error", "Please provide a valid encoded WAV file path.")
            return
        if not key:
            messagebox.showerror("Error", "Please provide the Fernet key.")
            return

        self.email_status_var.set("⏳ Sending …")
        threading.Thread(
            target=self._do_send_email,
            args=(receiver, wav_path, key), daemon=True
        ).start()

    def _do_send_email(self, receiver: str, wav_path: str, key: str):
        try:
            send_email(receiver, key, wav_path)
            write_log(f"EMAIL | to={receiver} | wav={wav_path}")
            self.root.after(0, lambda: self.email_status_var.set(""))  # type: ignore
            self.root.after(0, lambda: messagebox.showinfo(
                "Email Sent",
                f"✅ Email sent successfully to:\n{receiver}\n\n"
                "The receiver got the encoded WAV file + decryption key."
            ))  # type: ignore
        except Exception as ex:
            err_msg = str(ex)
            write_log(f"EMAIL | to={receiver} | error={err_msg}")
            self.root.after(0, lambda: self.email_status_var.set(""))  # type: ignore
            self.root.after(0, lambda m=err_msg: messagebox.showerror("Email Error", m))  # type: ignore

    # ──────────────────────────────────────────────────────────
    #  PAGE: LOGS
    # ──────────────────────────────────────────────────────────
    def _build_logs(self):
        p = _styled_frame(self.content, bg=BG_DARK)
        self._pages["logs"] = p

        tk.Label(p, text="📋  Activity Logs & Reports",
                 font=FONT_TITLE, fg=ACCENT, bg=BG_DARK).pack(anchor="w", pady=(0, 4))
        tk.Label(p, text="Full audit trail of all encode, decode, and email operations.",
                 font=FONT_BODY, fg=TEXT_SUB, bg=BG_DARK).pack(anchor="w", pady=(0, 14))
        _sep(p, bg=BORDER).pack(fill="x", pady=(0, 16))

        toolbar = _styled_frame(p, bg=BG_DARK)
        toolbar.pack(fill="x", pady=(0, 10))
        _btn(toolbar, "🔄 Refresh",         self._refresh_logs,   color=ACCENT,  width=14).pack(side="left", padx=(0, 8))
        _btn(toolbar, "📄 Generate Report", self._gen_report,     color=WARNING, width=18).pack(side="left", padx=(0, 8))
        _btn(toolbar, "🗑️ Clear Logs",      self._clear_logs,     color=ERROR,   width=14).pack(side="left")

        self.log_box = _scrolled_text(p, height=22, state="disabled")
        self.log_box.pack(fill="both", expand=True)

        tk.Label(p, textvariable=self.log_status,
                 font=FONT_SMALL, fg=SUCCESS, bg=BG_DARK).pack(anchor="w", pady=4)

    def _refresh_logs(self):
        self.log_box.config(state="normal")
        self.log_box.delete("1.0", "end")
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8") as fh:
                content = fh.read()
            self.log_box.insert("end", content if content else "(No log entries yet)")
        else:
            self.log_box.insert("end", "(No log file found)")
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def _gen_report(self):
        if not os.path.exists(LOG_FILE):
            messagebox.showwarning("No Logs", "No activity log found to generate a report.")
            return

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(LOG_DIR, f"report_{ts}.txt")

        with open(LOG_FILE, "r", encoding="utf-8") as fh:
            log_content = fh.read()

        report = (
            "=" * 70 + "\n"
            "       ADVANCED AUDIO STEGANOGRAPHY — ACTIVITY REPORT\n"
            "=" * 70 + "\n"
            f"Generated : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Log File  : {os.path.abspath(LOG_FILE)}\n"
            "=" * 70 + "\n\n"
            + log_content + "\n"
            "=" * 70 + "\n"
            "END OF REPORT\n"
        )

        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(report)

        write_log(f"REPORT | generated={report_path}")
        self._refresh_logs()
        self.log_status.set(f"✅ Report saved: {report_path}")
        messagebox.showinfo("Report Generated", f"Report saved to:\n{report_path}")

    def _clear_logs(self):
        if not messagebox.askyesno("Clear Logs", "Are you sure you want to clear all logs?"):
            return
        with open(LOG_FILE, "w", encoding="utf-8") as fh:
            fh.write("")
        write_log("Logs cleared by user.")
        self._refresh_logs()
        self.log_status.set("🗑️ Logs cleared.")


# ──────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    app  = AudioStegApp(root)
    root.mainloop()
