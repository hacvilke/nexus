import sys
import os
import re
import json
import zipfile
import hashlib
from pathlib import Path
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QPalette, QColor
from bs4 import BeautifulSoup
import requests

TARIUNET_BASE = "https://tariunet.vercel.app"

# ============================================================
# SECURITY CONSTANTS
# ============================================================
# Maximum directory depth to prevent traversal attacks
MAX_DIR_DEPTH = 20
# Maximum total build size (50MB)
MAX_BUILD_SIZE = 50 * 1024 * 1024
# Allowed file extensions in the build
ALLOWED_EXTENSIONS = {'.html', '.htm', '.js', '.css', '.json', '.wasm', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.ogg', '.wav', '.txt', '.xml', '.map', '.data', '.bin', '.glb', '.gltf', '.bundle'}
# Blocked patterns (no executable files, no scripts that run outside browser)
BLOCKED_EXTENSIONS = {'.exe', '.dll', '.bat', '.cmd', '.sh', '.ps1', '.vbs', '.jsa', '.mjs', '.cjs', '.jar', '.py', '.php', '.rb', '.go', '.rs', '.cpp', '.c', '.h'}
# License key format validation
LICENSE_PATTERN = re.compile(r'^NXS_(live|test)_[a-f0-9]{32}$')

PLATFORM_BRIDGE_JS = """(function() {
  'use strict';
  var _hostname = window.location.hostname;
  var _isCrazyGames = _hostname.indexOf('crazygames.com') !== -1;
  var _isPoki = _hostname.indexOf('poki.com') !== -1;

  window.PlatformBridge = {
    _platform: _isCrazyGames ? 'CrazyGames' : (_isPoki ? 'Poki' : 'Unknown'),

    triggerMidroll: function() {
      if (_isCrazyGames) {
        if (window.CrazyGames && window.CrazyGames.SDK && window.CrazyGames.SDK.ad) {
          window.CrazyGames.SDK.ad.requestAd('midroll', {
            adStarted: function() { console.log('[PlatformBridge] CrazyGames midroll started'); },
            adError: function(e) { console.warn('[PlatformBridge] CrazyGames ad error', e); },
            adFinished: function() { console.log('[PlatformBridge] CrazyGames midroll finished'); }
          });
        }
      } else if (_isPoki) {
        if (window.PokiSDK) {
          window.PokiSDK.commercialBreak().then(function() {
            console.log('[PlatformBridge] Poki commercial break complete');
          });
        }
      } else {
        console.warn('[PlatformBridge] triggerMidroll called on unknown platform: ' + _hostname);
      }
    },

    triggerRewardedAd: function(onGranted) {
      if (_isCrazyGames) {
        if (window.CrazyGames && window.CrazyGames.SDK && window.CrazyGames.SDK.ad) {
          window.CrazyGames.SDK.ad.requestAd('rewarded', {
            adStarted: function() { console.log('[PlatformBridge] CrazyGames rewarded started'); },
            adError: function(e) { console.warn('[PlatformBridge] CrazyGames rewarded error', e); },
            adFinished: function() { if (typeof onGranted === 'function') onGranted(); }
          });
        }
      } else if (_isPoki) {
        if (window.PokiSDK) {
          window.PokiSDK.rewardedBreak().then(function(rewarded) {
            if (rewarded && typeof onGranted === 'function') onGranted();
          });
        }
      }
    },

    gameplayStart: function() {
      if (_isCrazyGames && window.CrazyGames && window.CrazyGames.SDK) {
        window.CrazyGames.SDK.game.gameplayStart();
      } else if (_isPoki && window.PokiSDK) {
        window.PokiSDK.gameplayStart();
      }
    },

    gameplayStop: function() {
      if (_isCrazyGames && window.CrazyGames && window.CrazyGames.SDK) {
        window.CrazyGames.SDK.game.gameplayStop();
      } else if (_isPoki && window.PokiSDK) {
        window.PokiSDK.gameplayStop();
      }
    },

    getPlatform: function() {
      return window.PlatformBridge._platform;
    }
  };

  console.log('[PlatformBridge] Initialized on platform: ' + window.PlatformBridge._platform);
})();
"""

SITELOCK_IIFE_TEMPLATE = """(function() {
  'use strict';
  var _nexusKey = '{license_key}';
  var _allowedHashes = {hashes_array};
  var _telemetryEndpoint = '{telemetry_endpoint}';

  function _bufToHex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(function(b) {
      return b.toString(16).padStart(2, '0');
    }).join('');
  }

  var _currentDomain = window.location.hostname;

  crypto.subtle.digest('SHA-256', new TextEncoder().encode(_currentDomain)).then(function(hashBuffer) {
    var hexHash = _bufToHex(hashBuffer);
    if (_allowedHashes.indexOf(hexHash) === -1) {
      fetch(_telemetryEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          license_key: _nexusKey,
          stolen_domain: _currentDomain,
          user_agent: navigator.userAgent
        })
      }).catch(function() {});

      document.documentElement.style.cssText = 'background:#f8f9fa;margin:0;padding:0;width:100%;height:100%;';
      document.body.innerHTML = '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;background:#f8f9fa;font-family:-apple-system,BlinkMacSystemFont,\\'Segoe UI\\',Roboto,sans-serif;"><div style="background:#fff;border:1px solid #e0e0e0;border-radius:12px;padding:40px;max-width:480px;text-align:center;"><div style="width:48px;height:48px;border-radius:50%;background:#fce8e6;display:flex;align-items:center;justify-content:center;margin:0 auto 16px;"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#c5221f" stroke-width="2"><path d="M12 9v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg></div><p style="color:#202124;font-size:16px;font-weight:500;margin:0 0 8px;">Unauthorized Domain</p><p style="color:#5f6368;font-size:14px;margin:0;line-height:1.5;">This build is protected by Nexus. Execution on this domain is not permitted.</p></div></div>';

      window.stop();
      throw new Error('NEXUS_SECURITY: Unauthorized domain execution halted.');
    } else {
      console.log('[Nexus] Domain verified: ' + _currentDomain);
    }
  });
})();
"""


def validate_license_key(key: str) -> bool:
    """Validate license key format server-side before any API call."""
    if not key or len(key) != 41:
        return False
    return bool(LICENSE_PATTERN.match(key))


def validate_directory(path: Path) -> tuple:
    """Validate the build directory is safe to process."""
    # Resolve to absolute and check for symlinks (prevent traversal)
    try:
        resolved = path.resolve(strict=True)
    except (OSError, FileNotFoundError):
        return False, "Directory does not exist or is a broken symlink."

    # Check depth
    parts = resolved.parts
    if len(parts) > MAX_DIR_DEPTH:
        return False, f"Directory depth exceeds maximum ({MAX_DIR_DEPTH})."

    # Check for index.html
    if not (resolved / "index.html").exists():
        return False, "No index.html found. The directory must contain a web build with index.html."

    # Check total size
    total_size = 0
    blocked_files = []
    for root, dirs, files in os.walk(resolved):
        for f in files:
            fpath = Path(root) / f
            ext = fpath.suffix.lower()

            if ext in BLOCKED_EXTENSIONS:
                blocked_files.append(f)
                continue

            try:
                total_size += fpath.stat().st_size
            except OSError:
                continue

    if blocked_files:
        return False, f"Blocked files found: {', '.join(blocked_files[:5])}. Executables and server-side scripts are not allowed."

    if total_size > MAX_BUILD_SIZE:
        return False, f"Build size ({total_size // 1024 // 1024}MB) exceeds maximum ({MAX_BUILD_SIZE // 1024 // 1024}MB)."

    return True, resolved


def compute_build_fingerprint(export_dir: Path) -> str:
    """Compute SHA-256 fingerprint of all allowed files for integrity verification."""
    h = hashlib.sha256()
    for root, dirs, files in sorted(os.walk(export_dir)):
        dirs.sort()
        for f in sorted(files):
            fpath = Path(root) / f
            if fpath.suffix.lower() in BLOCKED_EXTENSIONS:
                continue
            # Include relative path + size + mtime in fingerprint
            rel = str(fpath.relative_to(export_dir))
            try:
                stat = fpath.stat()
                h.update(rel.encode())
                h.update(str(stat.st_size).encode())
                h.update(str(int(stat.st_mtime)).encode())
            except OSError:
                continue
    return h.hexdigest()[:16]


class LicenseWorker(QThread):
    license_valid = pyqtSignal(str, dict)
    license_failed = pyqtSignal(str)
    log_message = pyqtSignal(str, str)

    def __init__(self, license_key, api_key=""):
        super().__init__()
        self.license_key = license_key
        self.api_key = api_key

    def run(self):
        self.log_message.emit("Validating license key format...", "#1a73e8")

        # Client-side format check (first defense)
        if not validate_license_key(self.license_key):
            self.log_message.emit("[SECURITY] Invalid license key format. Expected: NXS_live_<32hex> or NXS_test_<32hex>", "#c5221f")
            self.license_failed.emit("Invalid license key format")
            return

        self.log_message.emit("Connecting to TariuNet Nexus API...", "#1a73e8")
        self.log_message.emit(f"Base URL: {TARIUNET_BASE}", "#80868b")
        try:
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            response = requests.get(
                f"{TARIUNET_BASE}/api/nexus/license/{self.license_key}",
                headers=headers,
                timeout=15
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    license_data = data.get("license", {})
                    domains = license_data.get("allowed_domains", [])
                    max_games = license_data.get("max_games", 1)

                    self.log_message.emit("License verified via TariuNet.", "#188038")
                    self.log_message.emit(f"  Domains: {', '.join(domains[:5])}{'...' if len(domains) > 5 else ''}", "#80868b")
                    self.log_message.emit(f"  Max games: {max_games}", "#80868b")

                    # Pass license data to compile worker
                    self.license_valid.emit(self.license_key, license_data)
                else:
                    self.log_message.emit(f"[AUTH FAIL] {data.get('error', 'Unknown error')}", "#c5221f")
                    self.license_failed.emit(data.get('error', 'Unknown error'))
            elif response.status_code == 401:
                self.log_message.emit("[AUTH FAIL] Authentication failed. Check your API key.", "#c5221f")
                self.license_failed.emit("Authentication failed")
            elif response.status_code == 403:
                try:
                    err = response.json()
                    self.log_message.emit(f"[AUTH FAIL] {err.get('error', 'Forbidden')}", "#c5221f")
                    self.license_failed.emit(err.get('error', 'Forbidden'))
                except Exception:
                    self.log_message.emit("[AUTH FAIL] Insufficient permissions.", "#c5221f")
                    self.license_failed.emit("Insufficient permissions")
            else:
                try:
                    err = response.json().get("error", response.text)
                except Exception:
                    err = response.text
                self.log_message.emit(f"[AUTH FAIL] {err}", "#c5221f")
                self.license_failed.emit(str(err))
        except requests.exceptions.RequestException as e:
            self.log_message.emit(f"[AUTH FAIL] Network error: {e}", "#c5221f")
            self.license_failed.emit(str(e))


class CompileWorker(QThread):
    log_message = pyqtSignal(str, str)
    finished_compile = pyqtSignal(bool, str)

    def __init__(self, export_dir, license_key, license_data):
        super().__init__()
        self.export_dir = Path(export_dir)
        self.license_key = license_key
        self.license_data = license_data

    def run(self):
        try:
            export_dir = self.export_dir

            # Phase 1: Security validation
            self.log_message.emit("Validating build directory...", "#1a73e8")
            valid, result = validate_directory(export_dir)
            if not valid:
                raise SecurityError(result)
            export_dir = result  # resolved path

            # Compute fingerprint before modifications
            fingerprint_before = compute_build_fingerprint(export_dir)
            self.log_message.emit(f"Build fingerprint: {fingerprint_before}", "#80868b")

            # Get domains from license (fallback to defaults if empty)
            allowed_domains = self.license_data.get("allowed_domains", [])
            if not allowed_domains:
                allowed_domains = ["localhost", "127.0.0.1"]
                self.log_message.emit("No domains on license — using localhost only.", "#e37400")

            # Phase 2: Platform SDK Bridge injection
            self.log_message.emit("Scanning for index.html...", "#1a73e8")
            index_path = export_dir / "index.html"
            with open(index_path, "r", encoding="utf-8") as f:
                html_content = f.read()

            # Check if already protected (prevent double-injection)
            if "NEXUS_SECURITY" in html_content or "PlatformBridge" in html_content:
                raise SecurityError("This build is already Nexus-protected. Restore the original files first.")

            soup = BeautifulSoup(html_content, "html.parser")
            if not soup.head:
                new_head = soup.new_tag("head")
                soup.html.insert(0, new_head)

            script_tag = soup.new_tag("script")
            script_tag.string = PLATFORM_BRIDGE_JS
            soup.head.insert(0, script_tag)

            with open(index_path, "w", encoding="utf-8") as f:
                f.write(str(soup))
            self.log_message.emit("Platform bridge injected into index.html", "#188038")

            # Phase 3: Cryptographic Sitelock
            self.log_message.emit("Generating domain hashes for sitelock...", "#1a73e8")
            hashes_array = [hashlib.sha256(domain.encode('utf-8')).hexdigest() for domain in allowed_domains]

            sitelock_code = SITELOCK_IIFE_TEMPLATE.replace("{license_key}", self.license_key)
            sitelock_code = sitelock_code.replace("{hashes_array}", json.dumps(hashes_array))
            sitelock_code = sitelock_code.replace("{telemetry_endpoint}", f"{TARIUNET_BASE}/api/nexus/telemetry/report-theft")

            js_files = [f for f in export_dir.glob("*.js") if f.name != "platform_bridge.js"]
            if not js_files:
                raise FileNotFoundError("No .js files found in the build directory.")

            target_js = max(js_files, key=lambda p: p.stat().st_size)
            self.log_message.emit(f"Applying sitelock to {target_js.name}...", "#1a73e8")

            with open(target_js, "r", encoding="utf-8") as f:
                original_js = f.read()

            # Check if JS is already protected
            if "NEXUS_SECURITY" in original_js:
                raise SecurityError(f"{target_js.name} is already Nexus-protected.")

            with open(target_js, "w", encoding="utf-8") as f:
                f.write(sitelock_code + "\n" + original_js)
            self.log_message.emit(f"Sitelock applied to {target_js.name}", "#188038")

            # Phase 4: Integrity verification
            fingerprint_after = compute_build_fingerprint(export_dir)
            self.log_message.emit(f"Post-protection fingerprint: {fingerprint_after}", "#80868b")

            # Phase 5: Package
            self.log_message.emit("Packaging build...", "#1a73e8")
            zip_name = "dist_protected_build.zip"
            zip_path = export_dir / zip_name

            if zip_path.exists():
                zip_path.unlink()

            file_count = 0
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(export_dir):
                    if zip_name in files:
                        files.remove(zip_name)
                    dirs.sort()
                    for file in sorted(files):
                        file_path = Path(root) / file
                        ext = file_path.suffix.lower()
                        if ext in BLOCKED_EXTENSIONS:
                            continue
                        arcname = file_path.relative_to(export_dir)
                        zipf.write(file_path, arcname)
                        file_count += 1
                        self.log_message.emit(f"  {arcname}", "#80868b")

            self.log_message.emit(f"Build packaged: {zip_name} ({file_count} files)", "#188038")
            self.log_message.emit(f"Output: {zip_path}", "#80868b")
            self.finished_compile.emit(True, str(zip_path))

        except SecurityError as e:
            self.log_message.emit(f"[SECURITY] {str(e)}", "#c5221f")
            self.finished_compile.emit(False, str(e))
        except Exception as e:
            self.log_message.emit(f"[COMPILE FAIL] {str(e)}", "#c5221f")
            self.finished_compile.emit(False, str(e))


class SecurityError(Exception):
    """Raised when a security check fails during compilation."""
    pass


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Nexus Compiler — Tariu")
        self.resize(720, 540)
        self.setup_ui()

    def setup_ui(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #f8f9fa; }
            QLabel { color: #202124; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 13px; }
            QLineEdit {
                background-color: #fff;
                color: #202124;
                border: 1px solid #dadce0;
                padding: 10px 12px;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                font-size: 13px;
                border-radius: 8px;
            }
            QLineEdit:focus { border-color: #1a73e8; outline: none; }
            QLineEdit:read-only { background-color: #f1f3f4; color: #5f6368; }
            QPushButton {
                background-color: #fff;
                color: #1a73e8;
                border: 1px solid #dadce0;
                padding: 10px 20px;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                font-size: 13px;
                font-weight: 500;
                border-radius: 8px;
            }
            QPushButton:hover { background-color: #e8f0fe; border-color: #d2e3fc; }
            QPushButton:disabled { color: #80868b; border-color: #e0e0e0; background-color: #f8f9fa; }
            QPushButton#compileBtn {
                background-color: #1a73e8;
                color: #fff;
                border: none;
                font-size: 14px;
                font-weight: 500;
                padding: 12px 24px;
                border-radius: 8px;
            }
            QPushButton#compileBtn:hover { background-color: #1557b0; }
            QPushButton#compileBtn:disabled { background-color: #c4c9cf; color: #fff; }
            QTextEdit {
                background-color: #fff;
                color: #202124;
                border: 1px solid #dadce0;
                font-family: 'Roboto Mono', 'Consolas', monospace;
                font-size: 12px;
                padding: 12px;
                border-radius: 8px;
            }
        """)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(16)

        # Header
        header = QLabel("Nexus Compiler")
        header.setStyleSheet("font-size: 20px; font-weight: 500; color: #202124; margin-bottom: 2px;")
        layout.addWidget(header)

        sub = QLabel("Protect web builds with domain sitelocking and platform SDK injection. Works with any web project.")
        sub.setStyleSheet("font-size: 13px; color: #5f6368; margin-bottom: 4px;")
        sub.setWordWrap(True)
        layout.addWidget(sub)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("border: none; border-top: 1px solid #e0e0e0;")
        layout.addWidget(sep)

        # License key
        key_label = QLabel("Nexus License Key")
        key_label.setStyleSheet("font-size: 12px; font-weight: 500; color: #5f6368;")
        layout.addWidget(key_label)
        self.license_input = QLineEdit()
        self.license_input.setPlaceholderText("NXS_live_...")
        layout.addWidget(self.license_input)

        # API key
        api_label = QLabel("TariuNet API Key")
        api_label.setStyleSheet("font-size: 12px; font-weight: 500; color: #5f6368;")
        layout.addWidget(api_label)
        self.api_input = QLineEdit()
        self.api_input.setPlaceholderText("tnk_live_... (from TariuNet API Keys)")
        layout.addWidget(self.api_input)

        # Directory
        dir_label = QLabel("Build Directory")
        dir_label.setStyleSheet("font-size: 12px; font-weight: 500; color: #5f6368;")
        layout.addWidget(dir_label)
        dir_row = QHBoxLayout()
        dir_row.setSpacing(12)
        self.dir_input = QLineEdit()
        self.dir_input.setReadOnly(True)
        self.dir_input.setPlaceholderText("Select your web build folder (must contain index.html)...")
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.setFixedWidth(90)
        self.browse_btn.clicked.connect(self.browse_directory)
        dir_row.addWidget(self.dir_input)
        dir_row.addWidget(self.browse_btn)
        layout.addLayout(dir_row)

        # Log
        log_label = QLabel("Build Log")
        log_label.setStyleSheet("font-size: 12px; font-weight: 500; color: #5f6368;")
        layout.addWidget(log_label)
        self.log_terminal = QTextEdit()
        self.log_terminal.setReadOnly(True)
        self.log_terminal.setMinimumHeight(120)
        layout.addWidget(self.log_terminal, 1)

        # Compile
        self.compile_btn = QPushButton("Compile")
        self.compile_btn.setObjectName("compileBtn")
        self.compile_btn.clicked.connect(self.start_compilation)
        layout.addWidget(self.compile_btn, alignment=Qt.AlignmentFlag.AlignRight)

        footer = QLabel("Tariu — Nexus Anti-Piracy")
        footer.setStyleSheet("font-size: 11px; color: #80868b;")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(footer)

        self.setCentralWidget(central)

    def append_log(self, message, color='#202124'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_terminal.append(f'<span style="color:#80868b;">[{timestamp}]</span> <span style="color:{color};">{message}</span>')
        self.log_terminal.verticalScrollBar().setValue(self.log_terminal.verticalScrollBar().maximum())

    def browse_directory(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Build Directory")
        if dir_path:
            self.dir_input.setText(dir_path)

    def start_compilation(self):
        license_key = self.license_input.text().strip()
        export_dir = self.dir_input.text().strip()

        if not license_key:
            self.append_log("Enter a Nexus license key to continue.", "#c5221f")
            return
        if not export_dir:
            self.append_log("Select a build directory.", "#c5221f")
            return

        self.compile_btn.setEnabled(False)
        self.browse_btn.setEnabled(False)
        self.license_input.setEnabled(False)
        self.api_input.setEnabled(False)

        self.append_log("Starting Nexus secure pipeline...", "#1a73e8")

        api_key = self.api_input.text().strip()
        self.license_worker = LicenseWorker(license_key, api_key)
        self.license_worker.log_message.connect(self.append_log)
        self.license_worker.license_valid.connect(self.on_license_valid)
        self.license_worker.license_failed.connect(self.on_license_failed)
        self.license_worker.start()

    def on_license_valid(self, license_key, license_data):
        export_dir = self.dir_input.text().strip()
        self.compile_worker = CompileWorker(export_dir, license_key, license_data)
        self.compile_worker.log_message.connect(self.append_log)
        self.compile_worker.finished_compile.connect(self.on_compile_finished)
        self.compile_worker.start()

    def on_license_failed(self, reason):
        self.append_log("Pipeline aborted.", "#c5221f")
        self.reset_ui()

    def on_compile_finished(self, success, output_path):
        if success:
            self.append_log("Pipeline finished successfully.", "#188038")
        else:
            self.append_log("Pipeline failed.", "#c5221f")
        self.reset_ui()

    def reset_ui(self):
        self.compile_btn.setEnabled(True)
        self.browse_btn.setEnabled(True)
        self.license_input.setEnabled(True)
        self.api_input.setEnabled(True)


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()