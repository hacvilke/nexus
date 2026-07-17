# NEXUS WEB COMPILER

A secure pipeline tool for packaging and securing Godot HTML5 exports for distribution on web portals like CrazyGames and Poki.

## Features
- Injects a cross-platform ad/analytics SDK bridge into `index.html`.
- Secures the main JavaScript payload with a cryptographic domain sitelock.
- Communicates securely with the NEXUS SaaS backend for telemetry and license verification.
- Packages all resources into a clean zip payload (`dist_protected_build.zip`).

## Installation
```bash
pip install -r requirements.txt
```

## Running
```bash
python main.py
```
