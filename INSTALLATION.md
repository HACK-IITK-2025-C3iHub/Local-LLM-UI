# Installation Guide

## Prerequisites

- Python 3.8 or higher
- Windows 10/11, Linux, or macOS
- 8GB RAM minimum (16GB recommended)

## Setup Steps

### 1. Install Python Packages

```bash
pip install -r requirements.txt
```

Or install individually:

```bash
pip install ollama PyPDF2 python-docx reportlab flask
```

### 2. Install Ollama

**Windows:**
```bash
# Download and run installer from:
https://ollama.ai/download
```

**Linux:**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

**macOS:**
```bash
brew install ollama
```

### 3. Download LLM Model

```bash
ollama pull gemma3:4b
```

### 4. Verify Installation

```bash
# Check Ollama
ollama --version

# Check model
ollama list

# Test system
python test_system.py --verify-offline
```

## Quick Test (CLI)

```bash
python src/main.py --policy data/test_policies/isms_policy.txt
```

## Start LAN Web Server

```bash
# Start on default port 5000
python src/main.py --serve

# Start on a custom port
python src/main.py --serve --port 8080
```

Open `http://localhost:5000` in your browser, or `http://<your-ip>:5000` from other devices on the LAN.

| Setting | Default | Flag |
|---------|---------|------|
| Host | `0.0.0.0` (all interfaces) | — |
| Port | `5000` | `--port` |
| Max queued jobs | 10 | Edit `rate_limiter.py` |
| Max jobs per IP | 2 | Edit `rate_limiter.py` |

## Troubleshooting

**Ollama not found:**
```bash
# Restart terminal after Ollama installation
```

**Model not found:**
```bash
ollama pull gemma3:4b
```

**Python packages error:**
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Port already in use:**
```bash
# Use a different port
python src/main.py --serve --port 8080
```

**Firewall blocking LAN access:**
```bash
# Windows: Allow Python through Windows Firewall
# Linux: sudo ufw allow 5000/tcp
```

---

**Setup complete!** System is ready for offline operation via CLI or LAN web server.
