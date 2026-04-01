<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Ollama-Local_LLM-FF6B6B?style=for-the-badge" alt="Ollama"/>
  <img src="https://img.shields.io/badge/NIST_CSF-2024-00A86B?style=for-the-badge" alt="NIST"/>
  <img src="https://img.shields.io/badge/Status-Offline_Ready-success?style=for-the-badge" alt="Status"/>
</p>

<h1 align="center">Local LLM Policy Gap Analyzer</h1>
<h3 align="center">Privacy-First Cybersecurity Policy Analysis Against NIST CSF Standards</h3>

<p align="center">
A fully offline, lightweight system for analyzing organizational cybersecurity policies against NIST Cybersecurity Framework standards using a local Large Language Model.
</p>

---

## Introduction

Organizations struggle to maintain cybersecurity policies that align with industry standards. This tool provides **automated gap analysis** by comparing your policies against the **NIST Cybersecurity Framework** using a local LLM (Gemma3 via Ollama). Every operation runs entirely on your machine—**no cloud APIs, no data collection, complete privacy**.

The system identifies policy weaknesses, generates revised policies addressing those gaps, and creates phased implementation roadmaps—all in professional PDF and text formats.

---

## What's New (March 2026)

- **Improved File Organization**: DOCX files now display in left column, PDF files in right column for better visual organization
- **ZIP Download**: All reports can now be downloaded as a single ZIP archive for convenience
- **Hidden Vulnerability Reports**: Vulnerability analysis PDFs are automatically saved to `risk_analysis/` folder (hidden from users)
- **Auto-Directory Creation**: System automatically creates required directories (`data/`, `risk_analysis/`) on first run
- **Persistent Job History**: Analysis history now persists across server restarts via JSON storage (`data/job_history.json`)
- **Smart History Filtering**: History automatically hides jobs whose output files have been deleted
- **Fixed PDF Downloads**: Resolved path handling issues for PDF downloads and inline viewing on Windows
- **Fixed PDF Modal Viewer**: View button now correctly opens PDFs in the inline modal viewer
- **Live Analysis Logs**: Real-time log streaming on the status page so users can watch each pipeline step
- **Global Analysis History**: Dedicated `/history` page to view jobs from all LAN devices in one place
- **JSON Status API**: Added `/api/status/<job_id>` for smooth in-page updates without full-page refresh
- **Input Sanitization**: Removes invisible/zero-width Unicode artifacts from extracted document text
- **Removed Vulnerability DOCX**: Vulnerability analysis no longer generates DOCX files (PDF only, hidden)
- **Enhanced Security**: Comprehensive prompt injection protection with centralized security instructions
- **Contact Information Filtering**: Automatically removes emails, phone numbers, URLs, and social media handles from LLM outputs
- **Centralized Prompt Configuration**: All LLM security rules managed from single `prompt_config.py` file

---

## Table of Contents

| Section                                               | Description                           |
| ----------------------------------------------------- | ------------------------------------- |
| [Features](#features)                                 | Core capabilities                     |
| [What's New](#whats-new-march-2026)                   | Recent updates                        |
| [Tech Stack](#tech-stack--prerequisites)              | Technologies and requirements         |
| [Architecture](#architecture-diagram)                 | Visual system overview                |
| [Project Structure](#project-structure)               | File organization                     |
| [Security Features](#security-features)               | LLM security & threat protection      |
| [Quick Start](#quick-start-user-instructions)         | Get running in 5 minutes              |
| [Developer Guide](#developer-guide)                   | Contributing code                     |
| [Contributor Expectations](#contributor-expectations) | Guidelines for contributors           |
| [Known Issues](#known-issues--limitations)            | Current limitations                   |
| [PDF Enhancement](BEFORE_AFTER_COMPARISON.md)         | Before/After comparison of PDF output |
| [📄 README.pdf](README.pdf)                           | PDF version with rendered diagrams    |

---

## Features

| Feature                    | Description                                                                 |
| -------------------------- | --------------------------------------------------------------------------- |
| **Gap Analysis**           | Identifies policy weaknesses against NIST CSF standards                     |
| **Vulnerability Analysis** | Security vulnerability assessment (saved to hidden `risk_analysis/` folder) |
| **Policy Revision**        | Auto-generates improved policy versions addressing gaps                     |
| **Implementation Roadmap** | Phased improvement plans (0-3, 3-6, 6-12 months)                            |
| **Executive Summary**      | Leadership-ready overview of findings                                       |
| **Multi-Format Input**     | Supports `.txt`, `.pdf`, and `.docx` policies                               |
| **Multi-Format Output**    | Professional DOCX and PDF reports using ReportLab                           |
| **ZIP Archive**            | Download all reports as a single ZIP file                                   |
| **Batch Processing**       | Analyze multiple policies in one run                                        |
| **LAN Web Server**         | Flask-based web UI — any device on the network can upload & analyze         |
| **Rate Limiting**          | Per-IP job limits + serialized LLM queue prevent overload                   |
| **Live Status & Logs**     | AJAX status polling and real-time step logs on the status page              |
| **Global Job History**     | Dedicated `/history` page listing all jobs across LAN clients               |
| **Persistent History**     | Job history survives server restarts and auto-cleans deleted files          |
| **Input Sanitization**     | Removes invisible/zero-width Unicode artifacts from extracted document text |
| **Prompt Injection Defense** | Multi-layer protection against LLM manipulation and jailbreak attempts    |
| **SSRF Protection**        | Blocks cloud metadata, localhost, and internal IP access attempts           |
| **Contact Info Filtering** | Removes emails, phone numbers, URLs, social media handles from outputs      |
| **100% Offline**           | Zero network calls after initial setup                                      |

---

## Tech Stack & Prerequisites

### Technology Stack

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#6366f1'}}}%%
flowchart TB
    subgraph AppLayer["🖥️ APPLICATION LAYER"]
        direction LR
        PY["🐍 Python 3.8+<br/>Core Runtime"]
        CLI["⌨️ CLI Interface<br/>argparse module"]
        PDF["📄 PDF Engine<br/>ReportLab 4.0+"]
        WEB["🌐 Flask Server<br/>LAN Hosting"]
    end

    subgraph LLMLayer["🤖 LLM LAYER"]
        direction LR
        OLL["🦙 Ollama<br/>Runtime Engine"]
        GEM["💎 Gemma3<br/>Local Model"]
    end

    subgraph DocLayer["📁 DOCUMENT PROCESSING"]
        direction LR
        PYPDF["📕 PyPDF2<br/>PDF Extraction"]
        DOCX["📘 python-docx<br/>Word Parsing"]
        TXT["📝 UTF-8<br/>Text Reading"]
    end

    subgraph RefLayer["📚 REFERENCE"]
        NIST["🛡️ NIST CSF<br/>CIS MS-ISAC 2024"]
    end

    AppLayer ==> LLMLayer
    LLMLayer ==> DocLayer
    RefLayer -.->|Standards| LLMLayer

    style AppLayer fill:#dbeafe,stroke:#3b82f6,stroke-width:2px
    style LLMLayer fill:#fce7f3,stroke:#ec4899,stroke-width:2px
    style DocLayer fill:#dcfce7,stroke:#22c55e,stroke-width:2px
    style RefLayer fill:#f3e8ff,stroke:#a855f7,stroke-width:2px
```

### System Requirements

| Component   | Minimum                    | Recommended               |
| ----------- | -------------------------- | ------------------------- |
| **CPU**     | Intel i5 / AMD Ryzen 5     | Intel i7 / AMD Ryzen 7    |
| **RAM**     | 8 GB                       | 16 GB                     |
| **Storage** | 10 GB                      | 20 GB                     |
| **OS**      | Windows 10 / Linux / macOS | Windows 11 / Ubuntu 22.04 |

### Dependencies

| Package       | Version   | Purpose                    |
| ------------- | --------- | -------------------------- |
| `PyPDF2`      | >= 3.0    | PDF text extraction        |
| `python-docx` | >= 0.8    | Word document parsing      |
| `reportlab`   | >= 4.0    | PDF report generation      |
| `flask`       | >= 3.0    | LAN web server & upload UI |
| `ollama`      | (runtime) | Local LLM execution        |

---

## Architecture Diagram

### System Overview

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#4f46e5', 'primaryTextColor': '#fff', 'primaryBorderColor': '#3730a3', 'lineColor': '#6366f1', 'secondaryColor': '#f0f9ff', 'tertiaryColor': '#e0e7ff'}}}%%
flowchart TB
    subgraph UserInput["📄 INPUT LAYER"]
        direction LR
        TXT["📝 Text Files<br/>.txt"]
        PDF["📕 PDF Documents<br/>.pdf"]
        DOCX["📘 Word Documents<br/>.docx"]
    end

    subgraph Orchestrator["⚙️ ORCHESTRATION LAYER - main.py"]
        direction TB
        CLI["Command Line Interface<br/>--policy | --batch | --output"]
        LOAD["Document Loader<br/>utils.read_policy_document()"]
        PIPE["Analysis Pipeline<br/>Sequential Processing"]
        SAVE["Report Generator<br/>TXT + PDF Output"]

        CLI --> LOAD --> PIPE --> SAVE
    end

    subgraph AnalysisEngine["🔍 ANALYSIS ENGINE"]
        direction TB

        subgraph GapModule["Gap Analyzer Module"]
            GA1["load_nist_framework()"]
            GA2["analyze_policy_gaps()"]
            GA3["extract_gaps_structured()"]
        end

        subgraph RevisionModule["Policy Reviser Module"]
            PR1["revise_policy()"]
            PR2["generate_revision_summary()"]
        end

        subgraph RoadmapModule["Roadmap Generator Module"]
            RG1["generate_improvement_roadmap()"]
            RG2["generate_executive_summary()"]
        end
    end

    subgraph LLMRuntime["🤖 LOCAL LLM RUNTIME"]
        direction TB
        OLLAMA["Ollama Service<br/>subprocess.run()"]
        MODEL["Gemma3:4b<br/>Fully Offline"]
        CONFIG["Configuration<br/>Timeout: 600s<br/>Max Prompt: 100KB<br/>Max Policy: 50KB"]

        OLLAMA --- MODEL
        OLLAMA --- CONFIG
    end

    subgraph OutputLayer["📊 OUTPUT LAYER"]
        direction LR
        subgraph TextReports["Text Reports"]
            T1["gap_analysis.txt"]
            T2["revised_policy.txt"]
            T3["roadmap.txt"]
            T4["executive_summary.txt"]
            T5["comprehensive_report.txt"]
        end

        subgraph PDFReports["PDF Reports - ReportLab"]
            P1["gap_analysis.pdf"]
            P2["revised_policy.pdf"]
            P3["roadmap.pdf"]
            P4["executive_summary.pdf"]
            P5["comprehensive_report.pdf"]
        end
    end

    subgraph Reference["📚 REFERENCE DATA"]
        NIST["NIST CSF Framework<br/>CIS MS-ISAC 2024<br/>data/reference/"]
    end

    UserInput ==> Orchestrator
    Orchestrator ==> AnalysisEngine
    Reference -.->|"Standards"| AnalysisEngine
    AnalysisEngine <===>|"Prompts & Responses"| LLMRuntime
    AnalysisEngine ==> OutputLayer

    style UserInput fill:#dbeafe,stroke:#3b82f6,stroke-width:2px
    style Orchestrator fill:#fef3c7,stroke:#f59e0b,stroke-width:2px
    style AnalysisEngine fill:#dcfce7,stroke:#22c55e,stroke-width:2px
    style LLMRuntime fill:#fce7f3,stroke:#ec4899,stroke-width:2px
    style OutputLayer fill:#e0e7ff,stroke:#6366f1,stroke-width:2px
    style Reference fill:#f3e8ff,stroke:#a855f7,stroke-width:2px
```

### Data Flow Diagram

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#6366f1', 'primaryTextColor': '#fff', 'lineColor': '#8b5cf6'}}}%%
flowchart LR
    subgraph Stage1["📥 STAGE 1: Input"]
        direction TB
        A1["User Policy<br/>(.txt / .pdf / .docx)"]
        A2["NIST Reference<br/>(data/reference/)"]
    end

    subgraph Stage2["🔄 STAGE 2: Processing"]
        direction TB
        B1["📊 Gap Analysis<br/>Compare against NIST"]
        B2["📝 Policy Revision<br/>Address all gaps"]
        B3["🗺️ Roadmap<br/>Phased improvements"]
        B4["📋 Executive Summary<br/>Leadership report"]

        B1 --> B2 --> B3 --> B4
    end

    subgraph Stage3["🤖 STAGE 3: LLM"]
        direction TB
        C1["Ollama Runtime"]
        C2["Gemma3 Model"]
        C1 --- C2
    end

    subgraph Stage4["📤 STAGE 4: Output"]
        direction TB
        D1["5 TXT Reports"]
        D2["5 PDF Reports"]
    end

    Stage1 ==>|"Load Documents"| Stage2
    Stage2 <===>|"AI Processing"| Stage3
    Stage2 ==>|"Generate"| Stage4

    style Stage1 fill:#dbeafe,stroke:#3b82f6,stroke-width:2px
    style Stage2 fill:#dcfce7,stroke:#22c55e,stroke-width:2px
    style Stage3 fill:#fce7f3,stroke:#ec4899,stroke-width:2px
    style Stage4 fill:#fef3c7,stroke:#f59e0b,stroke-width:2px
```

### Processing Sequence

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant M as main.py
    participant GA as gap_analyzer
    participant PR as policy_reviser
    participant RG as roadmap_generator
    participant O as Ollama LLM
    participant PDF as pdf_generator

    U->>M: python main.py --policy input.txt
    activate M
    M->>M: Load policy document
    M->>M: Load NIST framework

    M->>GA: analyze_policy_gaps()
    activate GA
    GA->>O: Send comparison prompt
    O-->>GA: Gap analysis results
    deactivate GA

    M->>PR: revise_policy()
    activate PR
    PR->>O: Send revision prompt
    O-->>PR: Revised policy
    deactivate PR

    M->>RG: generate_improvement_roadmap()
    activate RG
    RG->>O: Send roadmap prompt
    O-->>RG: Implementation roadmap
    RG->>O: Send summary prompt
    O-->>RG: Executive summary
    deactivate RG

    M->>PDF: generate_all_pdfs()
    activate PDF
    PDF-->>M: 5 PDF reports
    deactivate PDF

    M-->>U: Analysis complete!
    deactivate M
```

### NIST CSF Coverage Map

```mermaid
%%{init: {'theme': 'base'}}%%
flowchart TB
    subgraph Framework["NIST&nbsp;CYBERSECURITY&nbsp;FRAMEWORK"]

        direction TB

        subgraph Core["Core Functions"]
            direction LR
            ID["🔍 IDENTIFY<br/>(ID)"]
            PR["🛡️ PROTECT<br/>(PR)"]
            DE["👁️ DETECT<br/>(DE)"]
            RS["⚡ RESPOND<br/>(RS)"]
            RC["🔄 RECOVER<br/>(RC)"]
        end

        subgraph IDCat["Identify Categories"]
            ID_AM["Asset Management<br/>ID.AM"]
            ID_BE["Business Environment<br/>ID.BE"]
            ID_GV["Governance<br/>ID.GV"]
            ID_RA["Risk Assessment<br/>ID.RA"]
            ID_RM["Risk Management<br/>ID.RM"]
        end

        subgraph PRCat["Protect Categories"]
            PR_AC["Access Control<br/>PR.AC"]
            PR_AT["Awareness Training<br/>PR.AT"]
            PR_DS["Data Security<br/>PR.DS"]
            PR_IP["Info Protection<br/>PR.IP"]
            PR_MA["Maintenance<br/>PR.MA"]
            PR_PT["Protective Tech<br/>PR.PT"]
        end

        subgraph DECat["Detect Categories"]
            DE_AE["Anomalies & Events<br/>DE.AE"]
            DE_CM["Continuous Monitoring<br/>DE.CM"]
            DE_DP["Detection Processes<br/>DE.DP"]
        end

        subgraph RSCat["Respond Categories"]
            RS_RP["Response Planning<br/>RS.RP"]
            RS_CO["Communications<br/>RS.CO"]
            RS_AN["Analysis<br/>RS.AN"]
            RS_MI["Mitigation<br/>RS.MI"]
            RS_IM["Improvements<br/>RS.IM"]
        end

        subgraph RCCat["Recover Categories"]
            RC_RP["Recovery Planning<br/>RC.RP"]
            RC_IM["Improvements<br/>RC.IM"]
            RC_CO["Communications<br/>RC.CO"]
        end
    end

    ID --> IDCat
    PR --> PRCat
    DE --> DECat
    RS --> RSCat
    RC --> RCCat

    style ID fill:#3498db,color:#fff,stroke:#2980b9,stroke-width:2px
    style PR fill:#27ae60,color:#fff,stroke:#1e8449,stroke-width:2px
    style DE fill:#f39c12,color:#fff,stroke:#d68910,stroke-width:2px
    style RS fill:#e74c3c,color:#fff,stroke:#c0392b,stroke-width:2px
    style RC fill:#9b59b6,color:#fff,stroke:#7d3c98,stroke-width:2px
    style Framework fill:#f8fafc,stroke:#64748b,stroke-width:3px
```

---

## Project Structure

```
Local-LLM/
├── src/                           # Source code
│   ├── main.py                    # CLI entry point & orchestrator
│   ├── gap_analyzer.py            # NIST comparison & LLM calls
│   ├── vulnerability_analyzer.py  # Security vulnerability analysis
│   ├── policy_reviser.py          # Policy improvement generation
│   ├── roadmap_generator.py       # Implementation roadmap creation
│   ├── pdf_generator.py           # PDF report formatting (ReportLab)
│   ├── docx_generator.py          # DOCX report formatting (python-docx)
│   ├── utils.py                   # File I/O utilities
│   ├── prompt_config.py           # Centralized LLM security instructions
│   ├── server.py                  # Flask web server (LAN hosting)
│   ├── rate_limiter.py            # Thread-safe job queue & rate limiter
│   └── templates/                 # HTML templates
│       ├── index.html             # Upload page
│       ├── status.html            # Job status, live logs, and downloads
│       └── history.html           # Global job history page
│
├── data/
│   ├── reference/                 # NIST CSF framework files
│   ├── test_policies/             # Sample policies for testing
│   └── job_history.json           # Persistent job history (auto-generated)
│
├── output/                        # Generated reports (DOCX + PDF + ZIP)
├── uploads/                       # Uploaded policy files (`.gitkeep` retained)
├── risk_analysis/                 # Hidden vulnerability analysis PDFs (admin only)
├── models/                        # Model storage (Ollama)
│
├── test_system.py                 # Test suite
├── convert_to_pdf.py              # Standalone PDF converter
├── demo_formats.py                # Format demonstration
└── requirements.txt               # Python dependencies
```

### Module Responsibilities

| Module                      | Lines | Purpose                                                                           |
| --------------------------- | ----- | --------------------------------------------------------------------------------- |
| `main.py`                   | 253   | CLI interface, `--serve` mode, pipeline orchestration, progress + log callbacks   |
| `gap_analyzer.py`           | 135   | NIST framework loading, LLM prompt construction, gap extraction                   |
| `vulnerability_analyzer.py` | 95    | Security vulnerability analysis using LLM                                         |
| `policy_reviser.py`         | 64    | Policy revision prompts, change summary generation                                |
| `roadmap_generator.py`      | 111   | Phased roadmap creation, executive summary                                        |
| `pdf_generator.py`          | 185   | ReportLab PDF formatting with markdown parsing, hidden vuln PDF storage           |
| `docx_generator.py`         | 165   | python-docx DOCX formatting with style support                                    |
| `utils.py`                  | 87    | Multi-format document reading (TXT/PDF/DOCX), size checks, text sanitization      |
| `prompt_config.py`          | 60    | Centralized LLM security instructions and prompt injection defense rules          |
| `server.py`                 | 310   | Flask web server, upload/status/history routes, JSON status API, security headers |
| `rate_limiter.py`           | 380   | Thread-safe queue, persistent history, file validation, per-IP limits, TTL cleanup |

---

## Quick Start (User Instructions)

### Step 1: Install Dependencies

```bash
# Clone repository
git clone https://github.com/HACK-IITK-2025-C3iHub/Local-LLM-UI.git
cd "Local LLM"

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/macOS

# Install Python packages
pip install -r requirements.txt
```

### Step 2: Install Ollama & Model

| Step           | Command                                | Notes              |
| -------------- | -------------------------------------- | ------------------ |
| Install Ollama | [Download](https://ollama.ai/download) | One-time install   |
| Pull Model     | `ollama run gemma3:4b`                 | Requires internet  |
| Verify         | `ollama list`                          | Should show gemma3 |

### Step 3: Run Analysis

```bash
# Single policy (CLI)
python src/main.py --policy data/test_policies/isms_policy.txt

# Batch processing
python src/main.py --batch data/test_policies/

# Custom output directory
python src/main.py --policy policy.txt --output results/
```

### Step 3 (Alt): Start LAN Web Server

```bash
# Start web server on default port 5000
python src/main.py --serve

# Start on a custom port
python src/main.py --serve --port 8080
```

Then open `http://localhost:5000` (or `http://<your-ip>:5000` from another device on the LAN) to upload policies via the browser.

| Server Feature        | Detail                                                                       |
| --------------------- | ---------------------------------------------------------------------------- |
| **LAN Access**        | Binds to `0.0.0.0` — accessible from any device on the network               |
| **Rate Limiting**     | Max 2 queued jobs per IP, 10 total queue capacity                            |
| **Progress Tracking** | Real-time stage progress (1/6 → 6/6) via AJAX polling (no full-page refresh) |
| **Live Logs**         | Detailed per-stage execution logs stream to the status page while running    |
| **Global History**    | `/history` shows all submitted jobs across all LAN clients                   |
| **Persistent Storage**| Job history saved to `data/job_history.json` and survives server restarts   |
| **Smart Cleanup**     | Automatically removes jobs from history when output files are deleted        |
| **Downloads**         | All 10 reports (TXT + PDF) available for download on completion              |

### Web Routes

| Route                  | Method | Purpose                                                 |
| ---------------------- | ------ | ------------------------------------------------------- |
| `/`                    | GET    | Upload page                                             |
| `/upload`              | POST   | Upload policy and enqueue analysis                      |
| `/status/<job_id>`     | GET    | Human-readable status page with progress/logs/downloads |
| `/api/status/<job_id>` | GET    | JSON status for live UI polling                         |
| `/history`             | GET    | Global history of jobs across all devices               |
| `/download/<filename>` | GET    | Download generated reports                              |
| `/view/<filename>`     | GET    | Inline PDF preview                                      |
| `/queue`               | GET    | Queue summary JSON                                      |

### Step 4: View Results

Reports are generated in the `output/` directory:

| Report                   | Format         | Description                  | Visibility |
| ------------------------ | -------------- | ---------------------------- | ---------- |
| `*_gap_analysis`         | DOCX + PDF     | Identified policy weaknesses | User       |
| `*_vulnerability_analysis` | PDF only     | Security vulnerabilities     | Hidden*    |
| `*_revised_policy`       | DOCX + PDF     | Improved policy version      | User       |
| `*_roadmap`              | DOCX + PDF     | Phased implementation plan   | User       |
| `*_executive_summary`    | DOCX + PDF     | Leadership overview          | User       |
| `*_comprehensive_report` | DOCX + PDF     | All reports combined         | User       |
| `*_all_reports.zip`      | ZIP Archive    | All user reports in one file | User       |

*Vulnerability analysis PDFs are saved to `risk_analysis/` folder for admin/internal review only.

### Processing Time Estimate

| Stage                     | Duration         |
| ------------------------- | ---------------- |
| Gap Analysis              | 1-2 minutes      |
| Vulnerability Analysis    | 1-2 minutes      |
| Policy Revision           | 2-3 minutes      |
| Roadmap Generation        | 1-2 minutes      |
| Executive Summary         | 30-60 seconds    |
| **TOTAL PER POLICY**      | **~6-10 minutes** |

---

## Security Features

### LLM Security Architecture

This system implements comprehensive security measures to protect against LLM-based attacks and ensure safe offline operation:

#### Prompt Injection Defense

**Centralized Security Configuration** (`prompt_config.py`):
- All LLM security rules managed from a single configuration file
- Multi-layer protection against prompt injection and jailbreak attempts
- Treats all input documents strictly as data, not instructions
- Blocks role manipulation attempts ("act as...", "you are now...", "ignore previous instructions")
- Flags and neutralizes hidden instructions in documents

**Input Sanitization** (`utils.py` & `gap_analyzer.py`):
- Removes invisible/zero-width Unicode characters
- Strips HTML comments and markdown hidden text
- Detects and blocks encoding tricks used to bypass filters
- Validates file magic bytes to prevent file type spoofing

#### SSRF Protection

**Network Request Blocking**:
- Blocks all cloud metadata endpoints (169.254.169.254, metadata.google.internal)
- Prevents localhost and internal IP access (127.0.0.1, 10.x.x.x, 192.168.x.x, 172.16-31.x.x)
- Removes file:// protocol URLs
- Identifies SSRF patterns without executing them
- Does NOT resolve DNS or follow encoded URLs

#### Data Exfiltration Prevention

**Output Filtering**:
- Automatically removes contact information (emails, phone numbers, URLs)
- Strips social media handles from LLM outputs
- Blocks markdown images and HTML img tags (common exfiltration vectors)
- Prevents DNS exfiltration attempts (nslookup, dig commands)
- Flags attempts to retrieve credentials, tokens, or internal data

#### Evidence-Based Analysis

**Quality Assurance**:
- Only reports findings supported by explicit evidence
- Adds confidence levels (Low/Medium/High) to all findings
- Marks ambiguous statements as "requires manual review"
- Includes disclaimer: "AI-assisted analysis – manual validation required"
- Avoids assumptions and prefers "Insufficient data" over guessing

#### File Upload Security

**Server-Side Protection** (`server.py`):
- File extension whitelist (.txt, .pdf, .docx only)
- Magic byte validation after upload
- Filename sanitization to prevent path traversal
- 50MB file size limit
- Secure file storage in job-specific directories

**Security Headers**:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY/SAMEORIGIN`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`

#### Rate Limiting & Resource Protection

**Job Queue Management** (`rate_limiter.py`):
- Maximum 2 queued jobs per IP address
- Global queue limit of 10 jobs
- Serialized LLM access (one analysis at a time)
- Automatic cleanup of old jobs (1-hour TTL)
- Thread-safe queue implementation

### Security Best Practices

**For Users**:
1. Always review LLM-generated reports manually
2. Do not upload sensitive/classified documents
3. Verify all recommendations before implementation
4. Use the system in a secure, isolated network environment

**For Developers**:
1. All security rules are centralized in `prompt_config.py`
2. Never bypass input sanitization functions
3. Always use `sanitize_input()` before passing data to LLM
4. Test security measures with adversarial inputs
5. Keep Ollama and dependencies updated

### Threat Model

**Protected Against**:
- ✅ Prompt injection attacks
- ✅ Jailbreak attempts
- ✅ SSRF attacks
- ✅ Data exfiltration via LLM outputs
- ✅ File upload attacks
- ✅ Path traversal attacks
- ✅ XSS attacks
- ✅ Resource exhaustion (DoS)

**Not Protected Against**:
- ❌ Physical access to the server
- ❌ Compromised Ollama installation
- ❌ Social engineering attacks
- ❌ Network-level attacks (use firewall/VPN)

---

## Developer Guide

### Code Architecture

```mermaid
%%{init: {'theme': 'base'}}%%
flowchart LR

    %% ================= ENTRY =================
    subgraph Entry["🚀 ENTRY POINT"]
        MAIN["main.py<br/>CLI & Orchestration"]
    end

    %% ================= CORE =================
    subgraph Core["🔧 CORE MODULES"]
        direction LR

        subgraph Gap["gap_analyzer.py"]
            GA2["analyze_policy_gaps()"]
            GA3["call_local_llm()"]
            GA4["extract_gaps_structured()"]
        end

        subgraph Rev["policy_reviser.py"]
            PR1["revise_policy()"]
        end

        subgraph Road["roadmap_generator.py"]
            RG1["generate_improvement_roadmap()"]
            RG2["generate_executive_summary()"]
        end
    end

    %% ================= SUPPORT =================
    subgraph Support["🛠️ SUPPORT"]
        direction LR

        subgraph Util["utils.py"]
            U1["read_policy_document()"]
            U5["save_output()"]
        end

        subgraph PDF["pdf_generator.py"]
            P2["generate_all_pdfs()"]
        end
    end

    %% ================= FLOW =================
    MAIN -->|Load| U1
    MAIN -->|Analyze| GA2
    MAIN -->|Revise| PR1
    MAIN -->|Roadmap| RG1
    MAIN -->|Summary| RG2
    MAIN -->|Generate PDFs| P2

    GA2 -.->|LLM| GA3
    PR1 -.->|LLM| GA3
    RG1 -.->|LLM| GA3
    RG2 -.->|LLM| GA3

    %% ================= STYLING =================
    style Entry fill:#fef3c7,stroke:#f59e0b,stroke-width:2px
    style Core fill:#dcfce7,stroke:#22c55e,stroke-width:2px
    style Support fill:#dbeafe,stroke:#3b82f6,stroke-width:2px
```

### Adding a New Policy Type

1. Add sample policy to `data/test_policies/`
2. Update prompts in `gap_analyzer.py` if needed
3. Run test: `python test_system.py --test-policy <path>`

### Modifying LLM Prompts

Edit prompt templates in:

- `gap_analyzer.py`: `analyze_policy_gaps()` function
- `policy_reviser.py`: `revise_policy()` function
- `roadmap_generator.py`: `generate_improvement_roadmap()` function

### Security Limits

| Parameter            | Value                                                           | Location            |
| -------------------- | --------------------------------------------------------------- | ------------------- |
| `LLM_TIMEOUT`        | 600s                                                            | `gap_analyzer.py`   |
| `MAX_PROMPT_SIZE`    | 100KB                                                           | `gap_analyzer.py`   |
| `MAX_POLICY_SIZE`    | 50KB                                                            | `gap_analyzer.py`   |
| `MAX_FILE_SIZE`      | 50MB                                                            | `utils.py`          |
| `ALLOWED_MODELS`     | Whitelist                                                       | `gap_analyzer.py`   |
| `MAX_UPLOAD_SIZE`    | 50MB                                                            | `server.py`         |
| `MAX_QUEUE_SIZE`     | 10 jobs                                                         | `rate_limiter.py`   |
| `MAX_JOBS_PER_IP`    | 2 jobs                                                          | `rate_limiter.py`   |
| `JOB_RESULT_TTL`     | 3600s                                                           | `rate_limiter.py`   |
| Security Headers     | `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection` | `server.py`         |
| Path Traversal Guard | Resolved path check                                             | `server.py`         |
| Prompt Injection Defense | Comprehensive multi-layer protection                        | `prompt_config.py`  |
| SSRF Protection      | Cloud metadata, localhost, internal IP blocking                 | `prompt_config.py`  |
| Contact Info Filter  | Email, phone, URL, social media removal                         | `prompt_config.py`  |

### Running Tests

```bash
# Full test suite
python test_system.py --test-all

# Verify offline operation
python test_system.py --verify-offline

# Test specific policy
python test_system.py --test-policy data/test_policies/isms_policy.txt
```

---

## Contributor Expectations

### Code Standards

| Aspect         | Requirement                       |
| -------------- | --------------------------------- |
| Python Version | 3.8+ compatible                   |
| Docstrings     | Required for all public functions |
| Type Hints     | Encouraged but not mandatory      |
| Line Length    | Max 100 characters                |
| Testing        | Add tests for new features        |

### Pull Request Process

```mermaid
flowchart TD
    A["1. Fork repository"] --> B["2. Create feature branch"]
    B --> C["3. Write code + tests"]
    C --> D["4. Run test suite"]
    D --> E["5. Submit PR"]
    E --> F["6. Address feedback"]
```

### Areas for Contribution

- Support for additional frameworks (ISO 27001, GDPR, SOC 2)
- Multi-language policy support
- Enhanced visualization and reporting
- Performance optimizations
- Additional LLM model support

---

## Known Issues & Limitations

| Issue               | Description                          | Mitigation                    |
| ------------------- | ------------------------------------ | ----------------------------- |
| **Model Accuracy**  | LLM outputs may contain inaccuracies | Human review recommended      |
| **Processing Time** | 5-8 minutes per policy               | Use batch mode for efficiency |
| **RAM Usage**       | High memory during analysis          | Close other applications      |
| **Complex PDFs**    | Layout may not parse perfectly       | Use TXT input when possible   |
| **Language**        | English only                         | Manual translation required   |
| **First Run**       | Slower due to model loading          | Subsequent runs faster        |

### Troubleshooting

| Error                       | Solution                                                    |
| --------------------------- | ----------------------------------------------------------- |
| `ollama: command not found` | Install Ollama from [ollama.ai](https://ollama.ai/download) |
| `Model not found`           | Run `ollama pull gemma3:4b`                                 |
| `LLM execution failed`      | Verify: `ollama run gemma3:4b`                              |
| `File too large`            | Split policy or use TXT format                              |

---

## License

This project is provided for educational and research purposes.

---

<p align="center">
  <strong>Made With &#x1F497; by T-reXploit</strong>
</p>

<p align="center">
  <sub>Framework: NIST CSF (CIS MS-ISAC 2024) | Version 1.1 | Last Updated: February 2026</sub>
</p>
