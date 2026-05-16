
# 🛡️ SentinelDocs

> **Privacy-first document scanner for detecting PII in Indian government documents**

SentinelDocs is a FastAPI-based document intelligence tool that scans uploaded files (PDFs, images) for Personally Identifiable Information (PII) commonly found in Indian government documents — Aadhaar numbers, PAN cards, passport numbers, and more — using OCR and regex-based detection, with full alignment to India's **Digital Personal Data Protection (DPDP) Act, 2023**.

---

## ✨ Features

- 🔍 **PII Detection** — Identifies sensitive identifiers: Aadhaar, PAN, Passport, Voter ID, Driving License, phone numbers, and email addresses
- 📄 **Multi-format Support** — Accepts PDFs and images (JPG, PNG, TIFF)
- 🔤 **OCR-powered Extraction** — Uses Tesseract OCR + PyMuPDF for accurate text extraction from scanned documents
- 🇮🇳 **India-specific Patterns** — Regex patterns tuned for Indian document formats and numbering schemes
- 🔒 **Privacy-first Architecture** — No document storage; files are processed in memory and immediately discarded
- ⚡ **Fast API Backend** — Built on FastAPI with async support
- 🎨 **Cyberpunk-themed Frontend** — Sleek, dark UI for document upload and result visualization
- 📋 **DPDP Act 2023 Aligned** — Designed with India's data protection law in mind

---

## 🧱 Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python, FastAPI |
| OCR | Tesseract OCR |
| PDF Processing | PyMuPDF (`fitz`) |
| PII Detection | Custom Regex Engine |
| Frontend | HTML/CSS/JS (Cyberpunk theme) |
| Packaging | Uvicorn, pip |

---

## 📁 Project Structure

```
SentinelDocs/
├── main.py                  # FastAPI app entry point
├── scanner/
│   ├── ocr.py               # Tesseract OCR + PyMuPDF extraction
│   ├── detector.py          # PII regex detection engine
│   └── patterns.py          # Indian document PII patterns
├── frontend/
│   ├── index.html           # Cyberpunk UI
│   ├── style.css
│   └── app.js
├── requirements.txt
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- Tesseract OCR installed on your system

**Install Tesseract:**
```bash
# Ubuntu/Debian
sudo apt install tesseract-ocr

# macOS
brew install tesseract

# Windows — download installer from: https://github.com/UB-Mannheim/tesseract/wiki
```

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/SentinelDocs.git
cd SentinelDocs

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the server
uvicorn main:app --reload
```

Visit `http://localhost:8000` to open the frontend.

---

## 🔬 PII Patterns Detected

| Document Type | Pattern Example |
|---------------|-----------------|
| Aadhaar Number | `XXXX XXXX XXXX` |
| PAN Card | `ABCDE1234F` |
| Indian Passport | `A1234567` |
| Voter ID | `ABC1234567` |
| Driving License | `DL-1420110012345` |
| Phone Number | `+91 XXXXX XXXXX` |
| Email Address | `user@example.com` |

---

## 🏛️ DPDP Act 2023 Compliance

SentinelDocs is designed with the **Digital Personal Data Protection Act, 2023** in mind:

- **No persistent storage** — Uploaded documents are never written to disk
- **Minimal data processing** — Only scans for defined PII categories
- **Transparency** — All detected PII is clearly surfaced to the user for review
- **Purpose limitation** — The tool's sole purpose is PII detection and awareness

> ⚠️ *SentinelDocs is a detection and awareness tool. It is not a substitute for legal compliance review.*

---

## 📡 API Reference

### `POST /scan`

Upload a document for PII scanning.

**Request:** `multipart/form-data`
| Field | Type | Description |
|-------|------|-------------|
| `file` | File | PDF or image to scan |

**Response:**
```json
{
  "filename": "document.pdf",
  "detected_pii": [
    {
      "type": "Aadhaar Number",
      "value": "XXXX XXXX 1234",
      "page": 1
    }
  ],
  "total_findings": 1,
  "status": "completed"
}
```

### `GET /health`

Returns API health status.

---

## 🛣️ Roadmap

- [ ] Support for more Indian document types (GST certificates, EPFO records)
- [ ] Risk scoring per document
- [ ] Redaction / masking mode
- [ ] Batch file upload
- [ ] Docker support
- [ ] Multi-language OCR (Hindi, Kannada, Tamil)

---

## 🤝 Contributing

Contributions are welcome! Please open an issue first to discuss what you'd like to change.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -m 'Add YourFeature'`)
4. Push to the branch (`git push origin feature/YourFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Alister** — CSE Student, VVCE Mysore  
Built as part of a privacy-tech portfolio focused on Indian data protection.

> *"Privacy is not an option, and it shouldn't be the price we accept for just getting services online."*
