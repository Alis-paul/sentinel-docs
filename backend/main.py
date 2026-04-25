from fastapi import FastAPI, UploadFile, File
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from detector import detect_with_nlp
from masker import (
    extract_text_from_pdf,
    extract_text_from_image,
    mask_image,
    mask_scanned_pdf,
    mask_pdf_text
)
import pytesseract

# Update this path to your actual Tesseract location
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def extract_text(file_bytes, filename):
    fname = filename.lower()
    # Explicitly check extension before passing to PIL or PyMuPDF
    if fname.endswith((".jpg", ".jpeg", ".png")):
        return extract_text_from_image(file_bytes)
    elif fname.endswith(".pdf"):
        return extract_text_from_pdf(file_bytes)
    return ""

def is_scanned_pdf(file_bytes):
    import fitz
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    for page in doc:
        if page.get_text().strip():
            return False
    return True

@app.get("/")
def home():
    return {"status": "SentinelDocs API is running"}

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    file_bytes = await file.read()
    print(f"Scanning: {file.filename} ({len(file_bytes)} bytes)")
    
    text = extract_text(file_bytes, file.filename)
    findings = detect_with_nlp(text)
    
    return {
        "filename": file.filename,
        "findings": findings
    }

@app.post("/mask")
async def mask_file(file: UploadFile = File(...)):
    file_bytes = await file.read()
    filename = file.filename.lower()
    text = extract_text(file_bytes, filename)
    findings = detect_with_nlp(text)

    if filename.endswith((".jpg", ".jpeg", ".png")):
        result = mask_image(file_bytes, findings)
    elif is_scanned_pdf(file_bytes):
        result = mask_scanned_pdf(file_bytes, findings)
    else:
        result = mask_pdf_text(file_bytes, findings)

    return Response(
        content=result,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=masked_{filename.rsplit('.', 1)[0]}.pdf"
        }
    )